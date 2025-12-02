package docker

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/docker/docker/api/types/container"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/mount"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	natting "github.com/docker/go-connections/nat"
)

// Config holds Docker runtime configuration
type Config struct {
	Host      string
	TLSVerify bool
	CertPath  string
}

// DockerRuntime implements ContainerRuntime for Docker
type DockerRuntime struct {
	client    *client.Client
	ctx       context.Context
	config    *Config
	connected bool
	mutex     sync.RWMutex
}

// New creates a new Docker runtime instance
func New(config *Config) (*DockerRuntime, error) {
	return &DockerRuntime{
		config: config,
		ctx:    context.Background(),
	}, nil
}

// Connect establishes connection to Docker daemon
func (d *DockerRuntime) Connect() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}

	if d.config != nil && d.config.Host != "" {
		opts = append(opts, client.WithHost(d.config.Host))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return err
	}

	// Test connection
	_, err = cli.Ping(d.ctx)
	if err != nil {
		cli.Close()
		return err
	}

	d.client = cli
	d.connected = true
	return nil
}

// IsConnected returns whether Docker is connected
func (d *DockerRuntime) IsConnected() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.connected
}

// Close closes the Docker client connection
func (d *DockerRuntime) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.client != nil {
		err := d.client.Close()
		d.client = nil
		d.connected = false
		return err
	}
	return nil
}

// Create creates a new container
func (d *DockerRuntime) Create(config types.ContainerConfig) (string, error) {
	// Convert ContainerConfig to Docker config
	containerConfig := &container.Config{
		Image:        config.Image,
		Hostname:     config.Hostname,
		Domainname:   config.Domainname,
		User:         config.User,
		WorkingDir:   config.WorkingDir,
		Entrypoint:   config.Entrypoint,
		Cmd:          config.Command,
		Tty:          config.TTY,
		OpenStdin:    config.StdinOpen,
		Labels:       config.Labels,
	}

	// Convert environment map to slice
	for k, v := range config.Environment {
		containerConfig.Env = append(containerConfig.Env, k+"="+v)
	}

	// Convert ports
	exposedPorts := natting.PortSet{}
	portBindings := natting.PortMap{}

	for _, p := range config.Ports {
		port, err := natting.NewPort(p.Protocol, p.ContainerPort)
		if err != nil {
			continue
		}
		exposedPorts[port] = struct{}{}
		portBindings[port] = []natting.PortBinding{
			{
				HostIP:   p.HostIP,
				HostPort: p.HostPort,
			},
		}
	}
	containerConfig.ExposedPorts = exposedPorts

	// Build host config
	hostConfig := &container.HostConfig{
		PortBindings:  portBindings,
		Privileged:    config.Privileged,
		DNS:           config.DNS,
		DNSSearch:     config.DNSSearch,
		ExtraHosts:    config.ExtraHosts,
		CapAdd:        config.CapAdd,
		CapDrop:       config.CapDrop,
		SecurityOpt:   config.SecurityOpt,
		RestartPolicy: container.RestartPolicy{
			Name:              container.RestartPolicyMode(config.RestartPolicy.Name),
			MaximumRetryCount: config.RestartPolicy.MaximumRetryCount,
		},
	}

	// Convert volumes to mounts
	for _, vol := range config.Volumes {
		m := mount.Mount{
			Target:   vol.Target,
			Source:   vol.Source,
			ReadOnly: vol.ReadOnly,
		}
		switch vol.Type {
		case types.MountTypeBind:
			m.Type = mount.TypeBind
		case types.MountTypeVolume:
			m.Type = mount.TypeVolume
		case types.MountTypeTmpfs:
			m.Type = mount.TypeTmpfs
		}
		hostConfig.Mounts = append(hostConfig.Mounts, m)
	}

	// Resource limits
	if config.Memory > 0 {
		hostConfig.Memory = config.Memory
	}
	if config.MemorySwap > 0 {
		hostConfig.MemorySwap = config.MemorySwap
	}
	if config.CPUShares > 0 {
		hostConfig.CPUShares = config.CPUShares
	}
	if config.CPUs > 0 {
		hostConfig.NanoCPUs = int64(config.CPUs * 1e9)
	}

	// Health check
	if config.HealthCheck != nil {
		containerConfig.Healthcheck = &container.HealthConfig{
			Test:        config.HealthCheck.Test,
			Interval:    time.Duration(config.HealthCheck.Interval),
			Timeout:     time.Duration(config.HealthCheck.Timeout),
			Retries:     config.HealthCheck.Retries,
			StartPeriod: time.Duration(config.HealthCheck.StartPeriod),
		}
	}

	// Network config
	var networkConfig *networktypes.NetworkingConfig
	if len(config.Networks) > 0 {
		networkConfig = &networktypes.NetworkingConfig{
			EndpointsConfig: make(map[string]*networktypes.EndpointSettings),
		}
		// Connect to first network, others will be connected after creation
		networkConfig.EndpointsConfig[config.Networks[0]] = &networktypes.EndpointSettings{}
	}

	resp, err := d.client.ContainerCreate(d.ctx, containerConfig, hostConfig, networkConfig, nil, config.Name)
	if err != nil {
		return "", err
	}

	// Connect to additional networks
	for i := 1; i < len(config.Networks); i++ {
		d.client.NetworkConnect(d.ctx, config.Networks[i], resp.ID, &networktypes.EndpointSettings{})
	}

	return resp.ID, nil
}

// Start starts a container
func (d *DockerRuntime) Start(id string) error {
	return d.client.ContainerStart(d.ctx, id, container.StartOptions{})
}

// Stop stops a container
func (d *DockerRuntime) Stop(id string) error {
	return d.client.ContainerStop(d.ctx, id, container.StopOptions{})
}

// Restart restarts a container
func (d *DockerRuntime) Restart(id string) error {
	return d.client.ContainerRestart(d.ctx, id, container.StopOptions{})
}

// Remove removes a container
func (d *DockerRuntime) Remove(id string) error {
	return d.client.ContainerRemove(d.ctx, id, container.RemoveOptions{})
}

// Recreate stops, removes, and recreates a container
func (d *DockerRuntime) Recreate(id string, config types.ContainerConfig) (string, error) {
	// Get current container info to preserve networks
	inspect, err := d.Inspect(id)
	if err != nil {
		return "", err
	}

	// Stop and remove old container
	if err := d.Stop(id); err != nil {
		return "", err
	}
	if err := d.Remove(id); err != nil {
		return "", err
	}

	// Preserve networks if not specified
	if len(config.Networks) == 0 {
		for netName := range inspect.NetworkSettings.Networks {
			config.Networks = append(config.Networks, netName)
		}
	}

	// Create new container
	newID, err := d.Create(config)
	if err != nil {
		return "", err
	}

	// Start new container
	if err := d.Start(newID); err != nil {
		return "", err
	}

	return newID, nil
}

// List lists all containers
func (d *DockerRuntime) List() ([]types.Container, error) {
	containers, err := d.client.ContainerList(d.ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	result := make([]types.Container, len(containers))
	for i, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		var ports []types.PortMapping
		for _, p := range c.Ports {
			ports = append(ports, types.PortMapping{
				HostIP:        p.IP,
				HostPort:      strconv.Itoa(int(p.PublicPort)),
				ContainerPort: strconv.Itoa(int(p.PrivatePort)),
				Protocol:      p.Type,
			})
		}

		var networks []string
		for netName := range c.NetworkSettings.Networks {
			networks = append(networks, netName)
		}

		result[i] = types.Container{
			ID:       c.ID,
			Name:     name,
			Image:    c.Image,
			State:    types.ContainerState(c.State),
			Status:   c.Status,
			Created:  c.Created,
			Labels:   c.Labels,
			Ports:    ports,
			Networks: networks,
		}
	}

	return result, nil
}

// Inspect returns detailed container information
func (d *DockerRuntime) Inspect(id string) (*types.ContainerDetails, error) {
	info, err := d.client.ContainerInspect(d.ctx, id)
	if err != nil {
		return nil, err
	}

	name := strings.TrimPrefix(info.Name, "/")

	// Convert ports
	var ports []types.PortMapping
	for port, bindings := range info.NetworkSettings.Ports {
		for _, binding := range bindings {
			ports = append(ports, types.PortMapping{
				HostIP:        binding.HostIP,
				HostPort:      binding.HostPort,
				ContainerPort: port.Port(),
				Protocol:      port.Proto(),
			})
		}
	}

	// Convert networks
	var networks []string
	networkSettings := types.NetworkSettings{
		Networks: make(map[string]types.NetworkEndpoint),
	}
	if info.NetworkSettings != nil {
		networkSettings.IPAddress = info.NetworkSettings.IPAddress
		networkSettings.Gateway = info.NetworkSettings.Gateway
		networkSettings.MacAddress = info.NetworkSettings.MacAddress

		for netName, endpoint := range info.NetworkSettings.Networks {
			networks = append(networks, netName)
			networkSettings.Networks[netName] = types.NetworkEndpoint{
				NetworkID:  endpoint.NetworkID,
				IPAddress:  endpoint.IPAddress,
				Gateway:    endpoint.Gateway,
				MacAddress: endpoint.MacAddress,
				Aliases:    endpoint.Aliases,
			}
		}
	}

	// Convert mounts
	var mounts []types.VolumeMount
	for _, m := range info.Mounts {
		mountType := types.MountTypeBind
		switch m.Type {
		case mount.TypeVolume:
			mountType = types.MountTypeVolume
		case mount.TypeTmpfs:
			mountType = types.MountTypeTmpfs
		}
		mounts = append(mounts, types.VolumeMount{
			Type:     mountType,
			Source:   m.Source,
			Target:   m.Destination,
			ReadOnly: !m.RW,
		})
	}

	// Convert environment
	env := make(map[string]string)
	for _, e := range info.Config.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	return &types.ContainerDetails{
		Container: types.Container{
			ID:       info.ID,
			Name:     name,
			Image:    info.Config.Image,
			State:    types.ContainerState(info.State.Status),
			Status:   info.State.Status,
			Created:  info.Created.Unix(),
			Labels:   info.Config.Labels,
			Ports:    ports,
			Networks: networks,
		},
		Config: types.ContainerConfig{
			Name:        name,
			Image:       info.Config.Image,
			Hostname:    info.Config.Hostname,
			Domainname:  info.Config.Domainname,
			User:        info.Config.User,
			WorkingDir:  info.Config.WorkingDir,
			Entrypoint:  info.Config.Entrypoint,
			Command:     info.Config.Cmd,
			Environment: env,
			Labels:      info.Config.Labels,
			TTY:         info.Config.Tty,
			StdinOpen:   info.Config.OpenStdin,
		},
		NetworkSettings: networkSettings,
		Mounts:          mounts,
		HostConfig: types.HostConfig{
			NetworkMode:   string(info.HostConfig.NetworkMode),
			Privileged:    info.HostConfig.Privileged,
			DNS:           info.HostConfig.DNS,
			DNSSearch:     info.HostConfig.DNSSearch,
			ExtraHosts:    info.HostConfig.ExtraHosts,
			CapAdd:        info.HostConfig.CapAdd,
			CapDrop:       info.HostConfig.CapDrop,
		},
	}, nil
}

// Logs returns container logs
func (d *DockerRuntime) Logs(id string, opts types.LogOptions) (io.ReadCloser, error) {
	return d.client.ContainerLogs(d.ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     opts.Follow,
		Timestamps: opts.Timestamps,
		Tail:       opts.Tail,
		Since:      opts.Since,
		Until:      opts.Until,
	})
}

// Stats returns container resource stats
func (d *DockerRuntime) Stats(id string) (*types.ContainerStats, error) {
	statsBody, err := d.client.ContainerStats(d.ctx, id, false)
	if err != nil {
		return nil, err
	}
	defer statsBody.Body.Close()

	var stats dockertypes.StatsJSON
	if err := decodeStats(statsBody.Body, &stats); err != nil {
		return nil, err
	}

	cpuPercent := calculateCPUPercent(&stats)
	memoryPercent := 0.0
	if stats.MemoryStats.Limit > 0 {
		memoryPercent = float64(stats.MemoryStats.Usage) / float64(stats.MemoryStats.Limit) * 100
	}

	var netRx, netTx int64
	for _, net := range stats.Networks {
		netRx += int64(net.RxBytes)
		netTx += int64(net.TxBytes)
	}

	var blockRead, blockWrite int64
	if len(stats.BlkioStats.IoServiceBytesRecursive) > 0 {
		blockRead = int64(stats.BlkioStats.IoServiceBytesRecursive[0].Value)
	}
	if len(stats.BlkioStats.IoServiceBytesRecursive) > 1 {
		blockWrite = int64(stats.BlkioStats.IoServiceBytesRecursive[1].Value)
	}

	return &types.ContainerStats{
		ID:            id,
		CPUPercent:    cpuPercent,
		MemoryUsage:   int64(stats.MemoryStats.Usage),
		MemoryLimit:   int64(stats.MemoryStats.Limit),
		MemoryPercent: memoryPercent,
		NetworkRx:     netRx,
		NetworkTx:     netTx,
		BlockRead:     blockRead,
		BlockWrite:    blockWrite,
	}, nil
}

// StatsAll returns stats for all running containers
func (d *DockerRuntime) StatsAll() ([]types.ContainerStats, error) {
	containers, err := d.List()
	if err != nil {
		return nil, err
	}

	var result []types.ContainerStats
	for _, c := range containers {
		if c.State != types.StateRunning {
			continue
		}
		stats, err := d.Stats(c.ID)
		if err != nil {
			continue
		}
		stats.Name = c.Name
		result = append(result, *stats)
	}
	return result, nil
}

// CreateNetwork creates a new network
func (d *DockerRuntime) CreateNetwork(config types.NetworkConfig) (string, error) {
	var ipamConfig []networktypes.IPAMConfig
	if config.IPAM != nil {
		for _, pool := range config.IPAM.Config {
			ipamConfig = append(ipamConfig, networktypes.IPAMConfig{
				Subnet:  pool.Subnet,
				Gateway: pool.Gateway,
				IPRange: pool.IPRange,
			})
		}
	}

	var ipam *networktypes.IPAM
	if config.IPAM != nil {
		ipam = &networktypes.IPAM{
			Driver: config.IPAM.Driver,
			Config: ipamConfig,
		}
	}

	resp, err := d.client.NetworkCreate(d.ctx, config.Name, dockertypes.NetworkCreate{
		Driver:     config.Driver,
		Internal:   config.Internal,
		EnableIPv6: config.EnableIPv6,
		IPAM:       ipam,
		Labels:     config.Labels,
	})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// RemoveNetwork removes a network
func (d *DockerRuntime) RemoveNetwork(id string) error {
	return d.client.NetworkRemove(d.ctx, id)
}

// ListNetworks lists all networks
func (d *DockerRuntime) ListNetworks() ([]types.Network, error) {
	networks, err := d.client.NetworkList(d.ctx, dockertypes.NetworkListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]types.Network, len(networks))
	for i, n := range networks {
		var ipam *types.IPAMConfig
		if n.IPAM.Driver != "" || len(n.IPAM.Config) > 0 {
			ipam = &types.IPAMConfig{
				Driver: n.IPAM.Driver,
			}
			for _, c := range n.IPAM.Config {
				ipam.Config = append(ipam.Config, types.IPAMPoolConfig{
					Subnet:  c.Subnet,
					Gateway: c.Gateway,
					IPRange: c.IPRange,
				})
			}
		}

		result[i] = types.Network{
			ID:       n.ID,
			Name:     n.Name,
			Driver:   n.Driver,
			Scope:    n.Scope,
			Internal: n.Internal,
			Labels:   n.Labels,
			IPAM:     ipam,
		}
	}
	return result, nil
}

// ConnectToNetwork connects a container to a network
func (d *DockerRuntime) ConnectToNetwork(containerID, networkID string, opts types.NetworkConnectOptions) error {
	return d.client.NetworkConnect(d.ctx, networkID, containerID, &networktypes.EndpointSettings{
		Aliases:     opts.Aliases,
		IPAddress:   opts.IPAddress,
		IPv6Gateway: opts.IPv6Address,
	})
}

// DisconnectFromNetwork disconnects a container from a network
func (d *DockerRuntime) DisconnectFromNetwork(containerID, networkID string) error {
	return d.client.NetworkDisconnect(d.ctx, networkID, containerID, false)
}

// CreateVolume creates a new volume
func (d *DockerRuntime) CreateVolume(config types.VolumeConfig) (string, error) {
	vol, err := d.client.VolumeCreate(d.ctx, volume.CreateOptions{
		Name:   config.Name,
		Driver: config.Driver,
		Labels: config.Labels,
	})
	if err != nil {
		return "", err
	}
	return vol.Name, nil
}

// RemoveVolume removes a volume
func (d *DockerRuntime) RemoveVolume(id string) error {
	return d.client.VolumeRemove(d.ctx, id, false)
}

// ListVolumes lists all volumes
func (d *DockerRuntime) ListVolumes() ([]types.Volume, error) {
	resp, err := d.client.VolumeList(d.ctx, volume.ListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]types.Volume, len(resp.Volumes))
	for i, v := range resp.Volumes {
		result[i] = types.Volume{
			Name:       v.Name,
			Driver:     v.Driver,
			Mountpoint: v.Mountpoint,
			Labels:     v.Labels,
			CreatedAt:  v.CreatedAt,
		}
	}
	return result, nil
}

// PullImage pulls an image
func (d *DockerRuntime) PullImage(ref string) (io.ReadCloser, error) {
	return d.client.ImagePull(d.ctx, ref, dockertypes.ImagePullOptions{})
}

// ListImages lists all images
func (d *DockerRuntime) ListImages() ([]types.Image, error) {
	images, err := d.client.ImageList(d.ctx, dockertypes.ImageListOptions{})
	if err != nil {
		return nil, err
	}

	result := make([]types.Image, len(images))
	for i, img := range images {
		name := ""
		if len(img.RepoTags) > 0 {
			name = img.RepoTags[0]
		}
		result[i] = types.Image{
			ID:      img.ID,
			Name:    name,
			Tags:    img.RepoTags,
			Size:    img.Size,
			Created: img.Created,
		}
	}
	return result, nil
}

// RemoveImage removes an image
func (d *DockerRuntime) RemoveImage(id string) error {
	_, err := d.client.ImageRemove(d.ctx, id, dockertypes.ImageRemoveOptions{})
	return err
}

// RuntimeType returns the runtime type
func (d *DockerRuntime) RuntimeType() types.RuntimeType {
	return types.RuntimeDocker
}

// Version returns the Docker version
func (d *DockerRuntime) Version() string {
	info, err := d.client.ServerVersion(d.ctx)
	if err != nil {
		return "unknown"
	}
	return info.Version
}

// Helper functions

func calculateCPUPercent(stats *dockertypes.StatsJSON) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage) - float64(stats.PreCPUStats.SystemUsage)

	perCore := len(stats.CPUStats.CPUUsage.PercpuUsage)
	if perCore == 0 {
		perCore = 1
	}

	if systemDelta > 0 && cpuDelta > 0 {
		return (cpuDelta / systemDelta) * float64(perCore) * 100
	}
	return 0
}

func decodeStats(r io.Reader, stats *dockertypes.StatsJSON) error {
	dec := io.NopCloser(r)
	defer dec.Close()

	buf := make([]byte, 8192)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return err
	}

	return parseStatsJSON(buf[:n], stats)
}

func parseStatsJSON(data []byte, stats *dockertypes.StatsJSON) error {
	return json.Unmarshal(data, stats)
}

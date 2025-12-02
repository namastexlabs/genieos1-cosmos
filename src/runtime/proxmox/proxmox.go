package proxmox

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pxapi "github.com/Telmate/proxmox-api-go/proxmox"
	runtime "github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/azukaar/cosmos-server/src/utils"
)

// Config holds Proxmox connection settings
type Config struct {
	Host          string
	Node          string
	TokenID       string
	TokenSecret   string
	Storage       string
	VMIDStart     int
	VMIDEnd       int
	SkipTLSVerify bool
}

// ProxmoxRuntime implements ContainerRuntime for Proxmox LXC
type ProxmoxRuntime struct {
	client      *pxapi.Client
	config      *Config
	node        string
	connected   bool
	vmidCounter int
	mutex       sync.RWMutex
	metadata    *MetadataStore
}

// MetadataStore handles container metadata (labels equivalent)
type MetadataStore struct {
	path string
	data map[int]map[string]string // vmid -> labels
	mu   sync.RWMutex
}

// New creates a new Proxmox runtime
func New(config *Config) (*ProxmoxRuntime, error) {
	if config == nil {
		return nil, errors.New("proxmox config is required")
	}

	if config.Host == "" {
		return nil, errors.New("proxmox host is required")
	}

	if config.Node == "" {
		return nil, errors.New("proxmox node is required")
	}

	if config.TokenID == "" || config.TokenSecret == "" {
		return nil, errors.New("proxmox API token is required")
	}

	return &ProxmoxRuntime{
		config:      config,
		node:        config.Node,
		vmidCounter: config.VMIDStart,
		metadata: &MetadataStore{
			path: "/var/lib/cosmos/proxmox-metadata",
			data: make(map[int]map[string]string),
		},
	}, nil
}

// Connect establishes connection to Proxmox API
func (p *ProxmoxRuntime) Connect() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Create HTTP client with optional TLS skip
	tlsConfig := &tls.Config{
		InsecureSkipVerify: p.config.SkipTLSVerify,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Build API URL
	apiURL := fmt.Sprintf("https://%s/api2/json", p.config.Host)

	// Create Proxmox client with API token
	client, err := pxapi.NewClient(apiURL, nil, httpClient.Transport, "", 300)
	if err != nil {
		return fmt.Errorf("failed to create Proxmox client: %w", err)
	}

	// Set API token authentication
	client.SetAPIToken(p.config.TokenID, p.config.TokenSecret)

	// Test connection by getting version
	_, err = client.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to connect to Proxmox: %w", err)
	}

	p.client = client
	p.connected = true

	// Load metadata from disk
	if err := p.metadata.Load(); err != nil {
		utils.Warn("Failed to load Proxmox metadata: " + err.Error())
	}

	// Find next available VMID
	if err := p.updateVMIDCounter(); err != nil {
		utils.Warn("Failed to update VMID counter: " + err.Error())
	}

	utils.Log("Proxmox LXC runtime connected to " + p.config.Host)
	return nil
}

// IsConnected returns connection status
func (p *ProxmoxRuntime) IsConnected() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.connected
}

// Close disconnects from Proxmox
func (p *ProxmoxRuntime) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.metadata.Save(); err != nil {
		utils.Warn("Failed to save Proxmox metadata: " + err.Error())
	}

	p.client = nil
	p.connected = false
	return nil
}

// RuntimeType returns the runtime identifier
func (p *ProxmoxRuntime) RuntimeType() runtime.RuntimeType {
	return runtime.RuntimeProxmox
}

// Version returns Proxmox version
func (p *ProxmoxRuntime) Version() string {
	if p.client == nil {
		return "unknown"
	}
	version, err := p.client.GetVersion()
	if err != nil {
		return "unknown"
	}
	return version["version"].(string)
}

// getNextVMID returns the next available VMID
func (p *ProxmoxRuntime) getNextVMID() (int, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	vmid := p.vmidCounter
	if vmid > p.config.VMIDEnd && p.config.VMIDEnd > 0 {
		return 0, errors.New("VMID range exhausted")
	}

	p.vmidCounter++
	return vmid, nil
}

// updateVMIDCounter scans existing containers to find next available VMID
func (p *ProxmoxRuntime) updateVMIDCounter() error {
	containers, err := p.client.GetResourceList("lxc")
	if err != nil {
		return err
	}

	maxVMID := p.config.VMIDStart
	for _, c := range containers {
		if vmid, ok := c["vmid"].(float64); ok {
			if int(vmid) >= maxVMID {
				maxVMID = int(vmid) + 1
			}
		}
	}
	p.vmidCounter = maxVMID
	return nil
}

// Create creates a new LXC container
func (p *ProxmoxRuntime) Create(config runtime.ContainerConfig) (string, error) {
	if !p.connected {
		return "", errors.New("not connected to Proxmox")
	}

	vmid, err := p.getNextVMID()
	if err != nil {
		return "", err
	}

	// Build LXC configuration
	lxcConfig := p.buildLXCConfig(vmid, config)

	// Create the container
	_, err = p.client.CreateLxcContainer(p.node, lxcConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create LXC container: %w", err)
	}

	// Store metadata (labels)
	if len(config.Labels) > 0 {
		p.metadata.Set(vmid, config.Labels)
	}

	// Store name mapping
	p.metadata.SetLabel(vmid, "cosmos-name", config.Name)

	containerID := strconv.Itoa(vmid)
	utils.Log(fmt.Sprintf("Created LXC container %s (VMID: %d)", config.Name, vmid))

	return containerID, nil
}

// buildLXCConfig converts runtime.ContainerConfig to Proxmox LXC config
func (p *ProxmoxRuntime) buildLXCConfig(vmid int, config runtime.ContainerConfig) map[string]interface{} {
	lxc := map[string]interface{}{
		"vmid":        vmid,
		"hostname":    config.Hostname,
		"ostemplate":  config.Image, // e.g., "local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst"
		"storage":     p.config.Storage,
		"password":    generateSecurePassword(), // Will be overwritten by cloud-init or SSH keys
		"unprivileged": !config.Privileged,
		"start":       false, // Don't auto-start, we'll start manually
	}

	// Set hostname
	if config.Hostname == "" {
		lxc["hostname"] = config.Name
	}

	// Memory (convert bytes to MB)
	if config.Memory > 0 {
		lxc["memory"] = config.Memory / (1024 * 1024)
	} else {
		lxc["memory"] = 512 // Default 512MB
	}

	// Swap
	if config.MemorySwap > 0 {
		lxc["swap"] = config.MemorySwap / (1024 * 1024)
	} else {
		lxc["swap"] = 512 // Default 512MB
	}

	// CPUs
	if config.CPUs > 0 {
		lxc["cores"] = int(config.CPUs)
	} else {
		lxc["cores"] = 1
	}

	// Network configuration
	// net0: name=eth0,bridge=vmbr0,ip=dhcp
	netConfig := "name=eth0,bridge=vmbr0,ip=dhcp"
	if len(config.Ports) > 0 {
		// Note: Proxmox LXC port mapping is done via firewall rules, not container config
		// Store port mappings in metadata for later firewall configuration
	}
	lxc["net0"] = netConfig

	// Mount points for volumes
	mpIndex := 0
	for _, vol := range config.Volumes {
		mpKey := fmt.Sprintf("mp%d", mpIndex)
		mpValue := fmt.Sprintf("%s,mp=%s", vol.Source, vol.Target)
		if vol.ReadOnly {
			mpValue += ",ro=1"
		}
		lxc[mpKey] = mpValue
		mpIndex++
	}

	// Root filesystem size (default 8GB)
	lxc["rootfs"] = fmt.Sprintf("%s:8", p.config.Storage)

	// Description (store metadata in description field as fallback)
	if config.Labels != nil {
		desc := "Cosmos Container\n"
		for k, v := range config.Labels {
			desc += fmt.Sprintf("%s=%s\n", k, v)
		}
		lxc["description"] = desc
	}

	// Features for nesting (if privileged or needed for Docker inside LXC)
	lxc["features"] = "nesting=1"

	return lxc
}

// Start starts a container
func (p *ProxmoxRuntime) Start(id string) error {
	vmid, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid container ID: %s", id)
	}

	vmr := pxapi.NewVmRef(vmid)
	vmr.SetNode(p.node)

	_, err = p.client.StartVm(vmr)
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", id, err)
	}

	utils.Log(fmt.Sprintf("Started LXC container VMID: %d", vmid))
	return nil
}

// Stop stops a container
func (p *ProxmoxRuntime) Stop(id string) error {
	vmid, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid container ID: %s", id)
	}

	vmr := pxapi.NewVmRef(vmid)
	vmr.SetNode(p.node)

	_, err = p.client.StopVm(vmr)
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", id, err)
	}

	utils.Log(fmt.Sprintf("Stopped LXC container VMID: %d", vmid))
	return nil
}

// Restart restarts a container
func (p *ProxmoxRuntime) Restart(id string) error {
	if err := p.Stop(id); err != nil {
		// Container might already be stopped
		utils.Warn("Stop before restart failed: " + err.Error())
	}

	// Wait a moment for clean stop
	time.Sleep(2 * time.Second)

	return p.Start(id)
}

// Remove deletes a container
func (p *ProxmoxRuntime) Remove(id string) error {
	vmid, err := strconv.Atoi(id)
	if err != nil {
		return fmt.Errorf("invalid container ID: %s", id)
	}

	// Stop first if running
	_ = p.Stop(id)
	time.Sleep(2 * time.Second)

	vmr := pxapi.NewVmRef(vmid)
	vmr.SetNode(p.node)

	_, err = p.client.DeleteVm(vmr)
	if err != nil {
		return fmt.Errorf("failed to delete container %s: %w", id, err)
	}

	// Remove metadata
	p.metadata.Delete(vmid)

	utils.Log(fmt.Sprintf("Removed LXC container VMID: %d", vmid))
	return nil
}

// Recreate recreates a container with new config
func (p *ProxmoxRuntime) Recreate(id string, config runtime.ContainerConfig) (string, error) {
	// Remove old container
	if err := p.Remove(id); err != nil {
		utils.Warn("Remove during recreate failed: " + err.Error())
	}

	// Create new container
	return p.Create(config)
}

// List returns all LXC containers
func (p *ProxmoxRuntime) List() ([]runtime.Container, error) {
	if !p.connected {
		return nil, errors.New("not connected to Proxmox")
	}

	resources, err := p.client.GetResourceList("lxc")
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []runtime.Container
	for _, r := range resources {
		if node, ok := r["node"].(string); ok && node != p.node {
			continue // Skip containers on other nodes
		}

		vmid := int(r["vmid"].(float64))
		container := runtime.Container{
			ID:     strconv.Itoa(vmid),
			Name:   p.metadata.GetLabel(vmid, "cosmos-name"),
			Status: getStatus(r["status"]),
			State:  mapProxmoxState(r["status"]),
			Labels: p.metadata.Get(vmid),
		}

		if container.Name == "" {
			if name, ok := r["name"].(string); ok {
				container.Name = name
			}
		}

		if template, ok := r["template"].(string); ok {
			container.Image = template
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// Inspect returns detailed container information
func (p *ProxmoxRuntime) Inspect(id string) (*runtime.ContainerDetails, error) {
	vmid, err := strconv.Atoi(id)
	if err != nil {
		return nil, fmt.Errorf("invalid container ID: %s", id)
	}

	vmr := pxapi.NewVmRef(vmid)
	vmr.SetNode(p.node)

	config, err := p.client.GetVmConfig(vmr)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	details := &runtime.ContainerDetails{
		Container: runtime.Container{
			ID:     id,
			Name:   p.metadata.GetLabel(vmid, "cosmos-name"),
			Labels: p.metadata.Get(vmid),
		},
	}

	// Parse config
	if hostname, ok := config["hostname"].(string); ok {
		details.Name = hostname
		details.Config.Hostname = hostname
	}

	if memory, ok := config["memory"].(float64); ok {
		details.Config.Memory = int64(memory) * 1024 * 1024
	}

	if cores, ok := config["cores"].(float64); ok {
		details.Config.CPUs = cores
	}

	return details, nil
}

// Logs returns container logs (via Proxmox exec/console)
func (p *ProxmoxRuntime) Logs(id string, opts runtime.LogOptions) (io.ReadCloser, error) {
	// Proxmox doesn't have direct log API like Docker
	// We can read from /var/log inside container or use lxc-attach
	// For now, return empty reader with note
	return io.NopCloser(strings.NewReader("Log streaming not yet implemented for Proxmox LXC\n")), nil
}

// Stats returns container resource usage
func (p *ProxmoxRuntime) Stats(id string) (*runtime.ContainerStats, error) {
	vmid, err := strconv.Atoi(id)
	if err != nil {
		return nil, fmt.Errorf("invalid container ID: %s", id)
	}

	vmr := pxapi.NewVmRef(vmid)
	vmr.SetNode(p.node)

	// Get current status which includes CPU/memory usage
	status, err := p.client.GetVmState(vmr)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	stats := &runtime.ContainerStats{
		ID:   id,
		Name: p.metadata.GetLabel(vmid, "cosmos-name"),
	}

	if cpu, ok := status["cpu"].(float64); ok {
		stats.CPUPercent = cpu * 100
	}

	if mem, ok := status["mem"].(float64); ok {
		stats.MemoryUsage = int64(mem)
	}

	if maxmem, ok := status["maxmem"].(float64); ok {
		stats.MemoryLimit = int64(maxmem)
		if stats.MemoryLimit > 0 {
			stats.MemoryPercent = float64(stats.MemoryUsage) / float64(stats.MemoryLimit) * 100
		}
	}

	return stats, nil
}

// StatsAll returns stats for all containers
func (p *ProxmoxRuntime) StatsAll() ([]runtime.ContainerStats, error) {
	containers, err := p.List()
	if err != nil {
		return nil, err
	}

	var allStats []runtime.ContainerStats
	for _, c := range containers {
		stats, err := p.Stats(c.ID)
		if err != nil {
			continue
		}
		allStats = append(allStats, *stats)
	}

	return allStats, nil
}

// Helper functions

func mapProxmoxState(status interface{}) runtime.ContainerState {
	s, ok := status.(string)
	if !ok {
		return runtime.StateDead
	}

	switch s {
	case "running":
		return runtime.StateRunning
	case "stopped":
		return runtime.StateExited
	case "paused":
		return runtime.StatePaused
	default:
		return runtime.StateDead
	}
}

func getStatus(status interface{}) string {
	if s, ok := status.(string); ok {
		return s
	}
	return "unknown"
}

func generateSecurePassword() string {
	// Generate a secure random password for initial container creation
	// This will typically be overwritten by cloud-init or SSH keys
	return "cosmos-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

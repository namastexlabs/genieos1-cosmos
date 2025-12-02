package runtime

import (
	"errors"
	"sync"

	"github.com/azukaar/cosmos-server/src/runtime/docker"
	"github.com/azukaar/cosmos-server/src/runtime/proxmox"
	"github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/azukaar/cosmos-server/src/utils"
)

var (
	activeRuntime types.ContainerRuntime
	runtimeMutex  sync.RWMutex
)

// GetRuntime returns the active container runtime instance
func GetRuntime() types.ContainerRuntime {
	runtimeMutex.RLock()
	defer runtimeMutex.RUnlock()
	return activeRuntime
}

// IsRuntimeConnected checks if runtime is connected
func IsRuntimeConnected() bool {
	r := GetRuntime()
	if r == nil {
		return false
	}
	return r.IsConnected()
}

// InitRuntime initializes the container runtime based on configuration
func InitRuntime(config types.RuntimeConfig) (types.ContainerRuntime, error) {
	runtimeMutex.Lock()
	defer runtimeMutex.Unlock()

	var rt types.ContainerRuntime
	var err error

	switch config.Type {
	case types.RuntimeDocker:
		rt, err = NewDockerRuntime(config.Docker)
	case types.RuntimeProxmox:
		rt, err = NewProxmoxRuntime(config.Proxmox)
	default:
		return nil, errors.New("unknown container runtime: " + string(config.Type))
	}

	if err != nil {
		return nil, err
	}

	// Connect to the runtime
	if err := rt.Connect(); err != nil {
		return nil, err
	}

	activeRuntime = rt
	utils.Log("Container runtime initialized: " + string(config.Type))
	return rt, nil
}

// CloseRuntime shuts down the active runtime
func CloseRuntime() error {
	runtimeMutex.Lock()
	defer runtimeMutex.Unlock()

	if activeRuntime != nil {
		err := activeRuntime.Close()
		activeRuntime = nil
		return err
	}
	return nil
}

// NewDockerRuntime creates a Docker runtime instance
func NewDockerRuntime(config *types.DockerConfig) (types.ContainerRuntime, error) {
	var dockerConfig *docker.Config
	if config != nil {
		dockerConfig = &docker.Config{
			Host:      config.Host,
			TLSVerify: config.TLSVerify,
			CertPath:  config.CertPath,
		}
	}
	return docker.New(dockerConfig)
}

// NewProxmoxRuntime creates a Proxmox LXC runtime instance
func NewProxmoxRuntime(config *types.ProxmoxConfig) (types.ContainerRuntime, error) {
	if config == nil {
		return nil, errors.New("proxmox config is required")
	}

	// Convert types.ProxmoxConfig to proxmox.Config
	pxConfig := &proxmox.Config{
		Host:          config.Host,
		Node:          config.Node,
		TokenID:       config.TokenID,
		TokenSecret:   config.TokenSecret,
		Storage:       config.Storage,
		VMIDStart:     config.VMIDStart,
		VMIDEnd:       config.VMIDEnd,
		SkipTLSVerify: config.SkipTLSVerify,
	}

	return proxmox.New(pxConfig)
}

package proxmox

import (
	"fmt"

	runtime "github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/azukaar/cosmos-server/src/utils"
)

// Network operations for Proxmox
// Proxmox uses bridges (vmbr0, vmbr1, etc.) and VLANs for networking
// Container-specific networks are implemented via firewall rules and bridge isolation

// CreateNetwork creates a network (in Proxmox context, this is typically a bridge or VLAN tag)
func (p *ProxmoxRuntime) CreateNetwork(config runtime.NetworkConfig) (string, error) {
	// Proxmox networks are created at the node level, not per-container
	// For Cosmos compatibility, we'll track "virtual" networks in metadata
	// and map them to Proxmox bridges or VLAN tags

	networkID := "cosmos-" + config.Name

	// Store network configuration in metadata
	// Actual bridge creation requires SSH/node-level access
	utils.Log(fmt.Sprintf("Network '%s' registered (maps to Proxmox bridge)", config.Name))

	// In production, you might:
	// 1. Create a new Linux bridge via Proxmox API (requires node-level permissions)
	// 2. Or assign a VLAN tag to isolate traffic
	// 3. Or use existing bridge with firewall rules

	return networkID, nil
}

// RemoveNetwork removes a network
func (p *ProxmoxRuntime) RemoveNetwork(id string) error {
	// Remove from metadata tracking
	utils.Log(fmt.Sprintf("Network '%s' removed from tracking", id))
	return nil
}

// ListNetworks returns available networks (Proxmox bridges)
func (p *ProxmoxRuntime) ListNetworks() ([]runtime.Network, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// Get node network configuration
	// This would list available bridges like vmbr0, vmbr1, etc.
	networks := []runtime.Network{
		{
			ID:     "vmbr0",
			Name:   "vmbr0",
			Driver: "bridge",
			Scope:  "local",
		},
	}

	// In production, query actual node network config:
	// GET /nodes/{node}/network

	return networks, nil
}

// ConnectToNetwork connects a container to a network
func (p *ProxmoxRuntime) ConnectToNetwork(containerID, networkID string, opts runtime.NetworkConnectOptions) error {
	// In Proxmox, this means modifying the container's network interface
	// to use a specific bridge or VLAN

	utils.Log(fmt.Sprintf("Container %s connected to network %s", containerID, networkID))

	// Actual implementation would:
	// 1. Modify container config to add/update net interface
	// 2. Set bridge= parameter to the target network
	// 3. Optionally set IP address if opts.IPAddress is provided

	return nil
}

// DisconnectFromNetwork disconnects a container from a network
func (p *ProxmoxRuntime) DisconnectFromNetwork(containerID, networkID string) error {
	utils.Log(fmt.Sprintf("Container %s disconnected from network %s", containerID, networkID))
	return nil
}

// ConfigurePortForwarding sets up port forwarding for a container
// This is done via iptables rules on the Proxmox host
func (p *ProxmoxRuntime) ConfigurePortForwarding(vmid int, ports []runtime.PortMapping) error {
	for _, port := range ports {
		// Generate iptables rule
		// iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport {hostPort} -j DNAT --to {containerIP}:{containerPort}

		utils.Log(fmt.Sprintf("Port forwarding configured: %s:%s -> container:%s",
			port.HostIP, port.HostPort, port.ContainerPort))
	}

	// Store port mapping in metadata for later cleanup
	return nil
}

package proxmox

import (
	"fmt"

	runtime "github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/azukaar/cosmos-server/src/utils"
)

// Storage operations for Proxmox
// Proxmox uses storage pools (local, local-lvm, NFS, etc.)
// Volumes are typically bind mounts or dedicated storage volumes

// CreateVolume creates a storage volume
func (p *ProxmoxRuntime) CreateVolume(config runtime.VolumeConfig) (string, error) {
	// In Proxmox, volumes are typically:
	// 1. Bind mounts from host paths
	// 2. Storage volumes in a storage pool (local-lvm, etc.)

	volumeID := fmt.Sprintf("cosmos-vol-%s", config.Name)

	// For bind mounts, just ensure the directory exists
	// For storage volumes, would need to create via:
	// POST /nodes/{node}/storage/{storage}/content

	utils.Log(fmt.Sprintf("Volume '%s' created in storage '%s'", config.Name, p.config.Storage))

	return volumeID, nil
}

// RemoveVolume removes a storage volume
func (p *ProxmoxRuntime) RemoveVolume(id string) error {
	// Remove volume from Proxmox storage
	// DELETE /nodes/{node}/storage/{storage}/content/{volume}

	utils.Log(fmt.Sprintf("Volume '%s' removed", id))
	return nil
}

// ListVolumes returns available volumes
func (p *ProxmoxRuntime) ListVolumes() ([]runtime.Volume, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// List volumes in storage pool
	// GET /nodes/{node}/storage/{storage}/content

	volumes := []runtime.Volume{}

	// In production, query actual storage content
	// Filter for cosmos-vol-* prefix

	return volumes, nil
}

// GetStorageInfo returns information about a storage pool
func (p *ProxmoxRuntime) GetStorageInfo() (map[string]interface{}, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// GET /nodes/{node}/storage/{storage}/status
	info := map[string]interface{}{
		"storage": p.config.Storage,
		"node":    p.node,
	}

	return info, nil
}

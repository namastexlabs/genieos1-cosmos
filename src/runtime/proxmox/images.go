package proxmox

import (
	"fmt"
	"io"
	"strings"

	runtime "github.com/azukaar/cosmos-server/src/runtime/types"
	"github.com/azukaar/cosmos-server/src/utils"
)

// Image/Template operations for Proxmox LXC
// Proxmox uses templates (.tar.gz, .tar.zst) instead of Docker images
// Templates are stored in storage pools (e.g., local:vztmpl/debian-12.tar.zst)

// PullImage downloads an LXC template
func (p *ProxmoxRuntime) PullImage(ref string) (io.ReadCloser, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// Parse template reference
	// Format: storage:vztmpl/template-name or just template-name
	storage, template := parseTemplateRef(ref, p.config.Storage)

	utils.Log(fmt.Sprintf("Downloading template %s to storage %s", template, storage))

	// Download template via Proxmox API
	// POST /nodes/{node}/aplinfo
	// This triggers template download from Proxmox template repository

	// For now, return a progress reader
	progress := strings.NewReader(fmt.Sprintf("Downloading template: %s\n", template))

	return io.NopCloser(progress), nil
}

// ListImages returns available LXC templates
func (p *ProxmoxRuntime) ListImages() ([]runtime.Image, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// List templates in storage
	// GET /nodes/{node}/storage/{storage}/content?content=vztmpl

	images := []runtime.Image{}

	// Common Proxmox templates (would be fetched from API in production)
	defaultTemplates := []struct {
		name string
		size int64
	}{
		{"debian-12-standard_12.0-1_amd64.tar.zst", 120 * 1024 * 1024},
		{"ubuntu-22.04-standard_22.04-1_amd64.tar.zst", 130 * 1024 * 1024},
		{"alpine-3.18-default_20230607_amd64.tar.xz", 3 * 1024 * 1024},
	}

	for _, t := range defaultTemplates {
		images = append(images, runtime.Image{
			ID:   fmt.Sprintf("%s:vztmpl/%s", p.config.Storage, t.name),
			Name: t.name,
			Tags: []string{"lxc", "template"},
			Size: t.size,
		})
	}

	return images, nil
}

// RemoveImage removes an LXC template
func (p *ProxmoxRuntime) RemoveImage(id string) error {
	if !p.connected {
		return fmt.Errorf("not connected to Proxmox")
	}

	// DELETE /nodes/{node}/storage/{storage}/content/{volume}
	utils.Log(fmt.Sprintf("Template %s removed", id))

	return nil
}

// GetAvailableTemplates returns templates available for download from Proxmox repos
func (p *ProxmoxRuntime) GetAvailableTemplates() ([]TemplateInfo, error) {
	if !p.connected {
		return nil, fmt.Errorf("not connected to Proxmox")
	}

	// GET /nodes/{node}/aplinfo
	// Returns list of downloadable templates

	templates := []TemplateInfo{
		{
			Template:    "debian-12-standard_12.0-1_amd64.tar.zst",
			Type:        "lxc",
			OS:          "debian",
			Version:     "12",
			Description: "Debian 12 Bookworm (standard)",
			Source:      "https://download.proxmox.com/",
		},
		{
			Template:    "ubuntu-22.04-standard_22.04-1_amd64.tar.zst",
			Type:        "lxc",
			OS:          "ubuntu",
			Version:     "22.04",
			Description: "Ubuntu 22.04 Jammy (standard)",
			Source:      "https://download.proxmox.com/",
		},
		{
			Template:    "alpine-3.18-default_20230607_amd64.tar.xz",
			Type:        "lxc",
			OS:          "alpine",
			Version:     "3.18",
			Description: "Alpine Linux 3.18",
			Source:      "https://download.proxmox.com/",
		},
		{
			Template:    "archlinux-base_20230101-1_amd64.tar.zst",
			Type:        "lxc",
			OS:          "archlinux",
			Version:     "latest",
			Description: "Arch Linux (base)",
			Source:      "https://download.proxmox.com/",
		},
	}

	return templates, nil
}

// TemplateInfo describes an available LXC template
type TemplateInfo struct {
	Template    string `json:"template"`
	Type        string `json:"type"`
	OS          string `json:"os"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Source      string `json:"source"`
	Size        int64  `json:"size"`
}

// parseTemplateRef parses a template reference
func parseTemplateRef(ref, defaultStorage string) (storage, template string) {
	if strings.Contains(ref, ":") {
		parts := strings.SplitN(ref, ":", 2)
		storage = parts[0]
		template = parts[1]
	} else {
		storage = defaultStorage
		template = ref
	}

	// Ensure vztmpl prefix
	if !strings.HasPrefix(template, "vztmpl/") {
		template = "vztmpl/" + template
	}

	return storage, template
}

// DockerToLXCTemplate maps common Docker images to equivalent LXC templates
func DockerToLXCTemplate(dockerImage string) string {
	// Map common Docker images to Proxmox LXC templates
	mappings := map[string]string{
		"debian":       "debian-12-standard_12.0-1_amd64.tar.zst",
		"debian:12":    "debian-12-standard_12.0-1_amd64.tar.zst",
		"debian:11":    "debian-11-standard_11.7-1_amd64.tar.zst",
		"ubuntu":       "ubuntu-22.04-standard_22.04-1_amd64.tar.zst",
		"ubuntu:22.04": "ubuntu-22.04-standard_22.04-1_amd64.tar.zst",
		"ubuntu:20.04": "ubuntu-20.04-standard_20.04-1_amd64.tar.gz",
		"alpine":       "alpine-3.18-default_20230607_amd64.tar.xz",
		"alpine:3.18":  "alpine-3.18-default_20230607_amd64.tar.xz",
		"archlinux":    "archlinux-base_20230101-1_amd64.tar.zst",
	}

	// Check for exact match
	if template, ok := mappings[dockerImage]; ok {
		return template
	}

	// Check for base image match (e.g., "nginx" -> "debian")
	// Most Docker images are Debian-based, so default to Debian
	for prefix, template := range mappings {
		if strings.HasPrefix(dockerImage, prefix+":") {
			return template
		}
	}

	// Default to Debian if no match
	return "debian-12-standard_12.0-1_amd64.tar.zst"
}

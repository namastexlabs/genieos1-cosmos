package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/azukaar/cosmos-server/src/utils"
)

type ProxmoxTestRequest struct {
	Host          string `json:"host"`
	Node          string `json:"node"`
	TokenID       string `json:"tokenID"`
	TokenSecret   string `json:"tokenSecret"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

type ProxmoxTestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Version string `json:"version,omitempty"`
}

func TestProxmoxConnectionRoute(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		utils.HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed, "PROXMOX001")
		return
	}

	var request ProxmoxTestRequest
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		utils.HTTPError(w, "Invalid request: "+err.Error(), http.StatusBadRequest, "PROXMOX002")
		return
	}

	// Validate required fields
	if request.Host == "" {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "Proxmox host URL is required",
		})
		return
	}

	if request.TokenID == "" || request.TokenSecret == "" {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "API Token ID and Secret are required",
		})
		return
	}

	// Create HTTP client with optional TLS skip
	tlsConfig := &tls.Config{
		InsecureSkipVerify: request.SkipTLSVerify,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Build API URL - handle both with and without protocol
	host := request.Host
	if host[0:4] != "http" {
		host = "https://" + host
	}
	apiURL := fmt.Sprintf("%s/api2/json/version", host)

	// Create request
	apiReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "Failed to create request: " + err.Error(),
		})
		return
	}

	// Add authentication header
	apiReq.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", request.TokenID, request.TokenSecret))

	// Execute request
	resp, err := client.Do(apiReq)
	if err != nil {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "Connection failed: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "Authentication failed - check your API Token ID and Secret",
		})
		return
	}

	if resp.StatusCode != 200 {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: fmt.Sprintf("Proxmox API returned status %d", resp.StatusCode),
		})
		return
	}

	// Parse version response
	var versionResp struct {
		Data struct {
			Version string `json:"version"`
			Release string `json:"release"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&versionResp); err != nil {
		json.NewEncoder(w).Encode(ProxmoxTestResponse{
			Success: false,
			Message: "Failed to parse Proxmox response",
		})
		return
	}

	// If node specified, verify it exists
	if request.Node != "" {
		nodeURL := fmt.Sprintf("%s/api2/json/nodes/%s/status", host, request.Node)
		nodeReq, _ := http.NewRequest("GET", nodeURL, nil)
		nodeReq.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", request.TokenID, request.TokenSecret))

		nodeResp, err := client.Do(nodeReq)
		if err != nil || nodeResp.StatusCode != 200 {
			json.NewEncoder(w).Encode(ProxmoxTestResponse{
				Success: false,
				Message: fmt.Sprintf("Connected to Proxmox %s but node '%s' not found or inaccessible", versionResp.Data.Version, request.Node),
			})
			return
		}
		nodeResp.Body.Close()
	}

	json.NewEncoder(w).Encode(ProxmoxTestResponse{
		Success: true,
		Message: fmt.Sprintf("Connected to Proxmox VE %s", versionResp.Data.Version),
		Version: versionResp.Data.Version,
	})
}

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/azukaar/cosmos-server/src/utils"
)

type ProxmoxTestRequest struct {
	Host          string `json:"host"`
	TokenID       string `json:"tokenID"`
	TokenSecret   string `json:"tokenSecret"`
	SkipTLSVerify bool   `json:"skipTLSVerify"`
}

type ProxmoxTestResponse struct {
	Success  bool     `json:"success"`
	Message  string   `json:"message"`
	Version  string   `json:"version,omitempty"`
	Nodes    []string `json:"nodes,omitempty"`
	Storages []string `json:"storages,omitempty"`
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
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
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

	// Fetch available nodes
	nodesURL := fmt.Sprintf("%s/api2/json/nodes", host)
	nodesReq, _ := http.NewRequest("GET", nodesURL, nil)
	nodesReq.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", request.TokenID, request.TokenSecret))

	var nodeNames []string
	nodesResp, err := client.Do(nodesReq)
	if err == nil && nodesResp.StatusCode == 200 {
		var nodesData struct {
			Data []struct {
				Node string `json:"node"`
			} `json:"data"`
		}
		if err := json.NewDecoder(nodesResp.Body).Decode(&nodesData); err == nil {
			for _, n := range nodesData.Data {
				nodeNames = append(nodeNames, n.Node)
			}
		}
		nodesResp.Body.Close()
	}

	// Fetch storage for first node (if available)
	var storageNames []string
	if len(nodeNames) > 0 {
		storageURL := fmt.Sprintf("%s/api2/json/nodes/%s/storage", host, nodeNames[0])
		storageReq, _ := http.NewRequest("GET", storageURL, nil)
		storageReq.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", request.TokenID, request.TokenSecret))

		storageResp, err := client.Do(storageReq)
		if err == nil && storageResp.StatusCode == 200 {
			var storageData struct {
				Data []struct {
					Storage string `json:"storage"`
					Content string `json:"content"`
				} `json:"data"`
			}
			if err := json.NewDecoder(storageResp.Body).Decode(&storageData); err == nil {
				for _, s := range storageData.Data {
					// Only include storage that can hold rootdir or images
					if s.Content == "" ||
					   strings.Contains(s.Content, "rootdir") ||
					   strings.Contains(s.Content, "images") ||
					   strings.Contains(s.Content, "vztmpl") {
						storageNames = append(storageNames, s.Storage)
					}
				}
			}
			storageResp.Body.Close()
		}
	}

	json.NewEncoder(w).Encode(ProxmoxTestResponse{
		Success:  true,
		Message:  fmt.Sprintf("Connected to Proxmox VE %s", versionResp.Data.Version),
		Version:  versionResp.Data.Version,
		Nodes:    nodeNames,
		Storages: storageNames,
	})
}

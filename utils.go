package tcpguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && n != nil {
			nets = append(nets, n)
			continue
		}
		// Support single IPs
		ip := net.ParseIP(strings.TrimSpace(c))
		if ip != nil {
			mask := net.CIDRMask(len(ip)*8, len(ip)*8)
			nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return nets
}

func ipInNets(ipStr string, nets []*net.IPNet) bool {
	if ipStr == "" {
		return false
	}
	addr := net.ParseIP(ipStr)
	if addr == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func loadConfig(configDir string) (*AnomalyConfig, error) {
	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global: GlobalRules{
				Rules: make(map[string]Rule),
			},
			APIEndpoints: make(map[string]EndpointRules),
		},
	}
	
	// Load global rules
	if err := loadGlobalRules(configDir+"/global", config); err != nil {
		return nil, fmt.Errorf("failed to load global rules: %v", err)
	}
	
	// Load pipeline rules
	if err := loadPipelineRules(configDir+"/rules", config); err != nil {
		return nil, fmt.Errorf("failed to load pipeline rules: %v", err)
	}
	
	// Load endpoint rules
	if err := loadEndpointRules(configDir+"/endpoints", config); err != nil {
		return nil, fmt.Errorf("failed to load endpoint rules: %v", err)
	}
	
	return config, nil
}

func loadGlobalRules(globalDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(globalDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read global rules directory: %v", err)
	}
	
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		// Validate file name to prevent directory traversal
		if strings.Contains(file.Name(), "..") || strings.Contains(file.Name(), "/") {
			return fmt.Errorf("invalid file name: %s", file.Name())
		}
		
		filePath := globalDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read global rule file %s: %v", file.Name(), err)
		}
		
		// Limit file size to prevent memory exhaustion
		if len(data) > 1024*1024 { // 1MB limit
			return fmt.Errorf("config file %s is too large", file.Name())
		}
		
		// Probe JSON to decide how to handle: rule or global overlay
		var probe map[string]any
		if err := json.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("failed to parse global file %s: %v", file.Name(), err)
		}
		nameVal, hasName := probe["name"].(string)
		if hasName && strings.TrimSpace(nameVal) != "" {
			// This is a Rule
			var rule Rule
			if err := json.Unmarshal(data, &rule); err != nil {
				return fmt.Errorf("failed to parse global rule file %s: %v", file.Name(), err)
			}
			if config.AnomalyDetectionRules.Global.Rules == nil {
				config.AnomalyDetectionRules.Global.Rules = make(map[string]Rule)
			}
			config.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
			continue
		}
		// Otherwise, treat as a global overlay/config
		type globalOverlay struct {
			AllowCIDRs        []string `json:"allowCIDRs"`
			DenyCIDRs         []string `json:"denyCIDRs"`
			TrustProxy        bool     `json:"trustProxy"`
			TrustedProxyCIDRs []string `json:"trustedProxyCIDRs"`
			BanEscalation     *struct {
				TempThreshold int    `json:"tempThreshold"`
				Window        string `json:"window"`
			} `json:"banEscalation"`
		}
		var overlay globalOverlay
		if err := json.Unmarshal(data, &overlay); err != nil {
			return fmt.Errorf("failed to parse global overlay file %s: %v", file.Name(), err)
		}
		gr := &config.AnomalyDetectionRules.Global
		if len(overlay.AllowCIDRs) > 0 {
			gr.AllowCIDRs = overlay.AllowCIDRs
		}
		if len(overlay.DenyCIDRs) > 0 {
			gr.DenyCIDRs = overlay.DenyCIDRs
		}
		// TrustProxy is a boolean; we set it if the key existed or true. Since we can't easily detect presence, honor value directly.
		gr.TrustProxy = gr.TrustProxy || overlay.TrustProxy
		if len(overlay.TrustedProxyCIDRs) > 0 {
			gr.TrustedProxyCIDRs = overlay.TrustedProxyCIDRs
		}
		if overlay.BanEscalation != nil {
			gr.BanEscalationConfig = &struct {
				TempThreshold int    `json:"tempThreshold"`
				Window        string `json:"window"`
			}{
				TempThreshold: overlay.BanEscalation.TempThreshold,
				Window:        overlay.BanEscalation.Window,
			}
		}
	}
	
	return nil
}

func loadPipelineRules(rulesDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read rules directory: %v", err)
	}
	
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		filePath := rulesDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %v", file.Name(), err)
		}
		
		var rule Rule
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %v", file.Name(), err)
		}
		
		config.AnomalyDetectionRules.Global.Rules[rule.Name] = rule
	}
	
	return nil
}

func loadEndpointRules(endpointsDir string, config *AnomalyConfig) error {
	files, err := os.ReadDir(endpointsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to read endpoints directory: %v", err)
	}
	
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		filePath := endpointsDir + "/" + file.Name()
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read endpoint file %s: %v", file.Name(), err)
		}
		
		var endpoint EndpointRules
		if err := json.Unmarshal(data, &endpoint); err != nil {
			return fmt.Errorf("failed to parse endpoint file %s: %v", file.Name(), err)
		}
		
		config.AnomalyDetectionRules.APIEndpoints[endpoint.Endpoint] = endpoint
	}
	
	return nil
}

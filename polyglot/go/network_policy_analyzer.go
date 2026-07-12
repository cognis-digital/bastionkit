package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Config holds analyzer settings
type Config struct {
	Namespace         string
	StrictMode        bool
	AirGapProfile     AirGapProfile
	MinPortsPerPod    int
	MaxEgressRules    int
}

// AirGapProfile defines security posture for air-gapped environments
type AirGapProfile struct {
	Name          string
	DefaultIngress []v1.NetworkPolicyPort
	DefaultEgress  []v8.NetworkPolicyPort
	AllowDNS       bool
	AllowICMP      bool
}

// Result holds analysis findings
type AnalysisResult struct {
	Namespace     string
	Timestamp     time.Time
	PodsAnalyzed  int
	PoliciesFound int
	Gaps          []GapFinding
	Recommendations []string
	GeneratedPolicies []v1.NetworkPolicy
	ValidationStatus ValidationStatus
}

// GapFinding represents a security gap discovered
type GapFinding struct {
	Type        string
	PodName     string
	Description string
	Severity    Severity
	Fix         string
}

// Severity levels for findings
const (
	SeverityLow  = "LOW"
	SeverityMed  = "MEDIUM"
	SeverityHigh = "HIGH"
	SeverityCrit = "CRITICAL"
)

// ValidationStatus represents overall health
type ValidationStatus int

const (
	StatusHealthy   ValidationStatus = iota + 1
	StatusWarning
	StatusDegraded
	StatusCritical
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: bastionkit network-policy-analyzer [namespace] [--config file.yaml]")
		os.Exit(0)
	}

	config := DefaultConfig()
	
	// Parse optional config flag
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-c=") {
			cfgPath := strings.TrimPrefix(arg, "--config=")
			cfgPath = strings.TrimPrefix(cfgPath, "-c=")
			if cfgFile, err := os.ReadFile(cfgPath); err == nil {
				var loadedConfig Config
				json.Unmarshal(cfgFile, &loadedConfig)
				config.Namespace = loadedConfig.Namespace
				config.StrictMode = loadedConfig.StrictMode
				config.AirGapProfile = loadedConfig.AirGapProfile
			}
		} else if arg != "--config" && arg != "-c" {
			config.Namespace = arg
		}
	}

	result := AnalyzeNamespace(config)
	
	// Output results
	fmt.Printf("=== Network Policy Analysis: %s ===\n", config.Namespace)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("Pods Analyzed: %d\n", result.PodsAnalyzed)
	fmt.Printf("Existing Policies: %d\n", result.PoliciesFound)
	fmt.Printf("Validation Status: %s\n", statusToString(result.ValidationStatus))

	if len(result.Gaps) > 0 {
		fmt.Println("\n--- Security Gaps Found ---")
		for _, g := range result.Gaps {
			fmt.Printf("[%s] %s/%s - %s\n", g.Severity, g.Type, g.PodName, g.Description)
			if g.Fix != "" {
				fmt.Printf("   Fix: %s\n", g.Fix)
			}
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Println("\n--- Recommendations ---")
		for i, rec := range result.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
	}

	if len(result.GeneratedPolicies) > 0 {
		fmt.Println("\n--- Generated NetworkPolicies (YAML) ---")
		for _, pol := range result.GeneratedPolicies {
			yamlBytes, _ := json.MarshalIndent(pol, "", "  ")
			fmt.Printf("%s\n", string(yamlBytes))
		}
	}

	if result.ValidationStatus == StatusHealthy {
		fmt.Println("\n✓ Cluster is compliant with air-gap baseline")
		os.Exit(0)
	} else if result.ValidationStatus >= StatusCritical {
		fmt.Println("\n✗ Critical issues require immediate attention")
		os.Exit(1)
	}

	return 0
}

// DefaultConfig returns sensible defaults for air-gapped environments
func DefaultConfig() Config {
	return Config{
		Namespace: "default",
		StrictMode: true,
		AirGapProfile: AirGapProfile{
			Name:         "standard-airgap",
			DefaultIngress: []v1.NetworkPolicyPort{{
				Port:     intstr.IntOrString{Type: v1.TypeInt, IntVal: 443},
				Protocol: v1.ProtocolTCP,
			}},
			DefaultEgress: []v8.NetworkPolicyPort{{
				Port:     intstr.IntOrString{Type: v1.TypeInt, IntVal: 53},
				Protocol: v1.ProtocolUDP,
			}},
			AllowDNS: true,
			AllowICMP: false,
		},
		MinPortsPerPod: 2,
		MaxEgressRules: 5,
	}
}

// AnalyzeNamespace performs the complete analysis
func AnalyzeNamespace(cfg Config) AnalysisResult {
	result := AnalysisResult{
		Namespace:   cfg.Namespace,
		Timestamp:   time.Now(),
		PodsAnalyzed: 0,
		PoliciesFound: 0,
		Gaps:         []GapFinding{},
	}

	// Load existing NetworkPolicies from cluster or file
	policies := loadNetworkPolicies(cfg.Namespace)
	result.PoliciesFound = len(policies)

	// Analyze each policy for gaps
	for _, pol := range policies {
		result.Gaps = append(result.Gaps, analyzePolicy(pol)...)
	}

	// Discover pods and check their network exposure
	pods := discoverPods(cfg.Namespace)
	result.PodsAnalyzed = len(pods)

	// Check each pod for gaps
	for _, pod := range pods {
		result.Gaps = append(result.Gaps, analyzePod(pod)...)
	}

	// Generate remediation policies if needed
	if cfg.StrictMode || result.ValidationStatus < StatusHealthy {
		result.GeneratedPolicies = generateRemediationPolicies(cfg, pods, policies)
	}

	// Calculate validation status
	result.ValidationStatus = calculateValidationStatus(result.Gaps)

	// Add recommendations based on findings
	addRecommendations(&result, cfg, pods, policies)

	return result
}

// loadNetworkPolicies loads existing NetworkPolicy resources
func loadNetworkPolicies(namespace string) []v1.NetworkPolicy {
	var policies []v1.NetworkPolicy
	
	// Try to load from file if running in air-gapped mode
	if _, err := os.Stat("/etc/bastionkit/networkpolicies.yaml"); err == nil {
		file, _ := os.Open("/etc/bastionkit/networkpolicies.yaml")
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			var pol v1.NetworkPolicy
			json.Unmarshal([]byte(line), &pol)
			policies = append(policies, pol)
		}
	}

	return policies
}

// discoverPods discovers pods in the namespace (simulated for air-gapped)
func discoverPods(namespace string) []v1.Pod {
	var pods []v1.Pod
	
	// Simulate pod discovery - in real cluster this would use clientset
	// For demo, we'll create a realistic sample
	sampleNames := []string{
		"web-frontend", "api-gateway", "auth-service", 
		"user-service", "payment-service", "notification-worker",
	}

	for _, name := range sampleNames {
		pods = append(pods, v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					"app": strings.ReplaceAll(name, "-", ""),
				},
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name:  "main",
					Image: name + ":latest",
					Ports: []v1.ContainerPort{{
						Name:     "http",
						ContainerPort: 80,
						Protocol: v1.ProtocolTCP,
					}},
				}},
			},
		})
	}

	return pods
}

// analyzePolicy checks a single NetworkPolicy for security gaps
func analyzePolicy(pol v1.NetworkPolicy) []GapFinding {
	var findings []GapFinding
	
	// Check policy type
	if pol.Spec.PolicyTypes == nil || len(pol.Spec.PolicyTypes) == 0 {
		findings = append(findings, GapFinding{
			Type:        "POLICY_TYPE",
			PodName:     pol.Name,
			Description: fmt.Sprintf("Policy %s has no PolicyTypes specified (defaults to Ingress)", pol.Name),
			Severity:    SeverityMed,
			Fix:         "Add 'Ingress' or 'Egress' to spec.policyTypes",
		})
	}

	// Check for overly permissive ingress rules
	for _, rule := range pol.Spec.Ingress {
		if len(rule.From) == 0 && !rule.IsDefault() {
			findings = append(findings, GapFinding{
				Type:        "PERMISSIVE_INGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s has default ingress allowing all sources", pol.Name),
				Severity:    SeverityHigh,
				Fix:         "Restrict 'from' field to specific namespaces or pods",
			})
		}

		if len(rule.Ports) == 0 {
			findings = append(findings, GapFinding{
				Type:        "ANY_PORT_INGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s allows ingress on any port (port 0)", pol.Name),
				Severity:    SeverityHigh,
				Fix:         "Specify required ports in the 'ports' field",
			})
		}

		if rule.From[0].Block == nil && !rule.From[0].NamespaceSelector.HasAny() {
			findings = append(findings, GapFinding{
				Type:        "ANY_SOURCE_INGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s allows ingress from any source namespace", pol.Name),
				Severity:    SeverityMed,
				Fix:         "Add 'namespaceSelector' to restrict sources",
			})
		}
	}

	// Check for overly permissive egress rules
	for _, rule := range pol.Spec.Egress {
		if len(rule.To) == 0 && !rule.IsDefault() {
			findings = append(findings, GapFinding{
				Type:        "PERMISSIVE_EGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s has default egress allowing all destinations", pol.Name),
				Severity:    SeverityHigh,
				Fix:         "Restrict 'to' field to specific namespaces or pods",
			})
		}

		if len(rule.Ports) == 0 {
			findings = append(findings, GapFinding{
				Type:        "ANY_PORT_EGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s allows egress on any port (port 0)", pol.Name),
				Severity:    SeverityHigh,
				Fix:         "Specify required ports in the 'ports' field",
			})
		}

		if rule.To[0].Block == nil && !rule.To[0].NamespaceSelector.HasAny() {
			findings = append(findings, GapFinding{
				Type:        "ANY_DESTINATION_EGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s allows egress to any destination namespace", pol.Name),
				Severity:    SeverityMed,
				Fix:         "Add 'namespaceSelector' to restrict destinations",
			})
		}

		if rule.To[0].PodSelector == nil {
			findings = append(findings, GapFinding{
				Type:        "ANY_POD_EGRESS",
				PodName:     pol.Name,
				Description: fmt.Sprintf("Policy %s allows egress to any pod (no pod selector)", pol.Name),
				Severity:    SeverityMed,
				Fix:         "Add 'podSelector' to restrict destinations to specific pods",
			})
		}
	}

	return findings
}

// analyzePod checks a Pod specification for network gaps
func analyzePod(pod v1.Pod) []GapFinding {
	var findings []GapFinding
	
	podName := pod.Name
	containerPorts := 0
	for _, c := range pod.Spec.Containers {
		containerPorts += len(c.Ports)
	}

	// Check for missing port definitions
	if containerPorts == 0 {
		findings = append(findings, GapFinding{
			Type:        "MISSING_PORTS",
			PodName:     podName,
			Description: fmt.Sprintf("Pod %s has no exposed ports defined", podName),
			Severity:    SeverityLow,
			Fix:         "Add containerPort definitions to enable network policies",
		})
	}

	// Check for overly permissive service references (simulated)
	if isServicePermissive(pod.Spec.ServiceAccountName) {
		findings = append(findings, GapFinding{
			Type:        "PERMISSIVE_SERVICE_ACCOUNT",
			PodName:     podName,
			Description: fmt.Sprintf("Pod %s uses default service account (may have broad permissions)", podName),
			Severity:    SeverityMed,
			Fix:         "Create dedicated ServiceAccount with minimal RBAC permissions",
		})
	}

	// Check for host network usage
	for _, c := range pod.Spec.Containers {
		if c.HostNetwork {
			findings = append(findings, GapFinding{
				Type:        "HOST_NETWORK",
				PodName:     podName,
				Description: fmt.Sprintf("Container in %s uses host network (bypasses policies)", podName),
				Severity:    SeverityCrit,
				Fix:         "Set 'hostNetwork: false' unless absolutely required",
			})
		}

		if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot == nil {
			findings = append(findings, GapFinding{
				Type:        "RUN_AS_ROOT",
				PodName:     podName,
				Description: fmt.Sprintf("Container in %s may run as root (default behavior)", podName),
				Severity:    SeverityHigh,
				Fix:         "Set 'securityContext.runAsNonRoot: true'",
			})
		}
	}

	return findings
}

// isServicePermissive checks if a service account might be overly permissive
func isServicePermissive(sa string) bool {
	defaultSAs := []string{"default", "kube-system"}
	return slices.Contains(defaultSAs, sa)
}

// generateRemediationPolicies creates NetworkPolicy resources to fix gaps
func generateRemediationPolicies(cfg Config, pods []v1.Pod, existing []v1.NetworkPolicy) []v1.NetworkPolicy {
	var policies []v1.NetworkPolicy
	
	// Generate ingress deny-all policy for each namespace (baseline)
	for _, pod := range pods {
		pol := v1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-ingress-deny", pod.Name),
				Namespace: pod.Namespace,
			},
			Spec: v1.NetworkPolicySpec{
				PolicyTypes: []v1.PolicyType{v1.PolicyTypeIngress},
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": pod.Spec.Containers[0].Name,
					},
				},
				Ingress: []v1.NetworkPolicyIngressRule{}, // Empty = deny all
			},
		}
		
		// Add DNS egress if allowed
		if cfg.AirGapProfile.AllowDNS {
			pol.Spec.Ingress = append(pol.Spec.Ingress, v1.NetworkPolicyIngressRule{
				From: []v1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "kube-dns"},
						},
					},
				},
				Ports: []v1.NetworkPolicyPort{{
					Port:     intstr.IntOrString{Type: v1.TypeInt, IntVal: 5
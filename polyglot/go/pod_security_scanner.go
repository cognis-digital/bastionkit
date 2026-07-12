//go:build linux || darwin
// +build linux darwin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ============================================================================
// Data Structures
// ============================================================================

type ManifestLoader struct {
	Source string // file, directory, or "-" for stdin
}

type PodValidator struct {
	PSSLevel string // "privileged", "baseline", "restricted"
}

type ClusterAnalyzer struct{}

type ReportGenerator struct {
	OutputFormat string // "json", "yaml", "text"
}

// PSSViolation represents a single security violation found
type PSSViolation struct {
	RuleID       string   `json:"rule_id"`
	Level        string   `json:"level"`
	Message      string   `json:"message"`
	PodName      string   `json:"pod_name,omitempty"`
	Namespace    string   `json:"namespace,omitempty"`
	Container    string   `json:"container,omitempty"`
	Suggestion   string   `json:"suggestion,omitempty"`
	Category     string   `json:"category"` // "privileged", "networking", "capabilities", etc.
	Severity     string   `json:"severity"` // "critical", "high", "medium", "low"
}

// PSSReport represents the complete security scan report
type PSSReport struct {
	Version       string               `json:"version"`
	PSSLevel      string               `json:"pss_level"`
	Source        string               `json:"source"`
	TotalPods     int                  `json:"total_pods"`
	TotalContainers int                `json:"total_containers"`
	Violations    []PSSViolation       `json:"violations"`
	Warnings      []string             `json:"warnings"`
	Summary       PSSSummary           `json:"summary"`
}

type PSSSummary struct {
	CriticalCount   int  `json:"critical_count"`
	HighCount       int  `json:"high_count"`
	MediumCount     int  `json:"medium_count"`
	TotalViolations int  `json:"total_violations"`
	Score           float64 `json:"score"` // 0-100, higher is better
}

// ============================================================================
// PSS Rule Definitions
// ============================================================================

var pssRules = map[string]struct {
	level    string
	category string
	severity string
	message  string
}{
	"PRIV-001": {"privileged", "privileged", "critical", "Container runs as privileged"},
	"PRIV-002": {"baseline", "privileged", "high", "Container requests host network namespace"},
	"PRIV-003": {"restricted", "privileged", "high", "Container shares host PID namespace"},
	"PRIV-004": {"restricted", "privileged", "medium", "Container shares host IPC namespace"},
	"PRIV-005": {"baseline", "capabilities", "high", "Container adds Linux capabilities"},
	"PRIV-006": {"restricted", "capabilities", "critical", "Container requests CAP_SYS_ADMIN"},
	"PRIV-007": {"restricted", "privileged", "critical", "Container runs as non-root user 0"},
	"PRIV-008": {"baseline", "filesystem", "medium", "Root filesystem is writable"},
	"PRIV-009": {"restricted", "privilege_escalation", "high", "AllowPrivilegeEscalation is true"},
	"PRIV-010": {"restricted", "seccomp", "medium", "No seccomp profile configured"},
}

// ============================================================================
// Manifest Loading
// ============================================================================

func (m *ManifestLoader) Load() ([]byte, error) {
	switch m.Source {
	case "-":
		return m.loadFromStdin()
	default:
		return m.loadFromFileOrDirectory(m.Source)
	}
}

func (m *ManifestLoader) loadFromStdin() ([]byte, error) {
	var result []byte
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		result = append(result, scanner.Bytes()...)
		result = append(result, '\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	return result, nil
}

func (m *ManifestLoader) loadFromFileOrDirectory(path string) ([]byte, error) {
	var result []byte
	
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	
	if info.IsDir() {
		result, err = m.loadFromDirectory(path)
		if err != nil {
			return nil, err
		}
	} else if info.Mode().IsRegular() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
		result = append(result, data...)
	}
	
	return result, nil
}

func (m *ManifestLoader) loadFromDirectory(dir string) ([]byte, error) {
	var result []byte
	
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".yaml") || 
		    strings.HasSuffix(info.Name(), ".yml") || 
		    strings.HasSuffix(info.Name(), ".json")) {
			
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				result = append(result, data...)
				result = append(result, []byte("\n---\n")...)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: reading %s: %v\n", path, readErr)
			}
		}
		
		return nil
	})
	
	if len(result) == 0 {
		return []byte{}, fmt.Errorf("no manifest files found in %q", dir)
	}
	
	return result, nil
}

// ============================================================================
// YAML/JSON Parsing Helpers
// ============================================================================

type K8sManifest struct {
	Items []K8sObject `json:"items"`
}

type K8sObject struct {
	Metadata k8sMetadata   `json:"metadata,omitempty"`
	Spec     interface{}   `json:"spec,omitempty"`
}

type k8sMetadata struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// ============================================================================
// Pod Security Validator - Core Logic
// ============================================================================

func (p *PodValidator) Validate(manifest []byte, pssLevel string) PSSReport {
	var report PSSReport
	
	report.Version = "1.0.0"
	report.PSSLevel = pssLevel
	report.Source = "-" // Will be updated by caller if needed
	
	// Parse manifests
	parsed := parseManifests(manifest)
	
	totalPods := 0
	totalContainers := 0
	var violations []PSSViolation
	
	for _, obj := range parsed {
		if pod, ok := extractPod(obj); ok {
			totalPods++
			
			// Check each container in the pod
			for i, container := range pod.Spec.Containers {
				totalContainers++
				
				violations = append(violations, p.checkContainer(&container, &pod, i)...)
			}
			
			// Check init containers if present
			if len(pod.Spec.InitContainers) > 0 {
				for i, container := range pod.Spec.InitContainers {
					totalContainers++
					violations = append(violations, p.checkContainer(&container, &pod, -1-i)...)
				}
			}
			
			// Check ephemeral containers if present
			if len(pod.Spec.EphemeralContainers) > 0 {
				for i, container := range pod.Spec.EphemeralContainers {
					totalContainers++
					violations = append(violations, p.checkContainer(&container, &pod, -1-i-len(pod.Spec.InitContainers))...)
				}
			}
		}
	}
	
	// Sort violations by severity and then by message for consistent output
	sort.Slice(violations, func(i, j int) bool {
		severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		if severityOrder[violation[i].Severity] < severityOrder[violation[j].Severity] {
			return true
		}
		return violation[i].Message < violation[j].Message
	})
	
	report.TotalPods = totalPods
	report.TotalContainers = totalContainers
	report.Violations = violations
	
	// Calculate summary statistics
	criticalCount, highCount, mediumCount := 0, 0, 0
	totalViolations := len(violations)
	
	for _, v := range violations {
		switch v.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}
	
	report.Summary = PSSSummary{
		CriticalCount: criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		TotalViolations: totalViolations,
		Score:         calculateScore(totalContainers, violations),
	}
	
	return report
}

func (p *PodValidator) checkContainer(container *K8sContainer, pod *K8sObject, containerIndex int) []PSSViolation {
	var violations []PSSViolation
	
	name := container.Name
	if name == "" {
		name = fmt.Sprintf("container-%d", containerIndex)
	}
	
	namespace := ""
	if obj, ok := pod.(map[string]interface{}); ok {
		if meta, ok := obj["metadata"].(map[string]interface{}); ok {
			if ns, ok := meta["namespace"].(string); ok && ns != "" {
				namespace = ns
			}
		}
	}
	
	// PRIV-001: Check privileged flag
	if container.Privileged {
		violations = append(violations, PSSViolation{
			RuleID:    "PRIV-001",
			Level:     p.PSSLevel,
			Category:  "privileged",
			Severity:  "critical",
			Message:   fmt.Sprintf("Container %q runs as privileged", name),
			Suggestion: "Set securityContext.privileged to false or remove the flag",
		})
	}
	
	// PRIV-002: Check hostNetwork
	if container.HostNetwork {
		violations = append(violations, PSSViolation{
			RuleID:    "PRIV-002",
			Level:     p.PSSLevel,
			Category:  "privileged",
			Severity:  "high",
			Message:   fmt.Sprintf("Container %q requests host network namespace", name),
			Suggestion: "Set securityContext.hostNetwork to false or use NetworkPolicy for isolation",
		})
	}
	
	// PRIV-003: Check hostPID
	if container.HostPID {
		violations = append(violations, PSSViolation{
			RuleID:    "PRIV-003",
			Level:     p.PSSLevel,
			Category:  "privileged",
			Severity:  "high",
			Message:   fmt.Sprintf("Container %q shares host PID namespace", name),
			Suggestion: "Set securityContext.hostPID to false",
		})
	}
	
	// PRIV-004: Check hostIPC
	if container.HostIPC {
		violations = append(violations, PSSViolation{
			RuleID:    "PRIV-004",
			Level:     p.PSSLevel,
			Category:  "privileged",
			Severity:  "medium",
			Message:   fmt.Sprintf("Container %q shares host IPC namespace", name),
			Suggestion: "Set securityContext.hostIPC to false",
		})
	}
	
	// PRIV-005 & PRIV-006: Check capabilities
	if container.SecurityContext != nil {
		caps := container.SecurityContext.Capabilities
		
		// Check for added capabilities
		addedCaps := caps.Added
		if len(addedCaps) > 0 {
			violations = append(violations, PSSViolation{
				RuleID:    "PRIV-005",
				Level:     p.PSSLevel,
				Category:  "capabilities",
				Severity:  "high",
				Message:   fmt.Sprintf("Container %q adds Linux capabilities: %v", name, addedCaps),
				Suggestion: "Drop all capabilities and add only required ones using securityContext.capabilities.drop=[\"ALL\"]",
			})
			
			// Check specifically for SYS_ADMIN which is very powerful
			for _, cap := range addedCaps {
				if strings.ToUpper(cap) == "SYS_ADMIN" || strings.ToUpper(cap) == "CAP_SYS_ADMIN" {
					violations = append(violations, PSSViolation{
						RuleID:    "PRIV-006",
						Level:     p.PSSLevel,
						Category:  "capabilities",
						Severity:  "critical",
						Message:   fmt.Sprintf("Container %q requests CAP_SYS_ADMIN capability", name),
						Suggestion: "CAP_SYS_ADMIN grants near-root privileges. Use a more specific capability if possible.",
					})
				}
			}
		}
		
		// Check for dropped capabilities (good practice)
		droppedCaps := caps.Dropped
		if len(droppedCaps) == 0 {
			violations = append(violations, PSSViolation{
				RuleID:    "PRIV-011",
				Level:     p.PSSLevel,
				Category:  "capabilities",
				Severity:  "medium",
				Message:   fmt.Sprintf("Container %q does not drop all capabilities", name),
				Suggestion: "Add securityContext.capabilities.drop=[\"ALL\"] and then add only required ones",
			})
		}
	}
	
	// PRIV-007: Check running as root
	if container.SecurityContext != nil {
		runAsUser := container.SecurityContext.RunAsNonRoot
		
		if runAsUser == nil || !*runAsUser {
			// Assume root if not explicitly set to non-root
			violations = append(violations, PSSViolation{
				RuleID:    "PRIV-007",
				Level:     p.PSSLevel,
				Category:  "privileged",
				Severity:  "critical",
				Message:   fmt.Sprintf("Container %q may run as root user (non-root not enforced)", name),
				Suggestion: "Set securityContext.runAsNonRoot to true and specify a non-zero runAsUser",
			})
		} else if container.SecurityContext.RunAsUser == nil || *container.SecurityContext.RunAsUser == 0 {
			violations = append(violations, PSSViolation{
				RuleID:    "PRIV-007",
				Level:     p.PSSLevel,
				Category:  "privileged",
				Severity:  "critical",
				Message:   fmt.Sprintf("Container %q runs as root user (UID 0)", name),
				Suggestion: "Set securityContext.runAsNonRoot to true and specify a non-zero runAsUser",
			})
		}
	}
	
	// PRIV-008: Check writable root filesystem
	if container.SecurityContext != nil {
		readOnly := container.SecurityContext.ReadOnlyRootFilesystem
		
		if readOnly == nil || !*readOnly {
			violations = append(violations, PSSViolation{
				RuleID:    "PRIV-008",
				Level:     p.PSSLevel,
				Category:  "filesystem",
				Severity:  "medium",
				Message:   fmt.Sprintf("Container %q has writable root filesystem", name),
				Suggestion: "Set securityContext.readOnlyRootFilesystem to true and use tmpfs for runtime needs",
			})
		}
	}
	
	// PRIV-009: Check AllowPrivilegeEscalation
	if container.SecurityContext != nil {
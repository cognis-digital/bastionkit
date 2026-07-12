use k8s_openapi::doc::k8s::api::networking_v1::{PolicyTypes, PolicyWithPeer};
use k8s_openapi::doc::k8s::api::core::Pod;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, BTreeMap};
use std::fs;

/// Represents a parsed Kubernetes manifest entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ManifestEntry {
    pub kind: String,
    pub api_version: String,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(default)]
    pub spec: Option<NetworkPolicySpec>,
}

/// Generic metadata for any Kubernetes resource.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

/// NetworkPolicy specification for analysis.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicySpec {
    #[serde(default)]
    pub pod_selector: Selector,
    #[serde(default)]
    pub ingress: Vec<Rule>,
    #[serde(default)]
    pub egress: Vec<Rule>,
}

/// Selector for matching pods.
#[derive(Debug, Clone, Deserialize)]
pub struct Selector {
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<MatchExpression>,
}

/// Match expression for label-based selection.
#[derive(Debug, Clone, Deserialize)]
pub struct MatchExpression {
    pub key: String,
    pub operator: Operator,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    In, NotIn, Exists, DoesNotExist, Gt, Lt, Gte, Lte,
}

/// A single NetworkPolicy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub from: Vec<Peer>,
    #[serde(default)]
    pub to: Vec<Peer>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub policy_types: Vec<PolicyTypes>,
}

/// Peer specification for ingress/egress rules.
#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    #[serde(default)]
    pub pod_selector: Selector,
    #[serde(default)]
    pub namespace_selector: Selector,
    #[serde(default)]
    pub ip_block: Option<IpBlock>,
}

/// IP block for CIDR-based peer matching.
#[derive(Debug, Clone, Deserialize)]
pub struct IpBlock {
    pub cidr: String,
    #[serde(default)]
    pub except: Vec<String>,
}

/// Port specification for traffic rules.
#[derive(Debug, Clone, Deserialize)]
pub struct Port {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp, Udp, Sctp, All,
}

/// Analysis result for a single namespace.
#[derive(Debug, Clone, Default)]
pub struct NamespaceAnalysis {
    pub name: String,
    pub pod_count: usize,
    pub policy_count: usize,
    pub ingress_rules: Vec<Rule>,
    pub egress_rules: Vec<Rule>,
    pub uncovered_services: Vec<String>,
    pub overly_permissive: Vec<OverlyPermissiveRule>,
}

/// A rule that is too permissive.
#[derive(Debug, Clone)]
pub struct OverlyPermissiveRule {
    pub namespace: String,
    pub policy_name: String,
    pub rule_index: usize,
    pub reason: String,
    pub recommendation: String,
}

/// Full analysis result for the cluster.
#[derive(Debug, Clone, Default)]
pub struct ClusterAnalysis {
    pub namespaces: BTreeMap<String, NamespaceAnalysis>,
    pub total_pods: usize,
    pub total_policies: usize,
    pub all_overly_permissive: Vec<OverlyPermissiveRule>,
    pub uncovered_services: HashSet<String>,
}

/// Configuration for the analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Namespaces to analyze (None = all).
    pub namespaces: Option<Vec<String>>,
    /// Pod labels that indicate critical services.
    pub critical_service_labels: Vec<String>,
    /// Default ports to expect for common services.
    pub default_ports: BTreeMap<u16, String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        let mut ports = BTreeMap::new();
        ports.insert(443, "https".to_string());
        ports.insert(80, "http".to_string());
        ports.insert(53, "dns".to_string());
        ports.insert(6443, "kubernetes-api".to_string());
        ports.insert(2379, "etcd-client".to_string());
        ports.insert(10250, "kubelet-apiserver".to_string());

        Self {
            namespaces: None,
            critical_service_labels: vec![
                "app.kubernetes.io/name=coredns".to_string(),
                "app.kubernetes.io/name=pause".to_string(),
                "app.kubernetes.io/name=kube-proxy".to_string(),
                "app.kubernetes.io/name=kube-dns".to_string(),
            ],
            default_ports: ports,
        }
    }
}

/// Main analyzer struct.
pub struct NetworkPolicyAnalyzer {
    config: AnalyzerConfig,
    manifests: Vec<ManifestEntry>,
}

impl NetworkPolicyAnalyzer {
    /// Create a new analyzer with the given configuration.
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            manifests: Vec::new(),
        }
    }

    /// Load manifests from files or stdin.
    pub fn load_from_files<P: AsRef<std::path::Path>>(
        &mut self,
        paths: &[P],
    ) -> Result<(), std::io::Error> {
        for path in paths {
            let content = fs::read_to_string(path.as_ref())?;
            if !content.trim().is_empty() {
                let entries: Vec<ManifestEntry> = serde_yaml::from_str(&content)?;
                self.manifests.extend(entries);
            }
        }
        Ok(())
    }

    /// Load a single manifest string.
    pub fn load_from_string(&mut self, content: &str) -> Result<(), serde_yaml::Error> {
        if !content.trim().is_empty() {
            let entries: Vec<ManifestEntry> = serde_yaml::from_str(content)?;
            self.manifests.extend(entries);
        }
        Ok(())
    }

    /// Analyze all loaded manifests.
    pub fn analyze(&mut self) -> ClusterAnalysis {
        let mut result = ClusterAnalysis::default();

        // Group by namespace
        let mut ns_map: BTreeMap<String, Vec<ManifestEntry>> = BTreeMap::new();
        
        for entry in &self.manifests {
            if entry.kind == "NetworkPolicy" {
                if let Some(spec) = &entry.spec {
                    let ns = entry.metadata.namespace.clone().or_else(|| {
                        self.config.namespaces.as_ref()
                            .and_then(|ns| ns.first().cloned())
                            .unwrap_or_default()
                    });
                    
                    match ns_map.entry(ns.clone()) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            e.get_mut().push(entry.clone());
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            let mut vec = Vec::new();
                            vec.push(entry.clone());
                            e.insert(vec);
                        }
                    }
                }
            }
        }

        // Analyze each namespace
        for (ns_name, policies) in ns_map {
            let analysis = self.analyze_namespace(&ns_name, &policies);
            result.namespaces.insert(ns_name.clone(), analysis);
        }

        // Aggregate results
        result.total_pods = result.namespaces.values()
            .map(|n| n.pod_count)
            .sum();
        
        result.total_policies = result.namespaces.values()
            .map(|n| n.policy_count)
            .sum();

        result.all_overly_permissive = result.namespaces
            .values()
            .flat_map(|n| &n.overly_permissive)
            .cloned()
            .collect();

        result.uncovered_services = result.namespaces
            .values()
            .map(|n| &n.uncovered_services)
            .flatten()
            .cloned()
            .collect();

        result
    }

    /// Analyze a single namespace.
    fn analyze_namespace(
        &self,
        ns_name: &str,
        policies: &[ManifestEntry],
    ) -> NamespaceAnalysis {
        let mut analysis = NamespaceAnalysis {
            name: ns_name.to_string(),
            pod_count: 0,
            policy_count: policies.len(),
            ingress_rules: Vec::new(),
            egress_rules: Vec::new(),
            uncovered_services: Vec::new(),
            overly_permissive: Vec::new(),
        };

        // Collect all ingress and egress rules
        for entry in policies {
            if let Some(spec) = &entry.spec {
                for rule in &spec.ingress {
                    analysis.ingress_rules.push(rule.clone());
                }
                for rule in &spec.egress {
                    analysis.egress_rules.push(rule.clone());
                }
            }
        }

        // Check for overly permissive rules
        self.check_overly_permissive(&mut analysis, ns_name);

        // Identify uncovered critical services
        self.find_uncovered_services(ns_name, &analysis);

        analysis
    }

    /// Check for overly permissive rules.
    fn check_overly_permissive(
        &self,
        analysis: &mut NamespaceAnalysis,
        ns_name: &str,
    ) {
        // Check ingress rules
        for (idx, rule) in analysis.ingress_rules.iter().enumerate() {
            if let Some(peer_list) = &rule.from {
                for peer in peer_list {
                    // Empty pod_selector means "all pods"
                    if peer.pod_selector.match_labels.is_empty() 
                        && peer.namespace_selector.match_labels.is_empty()
                        && peer.ip_block.is_none() {
                        
                        analysis.overly_permissive.push(OverlyPermissiveRule {
                            namespace: ns_name.to_string(),
                            policy_name: "unknown".to_string(),
                            rule_index: idx,
                            reason: format!(
                                "Ingress rule {} has empty peer selector (matches all pods)",
                                idx + 1
                            ),
                            recommendation: String::from(
                                "Add a specific pod_selector or namespace_selector to limit scope."
                            ),
                        });
                    }

                    // Empty port list means "all ports"
                    if rule.ports.is_empty() {
                        analysis.overly_permissive.push(OverlyPermissiveRule {
                            namespace: ns_name.to_string(),
                            policy_name: "unknown".to_string(),
                            rule_index: idx,
                            reason: format!(
                                "Ingress rule {} has no port restrictions (allows all ports)",
                                idx + 1
                            ),
                            recommendation: String::from(
                                "Add specific port and protocol restrictions."
                            ),
                        });
                    }

                    // PolicyTypes with only Allow means less restrictive
                    if rule.policy_types.contains(&PolicyTypes::Allow) 
                       && !rule.policy_types.contains(&PolicyTypes::Drop) {
                        
                        analysis.overly_permissive.push(OverlyPermissiveRule {
                            namespace: ns_name.to_string(),
                            policy_name: "unknown".to_string(),
                            rule_index: idx,
                            reason: format!(
                                "Ingress rule {} uses Allow type (less restrictive than Drop)",
                                idx + 1
                            ),
                            recommendation: String::from(
                                "Consider using Drop as default and Add specific Allow rules."
                            ),
                        });
                    }
                }
            }
        }

        // Check egress rules similarly
        for (idx, rule) in analysis.egress_rules.iter().enumerate() {
            if let Some(peer_list) = &rule.to {
                for peer in peer_list {
                    if peer.pod_selector.match_labels.is_empty() 
                        && peer.namespace_selector.match_labels.is_empty()
                        && peer.ip_block.is_none() {
                        
                        analysis.overly_permissive.push(OverlyPermissiveRule {
                            namespace: ns_name.to_string(),
                            policy_name: "unknown".to_string(),
                            rule_index: idx,
                            reason: format!(
                                "Egress rule {} has empty peer selector (matches all pods)",
                                idx + 1
                            ),
                            recommendation: String::from(
                                "Add a specific pod_selector or namespace_selector to limit scope."
                            ),
                        });
                    }

                    if rule.ports.is_empty() {
                        analysis.overly_permissive.push(OverlyPermissiveRule {
                            namespace: ns_name.to_string(),
                            policy_name: "unknown".to_string(),
                            rule_index: idx,
                            reason: format!(
                                "Egress rule {} has no port restrictions (allows all ports)",
                                idx + 1
                            ),
                            recommendation: String::from(
                                "Add specific port and protocol restrictions."
                            ),
                        });
                    }
                }
            }
        }

        // Check for rules with empty policy_types (defaults to Allow)
        let mut seen = HashSet::new();
        for rule in analysis.ingress_rules.iter() {
            if !rule.policy_types.is_empty() 
               && !seen.contains(&format!(
                   "{:?}", 
                   std::mem::discriminant(&rule.policy_types[0])
                )) {
                seen.insert(format!(
                    "{:?}", 
                    std::mem::discriminant(&rule.policy_types[0])
                ));
            } else if rule.policy_types.is_empty() {
                analysis.overly_permissive.push(OverlyPermissiveRule {
                    namespace: ns_name.to_string(),
                    policy_name: "unknown".to_string(),
                    rule_index: 0,
                    reason: format!(
                        "Ingress rule has empty policy_types (defaults to Allow)",
                    ),
                    recommendation: String::from(
                        "Explicitly specify PolicyTypes::Drop or PolicyTypes::Allow."
                    ),
                });
            }
        }

        for rule in analysis.egress_rules.iter() {
            if !rule.policy_types.is_empty() 
               && !seen.contains(&format!(
                   "{:?}", 
                   std::mem::discriminant(&rule.policy_types[0])
                )) {
                seen.insert(format!(
                    "{:?}", 
                    std::mem::discriminant(&rule.policy_types[0])
                ));
            } else if rule.policy_types.is_empty() {
                analysis.overly_permissive.push(OverlyPermissiveRule {
                    namespace: ns_name.to_string(),
                    policy_name: "unknown".to_string(),
                    rule_index: 0,
                    reason: format!(
                        "Egress rule has empty policy_types (defaults to Allow)",
                    ),
                    recommendation: String::from(
                        "Explicitly specify PolicyTypes::Drop or PolicyTypes::Allow."
                    ),
                });
            }
        }

        // Remove duplicates while preserving order
        analysis.overly_permissive.sort_by(|a, b| {
            (a.namespace.as_str(), a.rule_index)
                .cmp(&(b.namespace.as_str(), b.rule_index))
        });
        analysis.overly_permissive.dedup();
    }

    /// Find services that lack proper network coverage.
    fn find_uncovered_services(
        &self,
        ns_name: &str,
        analysis: &NamespaceAnalysis,
    ) {
        // Build a set of all allowed source IPs/ports from ingress rules
        let mut allowed_sources: HashSet<String> = HashSet::new();

        for rule in &analysis.ingress_rules {
            if let Some(peer_list) = &rule.from {
                for peer in peer_list {
                    if let Some(ip_block) = &peer.ip_block {
                        // Add CIDR blocks (excluding exceptions)
                        for cidr in ip_block.except.iter().filter(|c| !c.is_empty()) {
                            allowed_sources.insert(format!("EXCEPT:{}", cidr));
                        }
                        if !ip_block.cidr.is_empty() {
                            allowed_sources.insert(ip_block.cidr.clone());
                        }
                    }

                    // If pod_selector is empty, this rule matches all pods in namespace
                    if peer.pod_selector.match_labels.is_empty() 
                       && peer.namespace_selector.match_labels.is_empty() {
                        // This rule applies
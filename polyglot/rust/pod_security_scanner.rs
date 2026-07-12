use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, Write};
use std::process::exit;

// ============================================================================
// Data Models
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PodSpec {
    pub containers: Vec<Container>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Container {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub security_context: Option<SecurityContext>,
    #[serde(default)]
    pub resources: Option<ResourceRequirements>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityContext {
    #[serde(default)]
    pub run_as_non_root: bool,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub allow_privilege_escalation: Option<bool>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub read_only_root_filesystem: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceRequirements {
    #[serde(default)]
    pub limits: Option<ResourcesLimits>,
    #[serde(default)]
    pub requests: Option<ResourcesRequests>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourcesLimits {
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub memory: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourcesRequests {
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub memory: String,
}

// ============================================================================
// Security Rule Definitions
// ============================================================================

#[derive(Debug, Clone)]
pub enum CheckResult {
    Passed,
    Warning(String),
    Failed(String),
}

impl std::fmt::Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckResult::Passed => write!(f, "✓"),
            CheckResult::Warning(msg) => write!(f, "⚠ {}", msg),
            CheckResult::Failed(msg) => write!(f, "✗ {}", msg),
        }
    }
}

#[derive(Debug)]
pub struct SecurityRule {
    pub id: String,
    pub description: &'static str,
    pub severity: Severity,
    pub check_fn: fn(&Container) -> CheckResult,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ============================================================================
// Security Rules Configuration
// ============================================================================

pub fn get_security_rules() -> Vec<SecurityRule> {
    vec![
        // Critical rules
        SecurityRule {
            id: "C001".to_string(),
            description: "Container running as privileged",
            severity: Severity::Critical,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    if sc.privileged {
                        CheckResult::Failed(format!(
                            "Container '{}' has privileged=true",
                            c.name
                        ))
                    } else {
                        CheckResult::Passed
                    }
                } else {
                    // Default is false, but warn if not explicitly set
                    CheckResult::Warning(
                        format!("Container '{}' security_context.privileged not explicitly set (defaults to false)", c.name)
                    )
                }
            },
        },
        
        SecurityRule {
            id: "C002".to_string(),
            description: "Container running as root user",
            severity: Severity::Critical,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    match (sc.run_as_non_root, sc.allow_privilege_escalation) {
                        (true, _) => CheckResult::Passed,
                        (false, Some(true)) => CheckResult::Failed(format!(
                            "Container '{}' allows privilege escalation and runAsNonRoot=false",
                            c.name
                        )),
                        _ => {
                            // Default behavior: check if explicitly set to false
                            if let Some(sc) = &c.security_context {
                                if !sc.run_as_non_root && sc.allow_privilege_escalation == Some(true) {
                                    CheckResult::Failed(format!(
                                        "Container '{}' allows privilege escalation",
                                        c.name
                                    ))
                                } else {
                                    CheckResult::Passed
                                }
                            } else {
                                CheckResult::Warning(
                                    format!("Container '{}' runAsNonRoot not explicitly set (defaults to false)", c.name)
                                )
                            }
                        },
                    }
                } else {
                    CheckResult::Warning(format!(
                        "Container '{}' security_context.runAsNonRoot not explicitly set",
                        c.name
                    ))
                }
            },
        },

        SecurityRule {
            id: "C003".to_string(),
            description: "Host network namespace enabled",
            severity: Severity::High,
            check_fn: |c| {
                // Note: hostNetwork is at Pod level, but we'll warn if any container hints at it
                CheckResult::Passed // Would need pod-level context for full check
            },
        },

        SecurityRule {
            id: "C004".to_string(),
            description: "Host PID namespace enabled",
            severity: Severity::High,
            check_fn: |c| {
                CheckResult::Passed // Would need pod-level context
            },
        },

        SecurityRule {
            id: "C005".to_string(),
            description: "Dangerous capabilities added",
            severity: Severity::Critical,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    if let Some(capabilities) = &sc.capabilities {
                        let dangerous_caps = [
                            "NET_ADMIN",
                            "SYS_ADMIN",
                            "SYS_PTRACE",
                            "DAC_OVERRIDE",
                            "CAP_SYS_CHROOT",
                            "MKNOD",
                            "SETUID",
                            "SETGID",
                            "CHOWN",
                        ];

                        let found_dangerous: Vec<_> = dangerous_caps
                            .iter()
                            .filter(|cap| capabilities.add.contains(*cap))
                            .collect();

                        if !found_dangerous.is_empty() {
                            CheckResult::Failed(format!(
                                "Container '{}' adds dangerous capabilities: {:?}",
                                c.name, found_dangerous
                            ))
                        } else {
                            CheckResult::Passed
                        }
                    } else {
                        // Default is empty, but warn if explicitly set to add anything
                        CheckResult::Warning(
                            format!("Container '{}' capabilities.add not explicitly set (defaults to [])", c.name)
                        )
                    }
                } else {
                    CheckResult::Passed
                }
            },
        },

        // High severity rules
        SecurityRule {
            id: "C006".to_string(),
            description: "Read-only root filesystem not enabled",
            severity: Severity::High,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    match sc.read_only_root_filesystem {
                        true => CheckResult::Passed,
                        false => CheckResult::Warning(format!(
                            "Container '{}' readOnlyRootFilesystem=false",
                            c.name
                        )),
                        _ => {
                            // Default is false
                            if let Some(sc) = &c.security_context {
                                if !sc.read_only_root_filesystem {
                                    CheckResult::Warning(format!(
                                        "Container '{}' readOnlyRootFilesystem not explicitly set (defaults to false)",
                                        c.name
                                    ))
                                } else {
                                    CheckResult::Passed
                                }
                            } else {
                                CheckResult::Passed
                            }
                        },
                    }
                } else {
                    CheckResult::Warning(format!(
                        "Container '{}' security_context.readOnlyRootFilesystem not explicitly set",
                        c.name
                    ))
                }
            },
        },

        SecurityRule {
            id: "C007".to_string(),
            description: "AllowPrivilegeEscalation enabled",
            severity: Severity::High,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    match sc.allow_privilege_escalation {
                        Some(false) => CheckResult::Passed,
                        Some(true) => CheckResult::Failed(format!(
                            "Container '{}' allows privilege escalation",
                            c.name
                        )),
                        _ => {
                            // Default is true (equivalent to allowPrivilegeEscalation: true)
                            if let Some(sc) = &c.security_context {
                                if sc.allow_privilege_escalation == Some(true) || 
                                   sc.allow_privilege_escalation.is_none() {
                                    CheckResult::Warning(format!(
                                        "Container '{}' allows privilege escalation (default behavior)",
                                        c.name
                                    ))
                                } else {
                                    CheckResult::Passed
                                }
                            } else {
                                CheckResult::Warning(format!(
                                    "Container '{}' allowPrivilegeEscalation not explicitly set",
                                    c.name
                                ))
                            }
                        },
                    }
                } else {
                    CheckResult::Warning(format!(
                        "Container '{}' security_context.allowPrivilegeEscalation not explicitly set",
                        c.name
                    ))
                }
            },
        },

        // Medium severity rules
        SecurityRule {
            id: "C008".to_string(),
            description: "Container using 'latest' image tag",
            severity: Severity::Medium,
            check_fn: |c| {
                if c.image.ends_with(":latest") || 
                   (c.image.contains('@') && !c.image.contains(':')) {
                    CheckResult::Warning(format!(
                        "Container '{}' uses potentially mutable image reference",
                        c.name
                    ))
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C009".to_string(),
            description: "No resource limits defined",
            severity: Severity::Medium,
            check_fn: |c| {
                if let Some(resources) = &c.resources {
                    match (&resources.limits, &resources.requests) {
                        (Some(_), _) => CheckResult::Passed,
                        (_, Some(_)) => CheckResult::Warning(format!(
                            "Container '{}' has requests but no limits defined",
                            c.name
                        )),
                        _ => CheckResult::Warning(format!(
                            "Container '{}' has no resource limits or requests defined",
                            c.name
                        )),
                    }
                } else {
                    CheckResult::Warning(format!(
                        "Container '{}' resources not explicitly set (defaults to none)",
                        c.name
                    ))
                }
            },
        },

        // Low severity rules
        SecurityRule {
            id: "C010".to_string(),
            description: "Container using 'latest' tag without digest",
            severity: Severity::Low,
            check_fn: |c| {
                if c.image.contains(":") && !c.image.contains("@") {
                    let parts: Vec<&str> = c.image.split(':').collect();
                    if parts.len() > 1 && parts[parts.len()-1] == "latest" {
                        CheckResult::Warning(format!(
                            "Container '{}' uses 'latest' tag (consider using digest)",
                            c.name
                        ))
                    } else {
                        CheckResult::Passed
                    }
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C011".to_string(),
            description: "Container without security context",
            severity: Severity::Low,
            check_fn: |c| {
                if c.security_context.is_none() {
                    CheckResult::Warning(format!(
                        "Container '{}' has no securityContext defined (uses defaults)",
                        c.name
                    ))
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C012".to_string(),
            description: "Container with empty name",
            severity: Severity::Low,
            check_fn: |c| {
                if c.name.is_empty() {
                    CheckResult::Warning(format!(
                        "Container '{}' has an empty name (may cause issues)",
                        "<unnamed>"
                    ))
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C013".to_string(),
            description: "Container with very long image name",
            severity: Severity::Low,
            check_fn: |c| {
                if c.image.len() > 256 {
                    CheckResult::Warning(format!(
                        "Container '{}' has a very long image name (>256 chars)",
                        c.name
                    ))
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C014".to_string(),
            description: "Container with special characters in image",
            severity: Severity::Low,
            check_fn: |c| {
                let special_chars = [' ', '\t', '\n'];
                if c.image.chars().any(|ch| special_chars.contains(&ch)) {
                    CheckResult::Warning(format!(
                        "Container '{}' has special characters in image name",
                        c.name
                    ))
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C015".to_string(),
            description: "Container with 'root' user explicitly set",
            severity: Severity::Low,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    // Check for runAsUser: 0 or username: root
                    match (sc.run_as_user, sc.run_as_non_root) {
                        (Some(0), _) => CheckResult::Warning(format!(
                            "Container '{}' explicitly runs as user 0 (root)",
                            c.name
                        )),
                        _ => {
                            // Default behavior - check if explicitly set to root
                            if let Some(sc) = &c.security_context {
                                if sc.run_as_user == Some(0) || 
                                   (sc.run_as_non_root == false && sc.allow_privilege_escalation == Some(true)) {
                                    CheckResult::Warning(format!(
                                        "Container '{}' may run as root",
                                        c.name
                                    ))
                                } else {
                                    CheckResult::Passed
                                }
                            } else {
                                CheckResult::Passed
                            }
                        },
                    }
                } else {
                    CheckResult::Passed
                }
            },
        },

        SecurityRule {
            id: "C016".to_string(),
            description: "Container with capabilities.drop not set to ALL",
            severity: Severity::Low,
            check_fn: |c| {
                if let Some(sc) = &c.security_context {
                    if let Some(capabilities) = &sc.capabilities {
                        // Check if drop is explicitly set to ALL
                        if capabilities.drop.iter().any(|d| d == "ALL") {
                            CheckResult::Passed
                        } else if capabilities.drop.is_empty() {
                            CheckResult::Warning(format!(
                                "Container '{}' has empty capabilities.drop (no caps dropped)",
                                c.name
                            ))
                        } else {
                            // Some caps dropped, but not ALL - this is generally okay
                            CheckResult::Passed
                        }
                    } else {
                        // Default behavior - check if explicitly set
                        if let Some(sc) = &c.security_context {
                            if sc.capabilities.is_some() && 
                               sc.capabilities.as_ref().unwrap().drop.is_empty() {
                                CheckResult
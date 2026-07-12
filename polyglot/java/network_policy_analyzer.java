package com.bastionkit.java.network_policy_analyzer;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Network Policy Analyzer for BastionKit.
 * 
 * Analyzes Kubernetes NetworkPolicy resources and generates hardened security baselines
 * specifically designed for air-gapped, regulated environments.
 */
public class NetworkPolicyAnalyzer {

    // ============================================================================
    // Data Models - Immutable Records
    // ============================================================================

    /** Represents a parsed NetworkPolicy resource from K8s API */
    public record NetworkPolicy(
        String name,
        String namespace,
        String podSelector,
        List<Rule> ingressRules,
        List<Rule> egressRules,
        boolean isDefaultDeny,
        long creationTimestamp,
        Map<String, Object> labels
    ) {

        public static NetworkPolicy fromMap(Map<String, Object> map) {
            return new NetworkPolicy(
                (String) map.get("name"),
                (String) map.getOrDefault("namespace", "default"),
                (String) map.getOrDefault("podSelector", ""),
                extractRules(map, "ingress"),
                extractRules(map, "egress"),
                Boolean.TRUE.equals(map.get("isDefaultDeny")),
                System.currentTimeMillis(),
                (Map<String, Object>) map.getOrDefault("labels", Collections.emptyMap())
            );
        }

        private static List<Rule> extractRules(Map<String, Object> map, String type) {
            return Optional.ofNullable(map.get(type))
                    .map(list -> ((List<Map<String, Object>>) list).stream()
                            .map(NetworkPolicyAnalyzer::ruleFromMap)
                            .collect(Collectors.toList()))
                    .orElse(Collections.emptyList());
        }

        private static Rule ruleFromMap(Map<String, Object> map) {
            return new Rule(
                (String) map.getOrDefault("from", ""),
                (List<Map<String, String>>) map.getOrDefault("ports", Collections.emptyList()),
                (String) map.getOrDefault("to", ""),
                (String) map.getOrDefault("action", "Allow"),
                (Long) map.getOrDefault("protocol", -1L),
                (Integer) map.getOrDefault("port", 0)
            );
        }

        public static NetworkPolicy defaultDenyAll(String namespace, String podSelector) {
            return new NetworkPolicy(
                "default-deny-all",
                namespace,
                podSelector,
                Collections.emptyList(),
                Collections.emptyList(),
                true,
                0L,
                Map.of("bastionkit", "auto-generated")
            );
        }

        public static NetworkPolicy defaultDenyIngress(String namespace) {
            return new NetworkPolicy(
                "default-deny-ingress",
                namespace,
                "",
                Collections.emptyList(),
                Collections.emptyList(),
                true,
                0L,
                Map.of("bastionkit", "auto-generated")
            );
        }

        public static NetworkPolicy defaultDenyEgress(String namespace) {
            return new NetworkPolicy(
                "default-deny-egress",
                namespace,
                "",
                Collections.emptyList(),
                Collections.emptyList(),
                true,
                0L,
                Map.of("bastionkit", "auto-generated")
            );
        }
    }

    /** Represents a single NetworkPolicy rule */
    public record Rule(
        String from,           // Source selector or CIDR block
        List<Port> ports,      // Port specifications
        String to,             // Destination (usually empty for ingress/egress)
        String action,         // Allow/Deny
        long protocol,         // 0=TCP, 1=UDP, -1=All
        int port               // Port number or 0 for all
    ) {

        public static Rule allowFrom(String source, List<Port> ports, long protocol) {
            return new Rule(source, ports, "", "Allow", protocol, 0);
        }

        public static Rule denyFrom(String source, List<Port> ports, long protocol) {
            return new Rule(source, ports, "", "Deny", protocol, 0);
        }
    }

    /** Port specification */
    public record Port(int port, String name, String protocol) {}

    // ============================================================================
    // Security Baseline Constants
    // ============================================================================

    private static final long DEFAULT_DENY_PRIORITY = 100L;
    private static final int MAX_PERMISSIVE_SCORE = 50;
    private static final double CRITICAL_THRESHOLD = 3.0;
    private static final double WARNING_THRESHOLD = 2.0;

    // ============================================================================
    // Analyzer Engine - Core Analysis Logic
    // ============================================================================

    public record AnalysisResult(
        int totalPolicies,
        int defaultDenyCount,
        int permissiveRuleCount,
        int conflictCount,
        double securityScore,
        List<Finding> findings,
        List<Recommendation> recommendations,
        Map<String, NetworkPolicy> generatedBaselines
    ) {

        public static AnalysisResult empty() {
            return new AnalysisResult(0, 0, 0, 0, 1.0, Collections.emptyList(), 
                    Collections.emptyList(), Collections.emptyMap());
        }

        public static AnalysisResult fromPolicies(List<NetworkPolicy> policies) {
            if (policies == null || policies.isEmpty()) {
                return empty();
            }

            AnalyzerEngine engine = new AnalyzerEngine();
            return engine.analyze(policies);
        }

        public String toReport() {
            StringBuilder sb = new StringBuilder();
            
            sb.append("=== NETWORK POLICY ANALYSIS REPORT ===\n");
            sb.append(String.format("Total Policies: %d\n", totalPolicies));
            sb.append(String.format("Default Deny Count: %d\n", defaultDenyCount));
            sb.append(String.format("Permissive Rules Found: %d\n", permissiveRuleCount));
            sb.append(String.format("Conflicts Detected: %d\n", conflictCount));
            sb.append(String.format("Security Score: %.1f/5.0\n", securityScore));
            
            if (!findings.isEmpty()) {
                sb.append("\n--- FINDINGS ---\n");
                for (Finding f : findings) {
                    sb.append(f).append('\n');
                }
            }

            if (!recommendations.isEmpty()) {
                sb.append("\n--- RECOMMENDATIONS ---\n");
                for (Recommendation r : recommendations) {
                    sb.append(r).append('\n');
                }
            }

            return sb.toString();
        }
    }

    // ============================================================================
    // AnalyzerEngine - Main Analysis Logic
    // ============================================================================

    private static class AnalyzerEngine {

        /**
         * Analyzes a list of NetworkPolicy resources.
         * Returns comprehensive analysis results with findings and recommendations.
         */
        public AnalysisResult analyze(List<NetworkPolicy> policies) {
            List<Finding> findings = new ArrayList<>();
            List<Recommendation> recommendations = new ArrayList<>();
            
            int defaultDenyCount = 0;
            int permissiveRuleCount = 0;
            int conflictCount = 0;

            // Phase 1: Count and categorize existing policies
            for (NetworkPolicy policy : policies) {
                if (policy.isDefaultDeny()) {
                    defaultDenyCount++;
                } else {
                    // Check for permissive rules
                    if (hasPermissiveRules(policy)) {
                        permissiveRuleCount++;
                        findings.add(Finding.warning(
                            "Policy '" + policy.name() + "' contains overly permissive rules"
                        ));
                    }

                    // Phase 2: Detect conflicts between policies
                    detectConflicts(policies, policy);
                }
            }

            // Phase 3: Generate hardened baselines for each namespace
            Map<String, NetworkPolicy> generatedBaselines = new LinkedHashMap<>();
            Set<String> namespaces = policies.stream()
                    .map(NetworkPolicy::namespace)
                    .collect(Collectors.toSet());

            for (String ns : namespaces) {
                // Create a secure default-deny-all policy for the namespace
                NetworkPolicy baseline = NetworkPolicy.defaultDenyAll(ns, "");
                
                // Add exception rules based on existing traffic patterns
                List<NetworkPolicy> exceptions = extractTrafficPatterns(policies);
                if (!exceptions.isEmpty()) {
                    findings.add(Finding.info(
                        "Found " + exceptions.size() + " active traffic patterns that may require exceptions"
                    ));
                    
                    // Create exception-aware baseline
                    NetworkPolicy exceptionBaseline = createExceptionAwareBaseline(baseline, ns, exceptions);
                    generatedBaselines.put(ns + "-with-exceptions", exceptionBaseline);
                } else {
                    generatedBaselines.put(ns + "-secure-baseline", baseline);
                }
            }

            // Phase 4: Calculate overall security score
            double score = calculateSecurityScore(
                defaultDenyCount, permissiveRuleCount, conflictCount, policies.size()
            );

            return new AnalysisResult(
                policies.size(),
                defaultDenyCount,
                permissiveRuleCount,
                conflictCount,
                Math.max(0.0, Math.min(5.0, score)),
                findings,
                recommendations,
                generatedBaselines
            );
        }

        /** Checks if a policy has overly permissive rules */
        private boolean hasPermissiveRules(NetworkPolicy policy) {
            // Check ingress for overly permissive sources
            for (Rule rule : policy.ingressRules()) {
                if (isOverlyPermissiveIngress(rule)) {
                    return true;
                }
            }

            // Check egress for overly permissive destinations
            for (Rule rule : policy.egressRules()) {
                if (isOverlyPermissiveEgress(rule)) {
                    return true;
                }
            }

            return false;
        }

        /** Detects conflicts between policies */
        private void detectConflicts(List<NetworkPolicy> allPolicies, NetworkPolicy policy) {
            for (NetworkPolicy other : allPolicies) {
                if (other == policy || !sameNamespace(policy, other)) {
                    continue;
                }

                // Check for conflicting allow/deny pairs
                if (hasConflictingRules(policy, other)) {
                    conflictCount++;
                    findings.add(Finding.warning(
                        "Potential conflict between policies: '" + 
                        policy.name() + "' vs '" + other.name() + "'"
                    ));
                }
            }
        }

        /** Extracts active traffic patterns from existing policies */
        private List<NetworkPolicy> extractTrafficPatterns(List<NetworkPolicy> policies) {
            List<NetworkPolicy> patterns = new ArrayList<>();
            
            for (NetworkPolicy policy : policies) {
                // Look for allow rules that indicate actual traffic needs
                if (!policy.ingressRules().isEmpty() || !policy.egressRules().isEmpty()) {
                    // Filter to only include non-default-deny policies with allows
                    boolean hasAllow = policy.ingressRules().stream()
                            .anyMatch(r -> "Allow".equals(r.action()));
                    
                    if (hasAllow) {
                        patterns.add(policy);
                    }
                }
            }

            return patterns;
        }

        /** Creates a baseline with appropriate exceptions */
        private NetworkPolicy createExceptionAwareBaseline(
                NetworkPolicy base, String namespace, List<NetworkPolicy> exceptions) {
            
            // Start with default-deny-all
            Map<String, Object> labels = new HashMap<>();
            labels.put("bastionkit", "baseline-with-exceptions");
            labels.put("namespace", namespace);

            return new NetworkPolicy(
                base.name() + "-with-exceptions",
                namespace,
                "",
                buildExceptionRules(exceptions),
                buildExceptionRules(exceptions), // Same for egress as baseline
                true,
                0L,
                labels
            );
        }

        /** Builds exception rules from traffic patterns */
        private List<Rule> buildExceptionRules(List<NetworkPolicy> exceptions) {
            List<Rule> result = new ArrayList<>();

            for (NetworkPolicy ep : exceptions) {
                // Extract ingress exceptions
                if (!ep.ingressRules().isEmpty()) {
                    for (Rule rule : ep.ingressRules()) {
                        if ("Allow".equals(rule.action())) {
                            result.add(Rule.allowFrom(rule.from(), rule.ports(), rule.protocol()));
                        }
                    }
                }

                // Extract egress exceptions
                if (!ep.egressRules().isEmpty()) {
                    for (Rule rule : ep.egressRules()) {
                        if ("Allow".equals(rule.action())) {
                            result.add(Rule.allowFrom(rule.from(), rule.ports(), rule.protocol()));
                        }
                    }
                }
            }

            return result;
        }

        /** Calculates overall security score */
        private double calculateSecurityScore(
                int defaultDenyCount, int permissiveCount, 
                int conflictCount, int totalPolicies) {
            
            if (totalPolicies == 0) {
                return 1.0; // No policies = neutral
            }

            double baseScore = 5.0;
            
            // Deduct for missing default-deny
            double denyFactor = defaultDenyCount > 0 ? 1.0 : 0.8;
            
            // Deduct for permissive rules
            double permFactor = Math.max(0, 1.0 - (permissiveCount / (double) totalPolicies * 2));
            
            // Deduct for conflicts
            double conflictFactor = Math.max(0, 1.0 - (conflictCount / (double) totalPolicies));

            return baseScore * denyFactor * permFactor * conflictFactor;
        }

        /** Checks if ingress rule is overly permissive */
        private boolean isOverlyPermissiveIngress(Rule rule) {
            // Allow from 0.0.0.0/0 or empty source
            if (rule.from() == null || rule.from().isEmpty() || 
                rule.from().equals("0.0.0.0/0")) {
                return true;
            }

            // Allow all ports
            if (rule.port() == 0 && rule.protocol() == -1) {
                return true;
            }

            // Allow more than 5 different ports
            if (rule.ports().size() > 5) {
                return true;
            }

            return false;
        }

        /** Checks if egress rule is overly permissive */
        private boolean isOverlyPermissiveEgress(Rule rule) {
            // Allow to 0.0.0.0/0 or empty destination
            if (rule.to() == null || rule.to().isEmpty() || 
                rule.to().equals("0.0.0.0/0")) {
                return true;
            }

            // Allow all ports
            if (rule.port() == 0 && rule.protocol() == -1) {
                return true;
            }

            return false;
        }

        /** Checks if two policies are in the same namespace */
        private boolean sameNamespace(NetworkPolicy a, NetworkPolicy b) {
            return Objects.equals(a.namespace(), b.namespace());
        }

        /** Checks for conflicting rules between policies */
        private boolean hasConflictingRules(NetworkPolicy a, NetworkPolicy b) {
            // Simplified conflict detection: check if one allows what the other denies
            Set<String> allowSources = new HashSet<>();
            
            for (Rule rule : a.ingressRules()) {
                if ("Allow".equals(rule.action())) {
                    allowSources.add(normalizeSource(rule.from()));
                }
            }

            for (Rule rule : b.egressRules()) {
                if ("Deny".equals(rule.action())) {
                    String source = normalizeSource(rule.from());
                    if (allowSources.contains(source)) {
                        return true;
                    }
                }
            }

            return false;
        }

        /** Normalizes a source for comparison */
        private String normalizeSource(String source) {
            if (source == null || source.isEmpty()) {
                return "default";
            }
            
            // Normalize CIDR notation
            if (source.startsWith("0.0.0.0/")) {
                return "any-ipv4";
            }

            return source;
        }
    }

    // ============================================================================
    // Finding and Recommendation Classes
    // ============================================================================

    public enum Severity {
        INFO, WARNING, CRITICAL
    }

    public record Finding(Severity severity, String message) {
        private static final int INFO_LEVEL = 0;
        private static final int WARNING_LEVEL = 1;
        private static final int CRITICAL_LEVEL = 2;

        public static Finding info(String message) {
            return new Finding(INFO, message);
        }

        public static Finding warning(String message
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace bastionkit.polyglot.csharp
{
    // ============================================================================
    // DOMAIN MODELS
    // ============================================================================

    public interface IPolicyDocument
    {
        string? Namespace { get; }
        List<PolicyRule>? IngressRules { get; }
        List<PolicyRule>? EgressRules { get; }
        PolicyPriority Priority { get; }
    }

    public class PolicyRule
    {
        public List<string>? FromPorts { get; set; }
        public List<string>? ToPorts { get; set; }
        public string? Protocol { get; set; } // TCP, UDP, *
        public bool Allow { get; set; } = true;
        public List<string>? Sources { get; set; }
        public List<string>? Destinations { get; set; }
    }

    public enum PolicyPriority : byte
    {
        Critical,
        High,
        Medium,
        Low,
        Info
    }

    // ============================================================================
    // SECURITY BASELINE CONFIGURATION
    // ============================================================================

    public class SecurityBaseline
    {
        public const int DefaultDenyThreshold = 1;
        public const int MaxIngressPortsPerRule = 5;
        public const int MaxEgressRulesPerNamespace = 20;
        public static readonly string[] AllowedProtocols = { "TCP", "UDP", "*", "SCTP" };

        private SecurityBaseline() { }

        public static SecurityBaseline Instance => new();
   

        // ============================================================================
        // CORE ANALYZER INTERFACE
        // ============================================================================

        public interface INetworkPolicyAnalyzer
        {
            AnalysisResult Analyze(IPolicyDocument document);
            void SetBaseline(SecurityBaseline? baseline = null);
        }

        // ============================================================================
        // IMPLEMENTATION: NETWORK POLICY ANALYZER
        // ============================================================================

        public class NetworkPolicyAnalyzer : INetworkPolicyAnalyzer
        {
            private readonly SecurityBaseline _baseline;
            private readonly List<AnalysisFinding> _findings;

            public NetworkPolicyAnalyzer(SecurityBaseline? baseline = null)
            {
                _baseline = baseline ?? SecurityBaseline.Instance;
                _findings = new();
            }

            public AnalysisResult Analyze(IPolicyDocument document)
            {
                var result = new AnalysisResult(document.Namespace);
                result.Document = document;
                result.Score = 100.0;

                // Phase 1: Structural checks
                CheckDefaultDeny(result, document);
                CheckRuleComplexity(result, document);

                // Phase 2: Ingress analysis
                AnalyzeIngressRules(result, document.IngressRules);

                // Phase 3: Egress analysis  
                AnalyzeEgressRules(result, document.EgressRules);

                // Phase 4: Cross-checks and recommendations
                CheckCrossNamespaceTraffic(result, document);

                // Calculate final score
                result.Score = CalculateScore(result);

                return result;
            }

            public void SetBaseline(SecurityBaseline? baseline)
            {
                _baseline = baseline ?? SecurityBaseline.Instance;
            }

        // ============================================================================
        // ANALYSIS LOGIC - PHASE 1: STRUCTURAL CHECKS
        // ============================================================================

        private static void CheckDefaultDeny(AnalysisResult result, IPolicyDocument doc)
        {
            var hasIngressDeny = doc.IngressRules?.Any(r => !r.Allow) ?? false;
            var hasEgressDeny = doc.EgressRules?.Any(r => !r.Allow) ?? false;

            if (!hasIngressDeny && !hasEgressDeny)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Critical,
                    "Missing default deny policy - namespace allows all traffic by default",
                    new[] { "Add 'allow: false' rule at end of both Ingress and Egress sections" },
                    10.0));
            }

            if (hasIngressDeny && hasEgressDeny)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.High,
                    "Default deny policies present - good baseline",
                    new[] { "Verify rules are ordered correctly (deny last)" },
                    5.0));
            }
        }

        private static void CheckRuleComplexity(AnalysisResult result, IPolicyDocument doc)
        {
            if (doc.IngressRules?.Count > _baseline.MaxEgressRulesPerNamespace)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Medium,
                    $"Ingress rule count ({doc.IngressRules.Count}) exceeds threshold ({_baseline.MaxEgressRulesPerNamespace})",
                    new[] { "Consolidate rules using CIDR ranges or port groups" },
                    3.0));
            }

            if (doc.EgressRules?.Count > _baseline.MaxEgressRulesPerNamespace)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Medium,
                    $"Egress rule count ({doc.EgressRules.Count}) exceeds threshold",
                    new[] { "Group egress by service tier or application" },
                    3.0));
            }
        }

        // ============================================================================
        // ANALYSIS LOGIC - PHASE 2: INGRESS ANALYSIS
        // ============================================================================

        private static void AnalyzeIngressRules(AnalysisResult result, List<PolicyRule>? rules)
        {
            if (rules == null || !rules.Any()) return;

            var overlyPermissive = new List<(int Index, PolicyRule Rule)>();

            foreach (var (index, rule) in rules.Select((r, i) => (i, r)))
            {
                // Check for overly broad source ranges
                if (!string.IsNullOrEmpty(rule.FromPorts?.FirstOrDefault()))
                {
                    var portCount = rule.FromPorts.Count;
                    if (portCount > _baseline.MaxIngressPortsPerRule)
                    {
                        result.Findings.Add(new AnalysisFinding(
                            PolicyPriority.Low,
                            $"Ingress rule #{index + 1} has {portCount} ports - consider splitting",
                            new[] { "Split into multiple rules with specific port ranges" },
                            1.0));
                    }

                    // Check for wildcard protocols
                    if (rule.Protocol != null && !SecurityBaseline.AllowedProtocols.Contains(rule.Protocol))
                    {
                        result.Findings.Add(new AnalysisFinding(
                            PolicyPriority.Medium,
                            $"Ingress rule #{index + 1} uses non-standard protocol: {rule.Protocol}",
                            new[] { "Restrict to TCP/UDP/* or explicitly allowed protocols" },
                            4.0));
                    }

                    // Check for overly permissive sources (e.g., 0.0.0.0/0)
                    if (!string.IsNullOrEmpty(rule.Sources?.FirstOrDefault()))
                    {
                        var source = rule.Sources.First();
                        if (source.Contains("0.0.0.0") || source == "*")
                        {
                            result.Findings.Add(new AnalysisFinding(
                                PolicyPriority.High,
                                $"Ingress rule #{index + 1} allows traffic from any source: {source}",
                                new[] { "Restrict to specific CIDR blocks or namespaces" },
                                8.0));
                        }
                    }
                }

                // Check for missing port specification (allows all ports)
                if (rule.FromPorts == null || rule.FromPorts.Count == 0)
                {
                    result.Findings.Add(new AnalysisFinding(
                        PolicyPriority.Medium,
                        $"Ingress rule #{index + 1} has no port restrictions",
                        new[] { "Add 'fromPorts' field with specific ports or ranges" },
                        5.0));
                }
            }

            // Check if any ingress allows all traffic (no source/port limits)
            var unrestrictedIngress = rules.Any(r => 
                r.FromPorts == null || !r.FromPorts.Any());

            if (unrestrictedIngress)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Critical,
                    "At least one ingress rule allows all traffic",
                    new[] { "Add port restrictions or source limits to every ingress rule" },
                    15.0));
            }
        }

        // ============================================================================
        // ANALYSIS LOGIC - PHASE 3: EGRESS ANALYSIS
        // ============================================================================

        private static void AnalyzeEgressRules(AnalysisResult result, List<PolicyRule>? rules)
        {
            if (rules == null || !rules.Any()) return;

            var unrestrictedEgress = new List<(int Index, PolicyRule Rule)>();

            foreach (var (index, rule) in rules.Select((r, i) => (i, r)))
            {
                // Check for unrestricted egress
                if (rule.ToPorts == null || !rule.ToPorts.Any())
                {
                    result.Findings.Add(new AnalysisFinding(
                        PolicyPriority.Critical,
                        $"Egress rule #{index + 1} allows all traffic to any destination",
                        new[] { "Add 'toPorts' and 'destinations' restrictions" },
                        20.0));

                    unrestrictedEgress.Add((index, rule));
                }

                // Check for overly broad destinations
                if (!string.IsNullOrEmpty(rule.Destinations?.FirstOrDefault()))
                {
                    var dest = rule.Destinations.First();
                    if (dest.Contains("0.0.0.0") || dest == "*")
                    {
                        result.Findings.Add(new AnalysisFinding(
                            PolicyPriority.High,
                            $"Egress rule #{index + 1} allows traffic to any destination: {dest}",
                            new[] { "Restrict to required external services only" },
                            10.0));
                    }
                }

                // Check for missing egress restrictions
                if (rule.ToPorts == null || !rule.ToPorts.Any())
                {
                    result.Findings.Add(new AnalysisFinding(
                        PolicyPriority.Medium,
                        $"Egress rule #{index + 1} has no port restrictions",
                        new[] { "Add 'toPorts' field with specific ports" },
                        4.0));
                }

                // Check for external egress (potential data exfiltration)
                if (!string.IsNullOrEmpty(rule.Protocol))
                {
                    var isExternal = rule.Destinations?.Any(d => 
                        d.Contains(".") && !d.StartsWith("127.") && !d.StartsWith("10.") && 
                        !d.StartsWith("192.168.") && !d.StartsWith("172."));

                    if (isExternal)
                    {
                        result.Findings.Add(new AnalysisFinding(
                            PolicyPriority.High,
                            $"Egress rule #{index + 1} allows external traffic",
                            new[] { "Document business justification for each external dependency" },
                            6.0));
                    }
                }
            }

            if (unrestrictedEgress.Any())
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Critical,
                    $"{unrestrictedEgress.Count} egress rules allow unrestricted traffic",
                    new[] { "Apply least-privilege principle to external dependencies" },
                    25.0));
            }
        }

        // ============================================================================
        // ANALYSIS LOGIC - PHASE 4: CROSS-CHECKS
        // ============================================================================

        private static void CheckCrossNamespaceTraffic(AnalysisResult result, IPolicyDocument doc)
        {
            if (doc.Namespace == null || string.IsNullOrEmpty(doc.Namespace))
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Medium,
                    "Missing namespace identifier in policy document",
                    new[] { "Add 'namespace' field to properly scope the policy" },
                    2.0));
            }

            // Check for potential cross-namespace traffic patterns
            if (doc.IngressRules?.Any(r => r.Allow) == true && 
                doc.EgressRules?.Any(r => r.Allow) == true)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Info,
                    "Policy allows both ingress and egress traffic",
                    new[] { "Verify this is intentional for the workload type" },
                    0.5));
            }

            // Check for potential data exfiltration paths
            var externalEgressCount = doc.EgressRules?.Count(r => 
                r.ToPorts != null && r.ToPorts.Any()) ?? 0;

            if (externalEgressCount > 3)
            {
                result.Findings.Add(new AnalysisFinding(
                    PolicyPriority.Medium,
                    $"High egress complexity: {externalEgressCount} external egress rules",
                    new[] { "Review each rule for necessity and consolidation opportunities" },
                    2.0));
            }
        }

        // ============================================================================
        // SCORING AND REPORTING
        // ============================================================================

        private static double CalculateScore(AnalysisResult result)
        {
            if (result.Findings.Count == 0) return 100.0;

            var totalPenalty = result.Findings.Sum(f => f.Penalty);
            var score = Math.Max(0, 100.0 - totalPenalty);

            // Apply severity multiplier for critical findings
            var criticalCount = result.Findings.Count(f => f.Priority == PolicyPriority.Critical);
            if (criticalCount > 0)
            {
                score -= criticalCount * 5;
            }

            return Math.Max(0, score);
        }

        // ============================================================================
        // PUBLIC API: ANALYSIS RESULT
        // ============================================================================

        public class AnalysisResult
        {
            public string? Namespace { get; set; }
            public IPolicyDocument? Document { get; set; }
            public double Score { get; set; }
            public List<AnalysisFinding> Findings { get; } = new();
            public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;

            public AnalysisResult(string? namespaceName)
            {
                Namespace = namespaceName;
            }

            public void AddFinding(AnalysisFinding finding)
            {
                Findings.Add(finding);
            }

            public bool HasCriticalIssues() => 
                Findings.Any(f => f.Priority == PolicyPriority.Critical);

            public bool IsCompliant(double threshold = 80.0) => Score >= threshold;

            public string GenerateSummary()
            {
                var criticalCount = Findings.Count(f => f.Priority == PolicyPriority.Critical);
                var highCount = Findings.Count(f => f.Priority == PolicyPriority.High);
                var mediumCount = Findings.Count(f => f.Priority == PolicyPriority.Medium);

                return $"""
                    Namespace: {Namespace ?? "Unknown"}
                    Security Score: {Score:F1}%
                    
                    Severity Summary:
                      - Critical: {criticalCount}
                      - High:    {highCount}
                      - Medium:  {mediumCount}
                      - Low/Info:{Findings.Count(f => f.Priority != PolicyPriority.Critical && 
                                              f.Priority != PolicyPriority.High && 
                                              f.Priority != PolicyPriority.Medium)}

                    Compliance Status: {(IsCompliant() ? "COMPLIANT" : "NON-COMPLIANT")}
                    
                    Top Issues:
                """;
            }
        }

        public class AnalysisFinding
        {
            public PolicyPriority Priority { get; set; }
            public string Title { get; set; } = "";
            public List<string> Recommendations { get; set; } = new();
            public double Penalty { get; set; }

            public AnalysisFinding(PolicyPriority priority, string title, 
                                   List<string>? recommendations = null, 
                                   double penalty = 0.0)
            {
                Priority = priority;
                Title = title;
                Recommendations ??= new();
                if (recommendations != null)
                {
                    foreach (var rec in recommendations)
                    {
                        Recommendations.Add(rec);
                    }
                }
                Penalty = penalty;
            }

            public string ToMarkdown() => $"""
                    ### [{Priority}] {Title}
                    
                    **Penalty:** -{Penalty:F1}%
                    
                    
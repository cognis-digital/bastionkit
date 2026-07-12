// polyglot/typescript/network_policy_analyzer.ts

import { K8sNetworkPolicy, RuleSet, Violation, Severity, Report } from './types';

/**
 * Configuration for the analyzer.
 */
export interface AnalyzerConfig {
  namespaces: string[]; // Namespaces to analyze (empty = all)
  criticalServices: string[]; // Services that MUST have egress rules
  defaultDenyRequired: boolean; // Require at least one deny-all policy per namespace
}

/**
 * Severity levels for violations.
 */
export enum Severity {
  Critical = 'CRITICAL',
  High = 'HIGH',
  Medium = 'MEDIUM',
  Low = 'LOW',
  Info = 'INFO'
}

/**
 * A single violation found during analysis.
 */
export interface Violation {
  id: string;
  severity: Severity;
  ruleId: string;
  namespace: string;
  policyName?: string;
  description: string;
  recommendation: string;
  affectedResources: ResourceReference[];
}

/**
 * Reference to a Kubernetes resource.
 */
export interface ResourceReference {
  kind: string;
  name: string;
  namespace?: string;
  uid?: string;
}

/**
 * A parsed NetworkPolicy from K8s API response.
 */
export interface ParsedNetworkPolicy {
  metadata: {
    name: string;
    namespace: string;
    uid: string;
    labels?: Record<string, string>;
  };
  spec: {
    podSelector: { matchLabels?: Record<string, string> } | null;
    ingress?: IngressRule[];
    egress?: EgressRule[];
    policyTypes: ('Ingress' | 'Egress')[];
  };
}

/**
 * A single ingress rule.
 */
export interface IngressRule {
  from: FromSelector[];
  ports?: PortSelector[];
}

/**
 * A single egress rule.
 */
export interface EgressRule {
  to: ToSelector[];
  ports?: PortSelector[];
}

/**
 * Selector criteria (from/to).
 */
export interface FromSelector {
  namespaceSelector?: { matchLabels?: Record<string, string> } | null;
  podSelector?: { matchLabels?: Record<string, string> } | null;
}

/**
 * Port selector.
 */
export interface PortSelector {
  port: number | string;
  protocol: 'TCP' | 'UDP';
}

/**
 * Selector criteria (to).
 */
export interface ToSelector {
  namespaceSelector?: { matchLabels?: Record<string, string> } | null;
  podSelector?: { matchLabels?: Record<string, string> } | null;
}

/**
 * Main analyzer class.
 */
export class NetworkPolicyAnalyzer {
  private config: AnalyzerConfig;
  private violations: Violation[] = [];

  constructor(config: Partial<AnalyzerConfig> = {}) {
    this.config = {
      namespaces: [], // All if empty
      criticalServices: ['kube-dns', 'coredns'],
      defaultDenyRequired: true,
      ...config
    };
  }

  /**
   * Analyze a single parsed NetworkPolicy.
   */
  private analyzePolicy(policy: ParsedNetworkPolicy): void {
    const ns = policy.metadata.namespace;
    const name = policy.metadata.name;
    
    // Rule 1: Check for overly permissive ingress/egress
    this.checkPermissiveRules(policy, ns, name);
    
    // Rule 2: Verify critical services have egress rules
    if (this.config.criticalServices.length > 0) {
      this.checkCriticalServiceEgress(policy, ns, name);
    }
    
    // Rule 3: Check for default deny policy presence
    if (this.config.defaultDenyRequired) {
      this.checkDefaultDenyPresence(ns, name, policy);
    }
    
    // Rule 4: Validate port restrictions
    this.checkPortRestrictions(policy, ns, name);
  }

  /**
   * Check for overly permissive rules (using "*").
   */
  private checkPermissiveRules(
    policy: ParsedNetworkPolicy, 
    ns: string, 
    name: string
  ): void {
    const issues: { ruleId: string; description: string; recommendation: string }[] = [];

    // Check ingress for permissive "from"
    if (policy.spec.ingress) {
      policy.spec.ingress.forEach((rule, idx) => {
        const hasPermissiveFrom = rule.from.some(f => 
          !f.namespaceSelector || Object.keys(f.namespaceSelector.matchLabels || {}).length === 0
        );
        
        if (hasPermissiveFrom && rule.from.length > 1) {
          issues.push({
            ruleId: 'PERMISSIVE_INGRESS',
            description: `Ingress rule ${idx + 1} has overly permissive "from" selector`,
            recommendation: 'Restrict source namespaces or pods to specific selectors'
          });
        }

        // Check for port "*" in ingress
        if (rule.ports?.some(p => p.port === '*')) {
          issues.push({
            ruleId: 'PORT_WILDCARD_INGRESS',
            description: `Ingress rule ${idx + 1} allows all ports`,
            recommendation: 'Specify explicit port numbers or ranges'
          });
        }
      });
    }

    // Check egress for permissive "to"
    if (policy.spec.egress) {
      policy.spec.egress.forEach((rule, idx) => {
        const hasPermissiveTo = rule.to.some(t => 
          !t.namespaceSelector || Object.keys(t.namespaceSelector.matchLabels || {}).length === 0
        );

        if (hasPermissiveTo && rule.to.length > 1) {
          issues.push({
            ruleId: 'PERMISSIVE_EGRESS',
            description: `Egress rule ${idx + 1} has overly permissive "to" selector`,
            recommendation: 'Restrict destination namespaces or pods to specific selectors'
          });
        }

        // Check for port "*" in egress
        if (rule.ports?.some(p => p.port === '*')) {
          issues.push({
            ruleId: 'PORT_WILDCARD_EGRESS',
            description: `Egress rule ${idx + 1} allows all ports`,
            recommendation: 'Specify explicit port numbers or ranges'
          });
        }
      });
    }

    // Add violations for any issues found
    if (issues.length > 0) {
      this.addViolations(issues, ns, name);
    }
  }

  /**
   * Check that critical services have egress rules.
   */
  private checkCriticalServiceEgress(
    policy: ParsedNetworkPolicy, 
    ns: string, 
    name: string
  ): void {
    const hasEgress = policy.spec.policyTypes.includes('Egress');
    
    if (!hasEgress) {
      this.addViolation({
        id: `CRIT-${ns}-${name}-NO-EGRESS`,
        severity: Severity.Critical,
        ruleId: 'MISSING_CRITICAL_EGRESS',
        namespace: ns,
        policyName: name,
        description: `Critical service "${name}" has no egress rules defined`,
        recommendation: 'Add an Egress policy type to allow critical service communication',
        affectedResources: [{ kind: 'NetworkPolicy', name, namespace: ns }]
      });
    } else if (policy.spec.egress) {
      // Check if any rule allows external traffic
      const hasExternalEgress = policy.spec.egress.some(rule => 
        !rule.to.some(t => t.namespaceSelector || t.podSelector)
      );

      if (!hasExternalEgress && policy.spec.policyTypes.includes('Egress')) {
        this.addViolation({
          id: `CRIT-${ns}-${name}-STALE-EGRESS`,
          severity: Severity.High,
          ruleId: 'STALE_CRITICAL_EGRESS',
          namespace: ns,
          policyName: name,
          description: `Critical service "${name}" has egress rules but no external connectivity`,
          recommendation: 'Review if this critical service needs to communicate outside the cluster',
          affectedResources: [{ kind: 'NetworkPolicy', name, namespace: ns }]
        });
      }
    }
  }

  /**
   * Check for at least one default deny policy per namespace.
   */
  private checkDefaultDenyPresence(
    ns: string, 
    name: string, 
    policy: ParsedNetworkPolicy
  ): void {
    // A deny-all policy has no ingress/egress rules or empty selectors
    const isDenyAll = !policy.spec.ingress && !policy.spec.egress;

    if (isDenyAll) {
      this.addViolation({
        id: `DENY-${ns}-${name}`,
        severity: Severity.Info,
        ruleId: 'DEFAULT_DENY_FOUND',
        namespace: ns,
        policyName: name,
        description: `Found default deny-all policy "${name}"`,
        recommendation: 'Verify this is intentional and covers all pods in the namespace',
        affectedResources: [{ kind: 'NetworkPolicy', name, namespace: ns }]
      });
    } else if (policy.spec.ingress?.every(r => r.from.length === 0) &&
               policy.spec.egress?.every(r => r.to.length === 0)) {
      // Empty selectors also imply deny-all behavior
      this.addViolation({
        id: `DENY-${ns}-${name}-EMPTY`,
        severity: Severity.Info,
        ruleId: 'DEFAULT_DENY_EMPTY',
        namespace: ns,
        policyName: name,
        description: `Found default deny-all policy "${name}" with empty selectors`,
        recommendation: 'Verify this is intentional and covers all pods in the namespace',
        affectedResources: [{ kind: 'NetworkPolicy', name, namespace: ns }]
      });
    }
  }

  /**
   * Check port restrictions.
   */
  private checkPortRestrictions(
    policy: ParsedNetworkPolicy, 
    ns: string, 
    name: string
  ): void {
    const issues: { ruleId: string; description: string; recommendation: string }[] = [];

    // Check ingress ports
    if (policy.spec.ingress) {
      policy.spec.ingress.forEach((rule, idx) => {
        if (!rule.ports || rule.ports.length === 0) {
          issues.push({
            ruleId: 'INGRESS_NO_PORTS',
            description: `Ingress rule ${idx + 1} has no port restrictions`,
            recommendation: 'Add explicit port specifications to limit exposure'
          });
        } else if (rule.ports.some(p => typeof p.port === 'string')) {
          issues.push({
            ruleId: 'INGRESS_STRING_PORT',
            description: `Ingress rule ${idx + 1} uses string port (may be wildcard)`,
            recommendation: 'Convert to numeric ports for clarity'
          });
        }
      });
    }

    // Check egress ports
    if (policy.spec.egress) {
      policy.spec.egress.forEach((rule, idx) => {
        if (!rule.ports || rule.ports.length === 0) {
          issues.push({
            ruleId: 'EGRESS_NO_PORTS',
            description: `Egress rule ${idx + 1} has no port restrictions`,
            recommendation: 'Add explicit port specifications to limit outbound traffic'
          });
        } else if (rule.ports.some(p => typeof p.port === 'string')) {
          issues.push({
            ruleId: 'EGRESS_STRING_PORT',
            description: `Egress rule ${idx + 1} uses string port (may be wildcard)`,
            recommendation: 'Convert to numeric ports for clarity'
          });
        }
      });
    }

    if (issues.length > 0) {
      this.addViolations(issues, ns, name);
    }
  }

  /**
   * Add a single violation.
   */
  private addViolation(violation: Omit<Violation, 'id'>): void {
    const id = `${violation.ruleId}-${Date.now()}`;
    this.violations.push({ ...violation, id });
  }

  /**
   * Add multiple violations at once.
   */
  private addViolations(
    issues: { ruleId: string; description: string; recommendation: string }[], 
    ns: string, 
    name?: string
  ): void {
    const baseName = name || 'unnamed';

    for (const issue of issues) {
      this.addViolation({
        id: `${issue.ruleId}-${Date.now()}`,
        severity: Severity.Medium,
        ruleId: issue.ruleId,
        namespace: ns,
        policyName: baseName,
        description: issue.description,
        recommendation: issue.recommendation,
        affectedResources: [{ kind: 'NetworkPolicy', name: baseName, namespace: ns }]
      });
    }
  }

  /**
   * Analyze all policies in a single namespace.
   */
  public analyzeNamespace(ns: string, policies: ParsedNetworkPolicy[]): Report {
    this.violations = []; // Reset for new analysis
    
    let totalPolicies = 0;
    let compliantCount = 0;

    for (const policy of policies) {
      totalPolicies++;
      
      const isCompliant = !this.hasPermissiveRules(policy);
      
      if (isCompliant) {
        compliantCount++;
      }

      this.analyzePolicy(policy);
    }

    return {
      namespace: ns,
      totalPolicies,
      compliantCount,
      complianceRate: totalPolicies > 0 ? (compliantCount / totalPolicies * 100).toFixed(2) : '0',
      violations: this.violations.filter(v => v.namespace === ns),
      summary: {
        critical: this.violations.filter(v => v.severity === Severity.Critical).length,
        high: this.violations.filter(v => v.severity === Severity.High).length,
        medium: this.violations.filter(v => v.severity === Severity.Medium).length,
        low: this.violations.filter(v => v.severity === Severity.Low).length,
        info: this.violations.filter(v => v.severity === Severity.Info).length
      }
    };
  }

  /**
   * Analyze multiple namespaces.
   */
  public analyze(namespaces: string[], policiesByNs: Record<string, ParsedNetworkPolicy[]>): Report[] {
    const reports: Report[] = [];

    for (const ns of namespaces) {
      const policies = policiesByNs[ns] || [];
      if (policies.length === 0 && this.config.namespaces.includes(ns)) {
        // Namespace exists but has no policies - still report it
        reports.push({
          namespace: ns,
          totalPolicies: 0,
          compliantCount: 0,
          complianceRate: 'N/A',
          violations: [],
          summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        });
      } else if (policies.length > 0) {
        reports.push(this.analyzeNamespace(ns, policies));
      }
    }

    return reports;
  }

  /**
   * Check if a policy has any permissive rules.
   */
  private hasPermissiveRules(policy: ParsedNetworkPolicy): boolean {
    const checkIngress = (rule: IngressRule) => 
      rule.from.some(f => !f.namespaceSelector || Object.keys(f.namespaceSelector.matchLabels || {}).length === 0);

    const checkEgress = (rule: EgressRule) => 
      rule.to.some(t => !t.namespaceSelector || Object.keys(t.namespaceSelector.matchLabels || {}).length === 0);

    return policy.spec.ingress?.some(checkIngress) || 
           policy.spec.egress?.some(checkEgress) || false;
  }

  /**
   * Get aggregated summary across all analyzed namespaces.
   */
  public getGlobalSummary(): {
    totalNamespaces: number;
    totalPolicies: number;
    totalCompliant: number;
    overallRate: string;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  } {
    const namespaces = new Set(this.violations.map(v => v.namespace));
    
    let totalPolicies = 0;
    let totalCompliant = 0;

    for
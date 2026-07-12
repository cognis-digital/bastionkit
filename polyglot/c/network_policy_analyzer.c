/*
 * polyglot/c/network_policy_analyzer.c
 * 
 * BastionKit - Hardened Security Baseline for Air-Gapped/Regulated Kubernetes
 * Network Policy Analyzer Module
 * 
 * Analyzes existing NetworkPolicy resources to identify connectivity gaps,
 * potential violations, and generates hardened policy recommendations.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

#define MAX_PODS 1024
#define MAX_SERVICES 512
#define MAX_POLICIES 256
#define MAX_RULES_PER_POLICY 64
#define MAX_LABEL_VALUES 32
#define MAX_SELECTOR_TERMS 8
#define MAX_IP_RANGES 16
#define MAX_PORTS 16

/* ============================================================================
 * Data Structures
 * ============================================================================ */

typedef struct {
    char name[64];
    char namespace[64];
    uint32_t uid;
} PodInfo;

typedef struct {
    char name[64];
    char namespace[64];
    uint32_t uid;
    int port;
    int protocol; /* 0=TCP, 1=UDP */
} ServiceEntry;

typedef struct {
    char key[64];
    char value[MAX_LABEL_VALUES];
} SelectorTerm;

typedef struct {
    SelectorTerm terms[MAX_SELECTOR_TERMS];
    uint32_t term_count;
    bool match_all; /* true = AND, false = OR */
} LabelSelector;

typedef struct {
    char name[64];
    char namespace[64];
    int priority;
    bool is_ingress;
    
    /* Ingress rules (incoming traffic) */
    struct {
        LabelSelector from_selector;
        uint32_t ip_block_count;
        uint32_t port_count;
        bool allow_all_ports;
        bool allow_all_ips;
    } ingress_rules[MAX_RULES_PER_POLICY];
    
    /* Egress rules (outgoing traffic) */
    struct {
        LabelSelector to_selector;
        uint32_t ip_block_count;
        uint32_t port_count;
        bool allow_all_ports;
        bool allow_all_ips;
    } egress_rules[MAX_RULES_PER_POLICY];
    
    /* Policy metadata */
    int ingress_rule_count;
    int egress_rule_count;
} NetworkPolicy;

typedef struct {
    PodInfo pod;
    uint32_t policy_uid;
    bool is_allowed;
} PolicyMatchResult;

/* ============================================================================
 * Global State (for demo purposes - would be thread-local in production)
 * ============================================================================ */

static int g_pod_count = 0;
static int g_service_count = 0;
static int g_policy_count = 0;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static inline bool is_empty_string(const char *s, size_t len) {
    return s == NULL || (len == 0 && !*s);
}

static inline uint32_t hash_selector(const SelectorTerm *terms, uint32_t count) {
    uint32_t h = 5381;
    for (uint32_t i = 0; i < count; i++) {
        const char *key = terms[i].key;
        while (*key) {
            h = ((h << 5) + h) + (unsigned char)*key++;
        }
    }
    return h;
}

/* Check if a label selector matches a pod's labels */
static bool selector_matches_pod(const LabelSelector *sel, const PodInfo *pod,
                                  const char **labels, int num_labels) {
    if (sel->term_count == 0 && sel->match_all) {
        return true; /* Empty AND = match all */
    }

    for (uint32_t i = 0; i < sel->term_count; i++) {
        bool found = false;
        
        for (int j = 0; j < num_labels && !found; j++) {
            const char *label_key = labels[j];
            if (!is_empty_string(label_key, strlen(label_key))) {
                /* Check key match */
                size_t key_len = strlen(sel->terms[i].key);
                if (strncmp(label_key, sel->terms[i].key, key_len) == 0 &&
                    (label_key[key_len] == '\0' || label_key[key_len] == '=') &&
                    !is_empty_string(sel->terms[i].value, strlen(sel->terms[i].value))) {
                    
                    /* Check value match */
                    size_t val_len = strlen(sel->terms[i].value);
                    if (strncmp(&label_key[key_len + 1], sel->terms[i].value, val_len) == 0 &&
                        (&label_key[key_len + 1][val_len] == '\0' || 
                         &label_key[key_len + 1][val_len] == '=')) {
                        found = true;
                    }
                }
            }
        }

        if (!found) {
            return false; /* AND semantics - all terms must match */
        }
    }

    return sel->match_all ? true : false;
}

/* ============================================================================
 * Policy Matching Engine
 * ============================================================================ */

static int find_policy_for_pod(const NetworkPolicy **policies, int count,
                               const PodInfo *pod) {
    for (int i = 0; i < count; i++) {
        if (!is_empty_string(policies[i].name, strlen(policies[i].name))) {
            /* Check namespace match */
            size_t ns_len = strlen(pod->namespace);
            if (strncmp(policies[i].namespace, pod->namespace, ns_len) == 0 &&
                (&policies[i].namespace[ns_len] == '\0' || 
                 &policies[i].namespace[ns_len] == '=')) {
                
                /* Check selector match */
                if (selector_matches_pod(&policies[i].ingress_rules[0].from_selector,
                                        pod, NULL, 0)) {
                    return i;
                }
            }
        }
    }
    return -1;
}

/* ============================================================================
 * Traffic Matrix Builder
 * ============================================================================ */

typedef struct {
    char source_ip[32];
    uint16_t source_port;
    int protocol; /* 0=TCP, 1=UDP */
    char dest_ip[32];
    uint16_t dest_port;
} TrafficEntry;

static void build_traffic_matrix(const NetworkPolicy *policies, int count,
                                  TrafficEntry **matrix, int *matrix_size) {
    *matrix_size = 0;
    
    for (int i = 0; i < count && *matrix_size < MAX_PODS * MAX_PODS; i++) {
        /* Build ingress traffic entries */
        if (policies[i].ingress_rule_count > 0) {
            for (int j = 0; j < policies[i].ingress_rule_count; j++) {
                const NetworkPolicy *np = &policies[i];
                
                /* Check if this is an allow rule */
                bool is_allow = np->priority >= 1000;
                
                for (int k = 0; k < MAX_RULES_PER_POLICY && 
                         j + k < policies[i].ingress_rule_count; k++) {
                    const struct {
                        LabelSelector sel;
                        uint32_t ip_cnt, port_cnt;
                        bool all_ports, all_ips;
                    } *rule = &np->ingress_rules[j + k];
                    
                    /* Generate sample traffic entries for analysis */
                    if (is_allow) {
                        TrafficEntry *entry = &(*matrix)[*matrix_size];
                        
                        if (!rule->all_ips && !rule->all_ports) {
                            /* Specific rules - generate representative entries */
                            entry->source_ip[0] = '\0';
                            entry->dest_port = 80 + (j % 10);
                            entry->protocol = 0; /* TCP default */
                            
                            if (!rule->all_ips) {
                                snprintf(entry->source_ip, sizeof(entry->source_ip),
                                         "10.%d.0.0/24", j % 256);
                            } else {
                                strncpy(entry->source_ip, "0.0.0.0/", sizeof(entry->source_ip));
                            }
                            
                            if (!rule->all_ports) {
                                entry->dest_port = (uint16_t)(80 + j % 15);
                            } else {
                                entry->dest_port = 0; /* Any port */
                            }
                            
                            (*matrix_size)++;
                        }
                    }
                }
            }
        }
    }
}

/* ============================================================================
 * Analyzer Core - Find Connectivity Gaps and Violations
 * ============================================================================ */

typedef struct {
    char description[256];
    uint32_t severity; /* 0=info, 1=low, 2=medium, 3=high, 4=critical */
    int affected_pods;
    NetworkPolicy *suggested_policy;
} AnalysisFinding;

static void analyze_network_policies(const NetworkPolicy *policies, int count,
                                     AnalysisFinding **findings, 
                                     int *finding_count) {
    *finding_count = 0;
    
    /* Check for overly permissive ingress rules */
    for (int i = 0; i < count && *finding_count < MAX_POLICIES; i++) {
        const NetworkPolicy *np = &policies[i];
        
        if (!is_empty_string(np->name, strlen(np->name))) {
            /* Check ingress: allow all from anywhere */
            for (int j = 0; j < np->ingress_rule_count; j++) {
                const struct {
                    LabelSelector sel;
                    uint32_t ip_cnt, port_cnt;
                    bool all_ports, all_ips;
                } *rule = &np->ingress_rules[j];
                
                if (rule->all_ips && rule->all_ports) {
                    AnalysisFinding *f = &(*findings)[*finding_count];
                    
                    snprintf(f->description, sizeof(f->description),
                             "Policy '%s' allows all ingress from any IP on any port",
                             np->name);
                    f->severity = 3; /* High */
                    f->affected_pods = g_pod_count;
                    f->suggested_policy = (NetworkPolicy*)np;
                    
                    (*finding_count)++;
                } else if (!rule->all_ports && rule->ip_cnt == 0) {
                    AnalysisFinding *f = &(*findings)[*finding_count];
                    
                    snprintf(f->description, sizeof(f->description),
                             "Policy '%s' has ingress rule without IP restrictions",
                             np->name);
                    f->severity = 2; /* Medium */
                    f->affected_pods = g_pod_count / 2;
                    f->suggested_policy = (NetworkPolicy*)np;
                    
                    (*finding_count)++;
                }
            }
        }
    }
    
    /* Check for overly permissive egress rules */
    for (int i = 0; i < count && *finding_count < MAX_POLICIES; i++) {
        const NetworkPolicy *np = &policies[i];
        
        if (!is_empty_string(np->name, strlen(np->name))) {
            /* Check egress: allow all to anywhere */
            for (int j = 0; j < np->egress_rule_count; j++) {
                const struct {
                    LabelSelector sel;
                    uint32_t ip_cnt, port_cnt;
                    bool all_ports, all_ips;
                } *rule = &np->egress_rules[j];
                
                if (rule->all_ips && rule->all_ports) {
                    AnalysisFinding *f = &(*findings)[*finding_count];
                    
                    snprintf(f->description, sizeof(f->description),
                             "Policy '%s' allows all egress to any IP on any port",
                             np->name);
                    f->severity = 3; /* High */
                    f->affected_pods = g_pod_count;
                    f->suggested_policy = (NetworkPolicy*)np;
                    
                    (*finding_count)++;
                } else if (!rule->all_ports && rule->ip_cnt == 0) {
                    AnalysisFinding *f = &(*findings)[*finding_count];
                    
                    snprintf(f->description, sizeof(f->description),
                             "Policy '%s' has egress rule without IP restrictions",
                             np->name);
                    f->severity = 2; /* Medium */
                    f->affected_pods = g_pod_count / 2;
                    f->suggested_policy = (NetworkPolicy*)np;
                    
                    (*finding_count)++;
                }
            }
        }
    }
    
    /* Check for missing default deny policies */
    bool has_default_deny = false;
    for (int i = 0; i < count; i++) {
        const NetworkPolicy *np = &policies[i];
        
        if (!is_empty_string(np->name, strlen(np->name)) && 
            !is_empty_string(np->namespace, strlen(np->namespace))) {
            
            /* Check if this is a default deny policy */
            for (int j = 0; j < np->ingress_rule_count; j++) {
                const struct {
                    LabelSelector sel;
                    uint32_t ip_cnt, port_cnt;
                    bool all_ports, all_ips;
                } *rule = &np->ingress_rules[j];
                
                if (rule->all_ips && rule->all_ports) {
                    has_default_deny = true;
                    break;
                }
            }
        }
    }
    
    if (!has_default_deny) {
        AnalysisFinding *f = &(*findings)[*finding_count];
        
        snprintf(f->description, sizeof(f->description),
                 "No default deny ingress policy detected - consider adding one");
        f->severity = 2; /* Medium */
        f->affected_pods = g_pod_count;
        f->suggested_policy = NULL;
        
        (*finding_count)++;
    }
}

/* ============================================================================
 * Report Generation
 * ============================================================================ */

static void print_report_header(void) {
    printf("================================================================================\n");
    printf("           BASTIONKIT NETWORK POLICY ANALYSIS REPORT\n");
    printf("================================================================================\n");
    printf("\n");
}

static void print_summary(const NetworkPolicy *policies, int count,
                         AnalysisFinding *findings, int finding_count) {
    printf("SUMMARY\n");
    printf("-------\n");
    printf("Total Policies Analyzed: %d\n", count);
    printf("Total Findings: %d\n", finding_count);
    
    /* Count by severity */
    int critical = 0, high = 0, medium = 0, low = 0, info = 0;
    for (int i = 0; i < finding_count; i++) {
        switch (findings[i].severity) {
            case 4: critical++; break;
            case 3: high++; break;
            case 2: medium++; break;
            case 1: low++; break;
            default: info++; break;
        }
    }
    
    printf("Severity Breakdown:\n");
    printf("  Critical: %d\n", critical);
    printf("  High:     %d\n", high);
    printf("  Medium:   %d\n", medium);
    printf("  Low:      %d\n", low);
    printf("  Info:     %d\n", info);
    
    /* Overall score */
    double total_score = 0.0;
    if (finding_count > 0) {
        for (int i = 0; i < finding_count; i++) {
            total_score += findings[i].severity;
        }
        printf("Average Severity Score: %.1f/4\n", total_score / finding_count);
    } else {
        printf("Overall Security Score: N/A (no policies)\n");
    }
    
    printf("\n");
}

static void print_findings(const AnalysisFinding *findings, int count) {
    if (count == 0) {
        printf("No findings detected.\n\n");
        return;
    }
    
    printf("FINDINGS\n");
    printf("--------\n");
    
    for (int i = 0; i < count; i++) {
        const AnalysisFinding *f = &findings[i];
        
        printf("\n[%d] %s", f->severity, f->description);
        
        if (f->suggested_policy) {
            printf(" [Policy: %s]", f->suggested_policy->name);
        }
        
        printf("\n   Affected Pods: %d\n", f->affected_pods);
    }
    
    printf("\n");
}

static void print_recommendations(const AnalysisFinding *findings, int count) {
    if (count == 0) {
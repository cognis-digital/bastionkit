// polyglot/cpp/network_policy_analyzer.cpp
// Hardened security baseline analyzer for air-gapped Kubernetes
// Analyzes NetworkPolicies, Services, Pods and generates gap reports

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <functional>
#include <regex>

namespace bp {

// ============================================================================
// YAML Parsing (Minimal, no external deps)
// ============================================================================

class YamlParser {
public:
    std::string trim(const std::string& s) const {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    bool parseKey(const std::string& line, std::string& key, std::string& value) {
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos || colonPos > 0 && line[colonPos - 1] != ' ') {
            return false;
        }
        key = trim(line.substr(0, colonPos));
        value = trim(line.substr(colonPos + 1));
        return !key.empty();
    }

    bool parseList(const std::string& line, std::vector<std::string>& items) {
        if (line.find_first_of("[]") != std::string::npos) {
            auto start = line.find('[');
            auto end = line.rfind(']');
            if (start != std::string::npos && end > start + 1) {
                items.clear();
                size_t pos = start + 1;
                while (pos <= end) {
                    size_t next = line.find(',', pos);
                    if (next == std::string::npos) next = end + 1;
                    items.push_back(trim(line.substr(pos, next - pos)));
                    pos = next + 1;
                }
                return !items.empty();
            }
        }
        return false;
    }

    // Parse a single YAML document (one root object)
    bool parse(const std::string& content, std::map<std::string, std::string>& result) {
        std::vector<std::string> lines;
        std::stringstream ss(content);
        std::string line;
        
        while (std::getline(ss, line)) {
            // Handle multi-line strings
            if (!line.empty() && line.back() == '"') {
                size_t open = line.find('"');
                if (open != std::string::npos) {
                    line = line.substr(open + 1);
                    while (line.size() > 0 && !line.front().isspace()) {
                        auto nextOpen = line.find('"', 1);
                        if (nextOpen == std::string::npos) {
                            lines.push_back(line);
                            break;
                        }
                        lines.push_back(line.substr(0, nextOpen + 1));
                        line = line.substr(nextOpen + 1);
                    }
                } else {
                    lines.push_back(line);
                }
            } else if (!line.empty()) {
                lines.push_back(line);
            }
        }

        // Parse key-value pairs
        for (const auto& l : lines) {
            std::string k, v;
            if (parseKey(l, k, v)) {
                result[k] = v;
            } else if (!l.empty() && !l.front().isspace()) {
                // Could be a list item or nested key
                auto colonPos = l.find(':');
                if (colonPos != std::string::npos) {
                    k = trim(l.substr(0, colonPos));
                    v = trim(l.substr(colonPos + 1));
                    result[k] = v;
                } else {
                    // List item
                    auto listStart = l.find('[');
                    if (listStart != std::string::npos) {
                        auto listEnd = l.rfind(']');
                        if (listEnd > listStart + 1) {
                            std::vector<std::string> items;
                            size_t pos = listStart + 1;
                            while (pos <= listEnd) {
                                size_t next = l.find(',', pos);
                                if (next == std::string::npos) next = listEnd + 1;
                                items.push_back(trim(l.substr(pos, next - pos)));
                                pos = next + 1;
                            }
                            result[l] = items[0]; // Simplified: just take first item
                        }
                    } else {
                        result[l] = "";
                    }
                }
            }
        }

        return !result.empty();
    }

    bool parse(const std::string& content, std::map<std::string, std::vector<std::string>>& result) {
        // Parse into key -> list of values (for lists)
        std::map<std::string, std::string> flat;
        if (!parse(content, flat)) return false;

        for (const auto& [k, v] : flat) {
            if (v.empty()) continue;
            
            // Check if it's a list representation
            if (v.find_first_of("[]") != std::string::npos) {
                result[k].clear();
                size_t start = v.find('[');
                size_t end = v.rfind(']');
                if (start != std::string::npos && end > start + 1) {
                    for (size_t i = start + 1; i <= end; ) {
                        size_t comma = v.find(',', i);
                        if (comma == std::string::npos) comma = end + 1;
                        result[k].push_back(trim(v.substr(i, comma - i)));
                        i = comma + 1;
                    }
                }
            } else {
                // Single value - expand into list
                result[k].push_back(v);
            }
        }

        return !result.empty();
    }
};

// ============================================================================
// Data Structures
// ============================================================================

struct PodSpec {
    std::string name;
    std::string namespace_;
    std::vector<std::string> containers;
    std::map<std::string, std::string> labels;
    std::set<int> ports;
    std::set<std::string> volumes;
};

struct ServiceSpec {
    std::string name;
    std::string namespace_;
    int port;
    int targetPort;
    std::vector<std::string> selectors;
    bool typeClusterIp = true;
};

struct NetworkPolicyRule {
    std::string name;
    std::string namespace_;
    std::set<int> ports;
    std::set<std::string> protocols; // tcp, udp, icmp
    std::vector<std::string> from;      // Source selectors
    std::vector<std::string> to;        // Destination selectors  
    bool egress = false;
    bool allowAll = false;
};

struct NetworkPolicy {
    std::string name;
    std::string namespace_;
    std::set<int> ingressPorts;
    std::set<int> egressPorts;
    std::vector<std::string> ingressFrom;
    std::vector<std::string> egressTo;
    bool allowAllIngress = false;
    bool allowAllEgress = false;
};

struct ClusterState {
    std::map<std::string, PodSpec> pods;
    std::map<std::string, ServiceSpec> services;
    std::map<std::string, NetworkPolicy> policies;
    int totalPods = 0;
    int totalServices = 0;
    int totalPolicies = 0;
};

// ============================================================================
// Policy Engine
// ============================================================================

class PolicyEngine {
private:
    ClusterState state;
    
public:
    void loadPod(const std::string& name, const PodSpec& pod) {
        state.pods[name] = pod;
        state.totalPods++;
    }

    void loadService(const std::string& name, const ServiceSpec& svc) {
        state.services[name] = svc;
        state.totalServices++;
    }

    void loadPolicy(const std::string& name, const NetworkPolicy& pol) {
        state.policies[name] = pol;
        state.totalPolicies++;
    }

    // Check if a pod is reachable from another based on policies
    bool canReach(const PodSpec& src, const PodSpec& dst) {
        std::string srcNs = src.namespace_;
        std::string dstNs = dst.namespace_;
        
        // Same namespace - check for allow-all or explicit rules
        if (srcNs == dstNs) {
            auto it = state.policies.find(srcNs + "-default");
            if (it != state.policies.end()) {
                const auto& pol = it->second;
                // If allow all egress, can reach
                if (pol.allowAllEgress) return true;
                
                // Check for explicit deny rules
                for (const auto& [name, pol2] : state.policies) {
                    if (pol2.namespace_ == srcNs && !pol2.egressPorts.empty()) {
                        // Has egress restrictions - may block
                        return true; // Still potentially reachable
                    }
                }
            }
        }

        // Cross-namespace: need service or policy allowing it
        if (srcNs != dstNs) {
            // Check for services connecting namespaces
            for (const auto& [name, svc] : state.services) {
                if (svc.namespace_ == srcNs && svc.typeClusterIp) {
                    // ClusterIP service - can be reached from same namespace
                    if (srcNs == dstNs || !state.policies[dstNs + "-default"].allowAllEgress) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // Analyze traffic flows and find gaps
    std::vector<std::string> analyzeGaps() {
        std::vector<std::string> gaps;

        // 1. Check for pods without namespace isolation
        for (const auto& [name, pod] : state.pods) {
            if (pod.namespace_.empty()) {
                gaps.push_back("Pod '" + name + "' missing namespace label");
            }
            
            // Check container ports vs network policies
            bool hasIngressPolicy = false;
            for (const auto& [name, pol] : state.policies) {
                if (!pol.ingressPorts.empty() || !pol.egressPorts.empty()) {
                    hasIngressPolicy = true;
                    break;
                }
            }

            if (!hasIngressPolicy && pod.namespace_.empty()) {
                gaps.push_back("Pod '" + name + "' in default namespace without policy coverage");
            }
        }

        // 2. Check for overly permissive policies
        for (const auto& [name, pol] : state.policies) {
            if (pol.allowAllIngress || pol.allowAllEgress) {
                gaps.push_back("Policy '" + name + "' allows all " + 
                               (pol.allowAllIngress ? "ingress" : "egress") + ":");
            }
        }

        // 3. Check for services with wide selectors
        for (const auto& [name, svc] : state.services) {
            if (!svc.selectors.empty()) {
                gaps.push_back("Service '" + name + "' has broad selector: " + 
                               svc.selectors[0]);
            }
        }

        // 4. Check namespace isolation ratio
        std::set<std::string> namespaced;
        for (const auto& [name, pod] : state.pods) {
            if (!pod.namespace_.empty()) {
                namespaced.insert(pod.namespace_);
            }
        }

        double isolated = 0.0;
        if (!state.pods.empty()) {
            isolated = (double)namespaced.size() / state.totalPods * 100.0;
        }

        if (isolated < 50.0 && !gaps.empty()) {
            gaps.push_back(std::to_string(static_cast<int>(isolated)) + "% of pods in namespaces");
        }

        return gaps;
    }

    // Generate remediation recommendations
    std::vector<std::string> generateRemediations() const {
        std::vector<std::string> rems;

        if (state.totalPolicies == 0) {
            rems.push_back("Create default NetworkPolicy per namespace:");
            rems.push_back("  - Allow ingress on specific ports only");
            rems.push_back("  - Allow egress to required destinations");
            rems.push_back("  - Deny all else (default deny)");
        }

        if (state.totalServices > 0) {
            rems.push_back("Review Service selectors for minimal scope:");
            rems.push_back("  - Use specific app labels instead of '*'");
            rems.push_back("  - Consider namespace-scoped services");
        }

        // Check for common patterns
        bool hasDefaultPolicies = false;
        for (const auto& [name, pol] : state.policies) {
            if (name.find("-default") != std::string::npos) {
                hasDefaultPolicies = true;
                break;
            }
        }

        if (!hasDefaultPolicies) {
            rems.push_back("Add default deny policies per namespace:");
            rems.push_back("  apiVersion: networking.k8s.io/v1");
            rems.push_back("  kind: NetworkPolicy");
            rems.push_back("  metadata:");
            rems.push_back("    name: default-deny-egress");
            rems.push_back("    namespace: <your-namespace>");
            rems.push_back("  spec:");
            rems.push_back("    egress: []  # Deny all egress by default");
        }

        return rems;
    }

    // Generate JSON report
    std::string generateReport() const {
        std::stringstream ss;
        
        ss << "{\n";
        ss << "  \"cluster\": {\n";
        ss << "    \"total_pods\": " << state.totalPods << ",\n";
        ss << "    \"total_services\": " << state.totalServices << ",\n";
        ss << "    \"total_policies\": " << state.totalPolicies << "\n";
        ss << "  },\n";

        // Gaps analysis
        auto gaps = analyzeGaps();
        ss << "  \"gaps\": [";
        for (size_t i = 0; i < gaps.size(); ++i) {
            ss << "\"" << gaps[i] << "\"";
            if (i + 1 < gaps.size()) ss << ", ";
        }
        ss << "],\n";

        // Remediations
        auto rems = generateRemediations();
        ss << "  \"remediations\": [";
        for (size_t i = 0; i < rems.size(); ++i) {
            ss << "\"" << rems[i] << "\"";
            if (i + 1 < rems.size()) ss << ", ";
        }
        ss << "]\n";

        // Summary score (simple heuristic)
        int score = 100;
        for (const auto& g : gaps) {
            score -= std::min(25, static_cast<int>(g.length()));
        }
        if (score < 0) score = 0;

        ss << "  \"security_score\": " << score << "/100\n";
        ss << "}\n";

        return ss.str();
    }

    // Output human-readable report
    void outputReport(const std::string& title = "") const {
        if (title.empty()) title = "Network Policy Analysis Report";
        
        std::cout << "\n" << title << "\n";
        std::cout << std::string(60, '-') << "\n\n";

        // Summary
        ss << "SUMMARY\n";
        ss << "Total Pods:  " << state.totalPods << "\n";
        ss << "Total Services:  " << state.totalServices << "\n";
        ss << "Total Policies:  " << state.totalPolicies << "\n\n";

        // Gaps
        auto gaps = analyzeGaps();
        ss << "GAPS FOUND: " << gaps.size() << "\n\n";
        
        if (!gaps.empty()) {
            for (const auto& g : gaps) {
                std::cout << "  - " << g << "\n";
            }
        } else {
            std::cout << "  (none)\n";
        }

        // Remediations
        ss << "\nRECOMMENDATIONS\n\n";
        auto rems = generateRemediations();
        
        if (!rems.empty()) {
            for (const auto& r : rems) {
                std::cout << "  > " << r << "\n";
            }
        } else {
            std::cout << "  (none)\n";
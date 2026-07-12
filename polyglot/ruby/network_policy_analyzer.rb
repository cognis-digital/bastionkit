require 'yaml'
require 'json'
require 'fileutils'
require 'tempfile'
require 'open3'

module BastionKit
  module NetworkPolicyAnalyzer
  
    # Configuration constants
    DEFAULT_STRICTNESS = :strict
    DEFAULT_OUTPUT_DIR = './network-policies'
    DEFAULT_NAMESPACES = ['default']
    
    class << self
    
      def analyze_directory(dir, options = {})
        opts = {
          strictness: options[:strictness] || DEFAULT_STRICTNESS,
          namespaces: options[:namespaces] || DEFAULT_NAMESPACES,
          output_dir: options[:output_dir] || DEFAULT_OUTPUT_DIR,
          dry_run: options[:dry_run] || false,
          verbose: options[:verbose] || false
        }
        
        analyzer = new(opts)
        result = analyzer.analyze_directory(dir)
        
        if !opts[:dry_run] && result.success?
          FileUtils.mkdir_p(opts[:output_dir]) unless File.directory?(opts[:output_dir])
          result.save_reports(opts[:output_dir])
        end
        
        result
      end
    
      def analyze_string(yaml_content, options = {})
        opts = {
          strictness: options[:strictness] || DEFAULT_STRICTNESS,
          namespaces: options[:namespaces] || DEFAULT_NAMESPACES,
          output_dir: options[:output_dir] || DEFAULT_OUTPUT_DIR,
          dry_run: options[:dry_run] || false,
          verbose: options[:verbose] || false
        }
        
        analyzer = new(opts)
        result = analyzer.analyze_string(yaml_content)
        
        if !opts[:dry_run] && result.success?
          FileUtils.mkdir_p(opts[:output_dir]) unless File.directory?(opts[:output_dir])
          result.save_reports(opts[:output_dir])
        end
        
        result
      end
    
      def analyze_file(path, options = {})
        yaml_content = File.read(path)
        analyze_string(yaml_content, options.merge(source_path: path))
      end
    
    end
  end
  
  # Result container for analysis outcomes
  class AnalysisResult < Struct.new(:success?, :warnings, :errors, :metrics, :reports, :source_file, :start_time, :end_time)
    
    def initialize(success = true, warnings: [], errors: [], metrics: {}, reports: [])
      @success = success
      @warnings = warnings.map { |w| w.is_a?(String) ? w : w.to_s }
      @errors = errors.map { |e| e.is_a?(String) ? e : e.to_s }
      @metrics = metrics || {}
      @reports = reports || []
      @source_file = nil
      @start_time = Time.now
      @end_time = nil
    end
    
    def duration
      (@end_time - @start_time).to_f.round(3) if @end_time
    end
    
    def save_reports(output_dir)
      return unless @reports
      
      reports.each do |report|
        filename = "#{output_dir}/#{report[:name]}.yaml"
        File.write(filename, YAML.dump(report[:content]))
        
        puts "[REPORT] #{filename}" if ENV['BASTIONKIT_VERBOSE'] == '1'
      end
    end
    
    def to_h
      {
        success: @success,
        warnings: @warnings,
        errors: @errors,
        metrics: @metrics,
        reports: @reports,
        source_file: @source_file,
        duration: duration,
        start_time: @start_time.iso8601,
        end_time: @end_time ? @end_time.iso8601 : nil
      }
    end
    
    def to_json(*args)
      JSON.generate(to_h, *args)
    end
    
  end
  
  # Core analyzer class
  class Analyzer < Struct.new(:options, :namespace_list, :namespaces, :strictness_level, :metrics, :warnings, :errors, :reports)
    
    def initialize(opts = {})
      @options = opts
      @namespace_list = opts[:namespaces] || DEFAULT_NAMESPACES
      @strictness_level = opts[:strictness] || DEFAULT_STRICTNESS
      @metrics = { namespaces: 0, resources: 0, policies_found: 0 }
      @warnings = []
      @errors = []
      @reports = []
    end
    
    def analyze_directory(dir)
      puts "[ANALYZER] Scanning directory: #{dir}" if @options[:verbose]
      
      files = Dir.glob("#{dir}/**/*.yaml") + Dir.glob("#{dir}/**/*.yml")
      files << "#{dir}/kustomization.yaml" if File.directory?(dir)
      
      return analyze_string(files.join("\n---\n"), source_file: dir, namespace_list: @namespace_list) unless files.any?
    end
    
    def analyze_string(content, options = {})
      @options[:source_file] = options[:source_file] || 'stdin'
      @metrics[:resources] = 0
      
      # Parse all YAML documents
      docs = YAML.load_all(content)
      
      namespace_map = {}
      policies_found = []
      
      docs.each do |doc|
        next unless doc.is_a?(Hash) && doc.key?('apiVersion')
        
        api_version = doc['apiVersion']
        kind = doc['kind']
        name = doc['metadata']['name'] || 'unknown'
        ns = doc['metadata']['namespace'] || 'default'
        
        @metrics[:resources] += 1
        
        # Track namespaces
        namespace_map[ns] ||= { count: 0, resources: [] }
        namespace_map[ns][:count] += 1
        namespace_map[ns][:resources] << kind unless namespace_map[ns][:resources].include?(kind)
        
        # Extract existing policies
        if policy_match?(api_version, kind)
          policies_found << { api_version: api_version, kind: kind, name: name, namespace: ns }
          
          analyze_policy(doc, ns) if @strictness_level == :strict
        end
        
        # Analyze other resources for implicit policies
        analyze_resource(doc, ns) unless policy_match?(api_version, kind)
      end
      
      # Generate recommendations
      generate_recommendations(namespace_map, policies_found)
      
      result = AnalysisResult.new(true, @warnings, @errors, @metrics, @reports, @options[:source_file])
      result.end_time = Time.now
      
      puts "[ANALYZER] Found #{@metrics[:resources]} resources in #{@namespace_list.join(', ')} namespaces" if @options[:verbose]
      
      result
    end
    
    private
    
    def policy_match?(api_version, kind)
      policies = ['networking.k8s.io/v1', 'extensions/v1beta1']
      kinds = ['NetworkPolicy', 'Ingress', 'Service']
      
      (policies.include?(api_version) || api_version.start_with?('kubernetes.io')) && 
        kinds.include?(kind)
    end
    
    def analyze_policy(policy_doc, ns)
      name = policy_doc['metadata']['name'] || 'unknown'
      
      # Check for overly permissive rules
      policy_doc['spec'].each do |policy|
        next unless policy.is_a?(Hash) && policy.key?('policyTypes')
        
        policy['policyTypes'].each do |type|
          if type == :ingress
            analyze_ingress(policy, name, ns)
          elsif type == :egress
            analyze_egress(policy, name, ns)
          end
        end
      end
      
      # Check for default deny policies (good practice)
      check_default_deny!(policy_doc, name, ns)
    end
    
    def analyze_ingress(policy, name, ns)
      rules = policy['spec']['ingress'] || []
      
      rules.each do |rule|
        from_ports = rule['from'].map { |f| f['ports'] }.flatten.map { |p| p['port'] }
        
        if from_ports.include?(80) || from_ports.include?(443)
          @warnings << "Policy '#{name}' allows HTTP/HTTPS traffic in namespace #{ns}" unless @strictness_level == :very_strict
          
          # Check for wildcard ports
          if rule['from'].any? { |f| f['ports']&.any? { |p| p['port'] == 'all' } }
            @warnings << "Policy '#{name}' uses wildcard port in namespace #{ns}"
          end
        end
        
        # Check for overly broad CIDR ranges
        rule['from'].each do |f|
          if f['ipBlock']&.key?('cidr')
            cidr = f['ipBlock']['cidr']
            mask = extract_mask(cidr)
            
            if mask && mask < 24
              @warnings << "Policy '#{name}' allows broad CIDR #{mask}/16 in namespace #{ns}" unless @strictness_level == :very_strict
            end
          end
        end
      end
    end
    
    def analyze_egress(policy, name, ns)
      rules = policy['spec']['egress'] || []
      
      # Check for allow-all egress (common in air-gapped but verify intent)
      if rules.any? { |r| r['to'].any? { |t| t['ports']&.any? { |p| p['port'] == 'all' } } }
        @warnings << "Policy '#{name}' allows all egress ports in namespace #{ns}" unless @strictness_level == :very_strict
      end
      
      # Check for external internet access
      rules.each do |rule|
        if rule['to'].any? { |t| t['ipBlock']&.key?('cidr') }
          cidr = rule['to'][0]['ipBlock']['cidr']
          
          if cidr.start_with?('10.') || cidr.start_with?('172.16.') || cidr.start_with?('192.168.')
            # Internal network - good
          elsif !cidr.match?(/\A10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\./) && 
                 !['0.0.0.0/0', '::/0'].include?(cidr)
            @warnings << "Policy '#{name}' allows external access to #{cidr} in namespace #{ns}" unless @strictness_level == :very_strict
            
            # Check for common internet services
            if cidr.match?(/\A1\.|8\.8\./) || cidr.match?(/google/).to_s.include?('true')
              @warnings << "Policy '#{name}' allows Google DNS (#{cidr}) in namespace #{ns}" unless @strictness_level == :very_strict
            end
          end
        end
      end
    end
    
    def check_default_deny!(policy_doc, name, ns)
      # Check if this is a default deny policy
      if policy_doc['spec']['ingress']&.empty? && 
         policy_doc['spec']['egress']&.empty?
        
        @metrics[:policies_found] += 1
        
        # Verify it's actually denying by checking labels
        if policy_doc['metadata'].any? { |m| m.key?('labels') }
          labels = policy_doc['metadata']['labels'] || {}
          
          if labels.key?('app.kubernetes.io/name') && 
             (labels['app.kubernetes.io/name'] == 'default-deny' || 
              labels['app.kubernetes.io/name'] == 'deny-all')
            
            @metrics[:policies_found] += 1
            @reports << {
              name: 'DefaultDenyVerification',
              content: {
                namespace: ns,
                policy_name: name,
                status: :verified,
                message: "Default deny policy verified for #{name}"
              }
            }
          end
        end
      end
    end
    
    def analyze_resource(resource_doc, ns)
      kind = resource_doc['kind']
      
      # Check Service accounts for overly permissive automount
      if kind == 'ServiceAccount' && 
         !resource_doc['metadata'].any? { |m| m.key?('automountServiceAccountToken') }
        
        @warnings << "ServiceAccount '#{resource_doc['metadata']['name']}' may auto-mount tokens in #{ns}" unless @strictness_level == :very_strict
        
        # Check for default service account usage (implicit)
        if resource_doc['spec'].any? { |s| s.key?('automountServiceAccountToken') }
          token_setting = resource_doc['spec']['automountServiceAccountToken']
          
          if !token_setting.nil? && token_setting == true
            @warnings << "ServiceAccount '#{resource_doc['metadata']['name']}' explicitly auto-mounts tokens in #{ns}" unless @strictness_level == :very_strict
          end
        end
      end
      
      # Check for privileged containers (indicates potential need for PSP/PodSecurityPolicy)
      if kind == 'Deployment' || kind == 'StatefulSet' || kind == 'DaemonSet'
        check_privileged_containers(resource_doc, ns, kind)
      end
      
      # Check for host network access
      if resource_doc['spec'].any? { |s| s.key?('hostNetwork') } && 
         (resource_doc['spec']['template']['spec']&.key?('hostNetwork'))
        
        @warnings << "#{kind} '#{resource_doc['metadata']['name']}' uses hostNetwork in #{ns}" unless @strictness_level == :very_strict
        
        # Check for host PID namespace
        if resource_doc['spec']['template']['spec'].any? { |s| s.key?('hostPID') } && 
           (resource_doc['spec']['template']['spec'][0]['hostPID'] || false)
          
          @warnings << "#{kind} '#{resource_doc['metadata']['name']}' uses hostPID in #{ns}" unless @strictness_level == :very_strict
        end
      end
      
      # Check for privileged containers
      check_privileged_containers(resource_doc, ns, kind) if resource_doc['spec'].any? { |s| s.key?('template') }
    end
    
    def check_privileged_containers(doc, ns, kind)
      return unless doc['spec']&.key?('template') && 
                    doc['spec']['template']['spec']&.key?('containers')
      
      containers = doc['spec']['template']['spec']['containers']
      
      containers.each do |container|
        # Check for privileged mode
        if container.any? { |c| c.key?('privileged') } && 
           (container[0]['privileged'] || false)
          
          @warnings << "#{kind} '#{doc['metadata']['name']}' has privileged container in #{ns}" unless @strictness_level == :very_strict
        end
        
        # Check for host IPC namespace
        if container.any? { |c| c.key?('ipc') } && 
           (container[0]['ipc']&.key?('hostIPC'))
          
          @warnings << "#{kind} '#{doc['metadata']['name']}' shares host IPC in #{ns}" unless @strictness_level == :very_strict
        end
        
        # Check for root user
        if container.any? { |c| c.key?('user') } && 
           (container[0]['user']&.key?('uid'))
          
          uid = container[0]['user']['uid']
          
          if uid == 0 || uid.to_s == 'root'
            @warnings << "#{kind} '#{doc['metadata']['name']}' runs as root in #{ns}" unless @strictness_level == :very_strict
          end
        end
        
        # Check for capability escalation
        if container.any? { |c| c.key?('capabilities') } && 
           (container[0]['capabilities']&.key?('add'))
          
          caps = container[0]['capabilities']['add'] || []
          
          dangerous_caps = ['NET_ADMIN', 'SYS_ADMIN', 'SYS_PTRACE', 'DAC_OVERRIDE']
          
          dangerous_caps.each do |cap|
            if caps.include?(cap)
              @warnings << "#{kind} '#{doc['metadata']['name']}' adds #{cap} capability in #{ns}" unless @strictness_level == :very_strict
            end
          end
        end
      end
    end
    
    def generate_recommendations(namespace_map, policies_found)
      # Generate comprehensive recommendations
      
      # 1. Network Policy Coverage Analysis
      coverage = analyze_coverage(namespace_map)
      
      if coverage[:gaps].any?
        @warnings << "Network policy gaps detected in #{coverage[:namespaces_with_gaps]} namespaces" unless @strictness_level == :very_strict
        
        coverage[:gaps].each do |gap|
          @reports << {
            name: 'CoverageGap',
            content: {
              namespace: gap[:namespace],
              resource_type: gap[:type],
              recommendation: "Add NetworkPolicy for #{gap[:resource_name]}"
            }
          }
        end
      end
      
      # 2. Policy Effectiveness Score
      effectiveness = calculate_effectiveness(policies_found)
      
      if effectiveness < 80 && @strictness_level == :very_strict
        @warnings << "Network policy effectiveness: #{effectiveness}%" unless @strictness_level == :very_strict
        
        @reports << {
          name: 'EffectivenessScore',
          content: {
            score: effectiveness,
            recommendation: "Review and tighten policies to improve from #{effectiveness}% to 95%+"
          }
        }
      end
      
      # 3. Air-Gap Compliance Check
      air_gap_compliance = check_air_gap_compliance(policies_found)
      
      if !air_gap_compliance[:compliant]
        @warnings << "Air-gap compliance issues found" unless @strictness_level == :very_strict
        
        air_gap_compliance[:issues
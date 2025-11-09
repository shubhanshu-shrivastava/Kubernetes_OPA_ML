"""
OPA Policy Generation Engine
Generates OPA Gatekeeper Constraint YAMLs from detected security patterns
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class PolicyGenerator:
    """Generate OPA policies from detected patterns"""
    
    def __init__(self, gatekeeper_library_path='gatekeeper-library'):
        self.library_path = Path(gatekeeper_library_path)
        self.template_cache = {}
        
        # Pattern to template mapping
        self.pattern_templates = {
            'privileged_containers': 'library/pod-security-policy/privileged-containers',
            'missing_resource_limits': 'library/general/containerlimits',
            'host_namespaces': 'library/pod-security-policy/host-namespaces',
            'untrusted_registries': 'library/general/allowedrepos',
            'privilege_escalation': 'library/pod-security-policy/allow-privilege-escalation',
            'run_as_root': 'library/pod-security-policy/users',
            'dangerous_capabilities': 'library/pod-security-policy/capabilities'
        }
    
    def load_template(self, template_path: str) -> Dict:
        """Load ConstraintTemplate from gatekeeper-library"""
        if template_path in self.template_cache:
            return self.template_cache[template_path]
        
        template_file = self.library_path / template_path / 'template.yaml'
        
        if not template_file.exists():
            raise FileNotFoundError(f"Template not found: {template_file}")
        
        with open(template_file, 'r') as f:
            template = yaml.safe_load(f)
        
        self.template_cache[template_path] = template
        return template
    
    def generate_constraint_for_pattern(self, pattern: str, config: Dict = None) -> Dict:
        """Generate a Constraint YAML for a specific pattern"""
        if pattern not in self.pattern_templates:
            raise ValueError(f"Unknown pattern: {pattern}")
        
        template_path = self.pattern_templates[pattern]
        template = self.load_template(template_path)
        
        # Extract ConstraintTemplate kind
        constraint_kind = template['metadata']['name']
        
        # Build constraint based on pattern type
        constraint = {
            'apiVersion': 'constraints.gatekeeper.sh/v1beta1',
            'kind': constraint_kind,
            'metadata': {
                'name': f'generated-{pattern.replace("_", "-")}'
            },
            'spec': {
                'match': {
                    'kinds': [
                        {'apiGroups': [''], 'kinds': ['Pod']},
                        {'apiGroups': ['apps'], 'kinds': ['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet']}
                    ]
                }
            }
        }
        
        # Add pattern-specific parameters
        parameters = self._get_parameters_for_pattern(pattern, config)
        if parameters:
            constraint['spec']['parameters'] = parameters
        
        return constraint
    
    def _get_parameters_for_pattern(self, pattern: str, config: Dict = None) -> Dict:
        """Get parameters for specific pattern types"""
        params = {}
        
        if pattern == 'missing_resource_limits':
            params = {
                'cpu': '2',
                'memory': '2Gi'
            }
        
        elif pattern == 'untrusted_registries':
            params = {
                'repos': [
                    'gcr.io',
                    'registry.k8s.io',
                    'quay.io',
                    'docker.io/library',
                    'ghcr.io',
                    'mcr.microsoft.com'
                ]
            }
        
        elif pattern == 'dangerous_capabilities':
            params = {
                'requiredDropCapabilities': ['ALL'],
                'allowedCapabilities': ['CHOWN', 'DAC_OVERRIDE', 'FSETID', 'FOWNER']
            }
        
        elif pattern == 'run_as_root':
            params = {
                'runAsUser': {
                    'rule': 'MustRunAsNonRoot'
                }
            }
        
        return params
    
    def generate_policies_from_cluster(self, cluster_info: Dict) -> List[Dict]:
        """Generate policies for an entire cluster"""
        policies = []
        
        for policy_rec in cluster_info.get('recommended_policies', []):
            pattern = policy_rec['pattern']
            
            try:
                constraint = self.generate_constraint_for_pattern(pattern)
                policies.append({
                    'pattern': pattern,
                    'occurrences': policy_rec['occurrences'],
                    'template': policy_rec['template'],
                    'constraint': constraint
                })
            except Exception as e:
                print(f"Warning: Could not generate policy for {pattern}: {e}")
        
        return policies
    
    def generate_policies_from_config(self, yaml_config: str) -> List[Dict]:
        """Generate policies from a single YAML configuration"""
        # Parse YAML
        try:
            config = yaml.safe_load(yaml_config)
        except Exception as e:
            return [{'error': f'Invalid YAML: {e}'}]
        
        # Import pattern detector
        import sys
        sys.path.append('.')
        try:
            from pattern_detector import EnhancedSecurityAnalyzer as AnalyzerClass
        except ImportError:
            from pattern_detector import KubernetesSecurityAnalyzer as AnalyzerClass
        
        # Analyze config
        analyzer = AnalyzerClass()
        patterns = analyzer.analyze_config(config)
        
        if not patterns:
            return [{
                'message': 'No security issues detected - configuration appears secure!',
                'patterns': []
            }]
        
        # Generate policies for detected patterns
        policies = []
        seen_patterns = set()
        
        for pattern in patterns:
            pattern_type = pattern['pattern']
            
            # Avoid duplicate policies
            if pattern_type in seen_patterns:
                continue
            seen_patterns.add(pattern_type)
            
            try:
                constraint = self.generate_constraint_for_pattern(pattern_type, config)
                policies.append({
                    'pattern': pattern_type,
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'template': self.pattern_templates[pattern_type],
                    'constraint': constraint
                })
            except Exception as e:
                print(f"Warning: Could not generate policy for {pattern_type}: {e}")
        
        return policies
    
    def save_constraint_yaml(self, constraint: Dict, output_path: str):
        """Save constraint to YAML file"""
        with open(output_path, 'w') as f:
            yaml.dump(constraint, f, default_flow_style=False, sort_keys=False)
    
    def generate_policy_bundle(self, output_dir='generated_policies'):
        """Generate complete policy bundle from clustering results"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Load cluster results
        with open('cluster_results.json', 'r') as f:
            cluster_data = json.load(f)
        
        all_policies = []
        policy_summary = defaultdict(int)
        
        for cluster in cluster_data['clusters']:
            cluster_id = cluster['cluster_id']
            security_level = cluster['security_level']
            
            print(f"\nGenerating policies for Cluster {cluster_id} ({security_level})...")
            
            policies = self.generate_policies_from_cluster(cluster)
            
            if not policies:
                print(f"  No policies needed for Cluster {cluster_id}")
                continue
            
            # Save policies
            for i, policy in enumerate(policies):
                pattern = policy['pattern']
                constraint = policy['constraint']
                
                filename = f"cluster{cluster_id}_{pattern}.yaml"
                filepath = output_path / filename
                
                self.save_constraint_yaml(constraint, filepath)
                policy_summary[pattern] += 1
                
                all_policies.append({
                    'cluster_id': cluster_id,
                    'security_level': security_level,
                    'file': filename,
                    **policy
                })
                
                print(f"  ✓ Generated: {filename}")
        
        # Save policy summary
        summary = {
            'total_policies': len(all_policies),
            'policies_by_pattern': dict(policy_summary),
            'policies': all_policies
        }
        
        with open(output_path / 'policy_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n✅ Policy generation complete!")
        print(f"   - {len(all_policies)} policies generated")
        print(f"   - Saved to: {output_dir}/")
        
        return summary


def test_single_config():
    """Test with a sample insecure configuration"""
    test_config = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0
"""
    
    print("Testing with insecure configuration...\n")
    print("Input YAML:")
    print("-" * 70)
    print(test_config)
    print("-" * 70)
    
    generator = PolicyGenerator()
    policies = generator.generate_policies_from_config(test_config)
    
    print(f"\n✅ Generated {len(policies)} policies:\n")
    
    for i, policy in enumerate(policies, 1):
        if 'error' in policy:
            print(f"Error: {policy['error']}")
            continue
        
        if 'message' in policy:
            print(policy['message'])
            continue
        
        print(f"{i}. [{policy['severity']}] {policy['pattern']}")
        print(f"   Description: {policy['description']}")
        print(f"   Template: {policy['template']}")
        print(f"   Constraint Kind: {policy['constraint']['kind']}")
        print()
        
        # Show YAML
        constraint_yaml = yaml.dump(policy['constraint'], default_flow_style=False, sort_keys=False)
        print("   Generated Constraint YAML:")
        for line in constraint_yaml.split('\n'):
            print(f"   {line}")
        print()


def main():
    """Main policy generation function"""
    print("=" * 80)
    print("OPA POLICY GENERATION ENGINE")
    print("=" * 80)
    print()
    
    # Test with single config first
    test_single_config()
    
    # Generate full policy bundle
    print("\n" + "=" * 80)
    print("GENERATING COMPLETE POLICY BUNDLE FROM CLUSTERING RESULTS")
    print("=" * 80)
    
    generator = PolicyGenerator()
    summary = generator.generate_policy_bundle()
    
    print("\nPolicy Summary:")
    print("-" * 80)
    for pattern, count in summary['policies_by_pattern'].items():
        print(f"  - {pattern}: {count} policies")


if __name__ == "__main__":
    main()
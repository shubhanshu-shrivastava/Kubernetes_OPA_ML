"""
Enhanced Security Pattern Detector for Kubernetes Configurations
Comprehensive detection including RBAC, Deployments, ServiceAccounts, and more
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Tuple
from collections import Counter


class EnhancedSecurityAnalyzer:
    """Enhanced analyzer with comprehensive security checks"""
    
    def __init__(self):
        self.patterns_detected = []
        
    def load_samples(self, json_path: str) -> List[Dict]:
        """Load extracted gatekeeper samples"""
        with open(json_path, 'r') as f:
            return json.load(f)
    
    def extract_pod_spec(self, config: Dict) -> Dict:
        """Extract pod spec from various resource types"""
        if not config:
            return {}
        
        kind = config.get('kind', '')
        
        # Direct Pod
        if kind == 'Pod':
            return config.get('spec', {})
        
        # Deployment, StatefulSet, DaemonSet, ReplicaSet, Job
        if kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job']:
            return config.get('spec', {}).get('template', {}).get('spec', {})
        
        # CronJob
        if kind == 'CronJob':
            return config.get('spec', {}).get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
        
        return {}
    
    def extract_containers(self, pod_spec: Dict) -> List[Dict]:
        """Extract all containers from pod spec"""
        if not pod_spec:
            return []
        
        containers = []
        
        # Regular containers
        if 'containers' in pod_spec:
            containers.extend(pod_spec['containers'])
        
        # Init containers
        if 'initContainers' in pod_spec:
            containers.extend(pod_spec['initContainers'])
        
        # Ephemeral containers
        if 'ephemeralContainers' in pod_spec:
            containers.extend(pod_spec['ephemeralContainers'])
        
        return containers
    
    def detect_privileged_containers(self, config: Dict) -> Dict:
        """Detect privileged container usage"""
        pod_spec = self.extract_pod_spec(config)
        containers = self.extract_containers(pod_spec)
        privileged = []
        
        for container in containers:
            security_context = container.get('securityContext', {})
            if security_context.get('privileged', False):
                privileged.append(container.get('name', 'unknown'))
        
        if privileged:
            return {
                'pattern': 'privileged_containers',
                'severity': 'HIGH',
                'description': f'Privileged containers detected: {", ".join(privileged)}',
                'policy_template': 'library/pod-security-policy/privileged-containers',
                'containers': privileged
            }
        return None
    
    def detect_missing_resource_limits(self, config: Dict) -> Dict:
        """Detect containers without resource limits"""
        pod_spec = self.extract_pod_spec(config)
        containers = self.extract_containers(pod_spec)
        missing = []
        
        for container in containers:
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            
            if not limits or ('cpu' not in limits and 'memory' not in limits):
                missing.append(container.get('name', 'unknown'))
        
        if missing:
            return {
                'pattern': 'missing_resource_limits',
                'severity': 'MEDIUM',
                'description': f'Containers without resource limits: {", ".join(missing)}',
                'policy_template': 'library/general/containerlimits',
                'containers': missing
            }
        return None
    
    def detect_host_namespaces(self, config: Dict) -> Dict:
        """Detect host namespace usage"""
        pod_spec = self.extract_pod_spec(config)
        if not pod_spec:
            return None
        
        violations = []
        
        if pod_spec.get('hostNetwork', False):
            violations.append('hostNetwork')
        if pod_spec.get('hostPID', False):
            violations.append('hostPID')
        if pod_spec.get('hostIPC', False):
            violations.append('hostIPC')
        
        if violations:
            return {
                'pattern': 'host_namespaces',
                'severity': 'HIGH',
                'description': f'Host namespace usage: {", ".join(violations)}',
                'policy_template': 'library/pod-security-policy/host-namespaces',
                'namespaces': violations
            }
        return None
    
    def detect_untrusted_registries(self, config: Dict) -> Dict:
        """Detect images from untrusted registries"""
        pod_spec = self.extract_pod_spec(config)
        containers = self.extract_containers(pod_spec)
        trusted_registries = [
            'gcr.io',
            'registry.k8s.io',
            'quay.io',
            'docker.io/library',
            'ghcr.io',
            'mcr.microsoft.com'
        ]
        
        untrusted = []
        for container in containers:
            image = container.get('image', '')
            
            # Check if image uses a trusted registry
            is_trusted = any(image.startswith(reg) for reg in trusted_registries)
            
            # Check for 'latest' tag
            if ':latest' in image or ':' not in image:
                untrusted.append({
                    'name': container.get('name', 'unknown'),
                    'image': image,
                    'reason': 'uses latest tag or no tag'
                })
            elif not is_trusted:
                untrusted.append({
                    'name': container.get('name', 'unknown'),
                    'image': image,
                    'reason': 'untrusted registry'
                })
        
        if untrusted:
            return {
                'pattern': 'untrusted_registries',
                'severity': 'MEDIUM',
                'description': f'{len(untrusted)} container(s) with untrusted images',
                'policy_template': 'library/general/allowedrepos',
                'containers': untrusted
            }
        return None
    
    def detect_privilege_escalation(self, config: Dict) -> Dict:
        """Detect allowPrivilegeEscalation enabled"""
        pod_spec = self.extract_pod_spec(config)
        containers = self.extract_containers(pod_spec)
        violations = []
        
        for container in containers:
            security_context = container.get('securityContext', {})
            # Only flag if explicitly set to True (not if missing)
            if security_context.get('allowPrivilegeEscalation') is True:
                violations.append(container.get('name', 'unknown'))
        
        if violations:
            return {
                'pattern': 'privilege_escalation',
                'severity': 'HIGH',
                'description': f'Privilege escalation explicitly allowed: {", ".join(violations)}',
                'policy_template': 'library/pod-security-policy/allow-privilege-escalation',
                'containers': violations
            }
        return None
    
    def detect_run_as_root(self, config: Dict) -> Dict:
        """Detect containers running as root"""
        pod_spec = self.extract_pod_spec(config)
        if not pod_spec:
            return None
        
        containers = self.extract_containers(pod_spec)
        
        # Check pod-level security context
        pod_security = pod_spec.get('securityContext', {})
        run_as_non_root = pod_security.get('runAsNonRoot', False)
        pod_run_as_user = pod_security.get('runAsUser')
        
        if run_as_non_root or (pod_run_as_user and pod_run_as_user != 0):
            return None  # Pod enforces non-root
        
        violations = []
        for container in containers:
            security_context = container.get('securityContext', {})
            container_non_root = security_context.get('runAsNonRoot', False)
            run_as_user = security_context.get('runAsUser')
            
            # Flag if no explicit non-root setting
            if not container_non_root and (run_as_user is None or run_as_user == 0):
                violations.append(container.get('name', 'unknown'))
        
        if violations:
            return {
                'pattern': 'run_as_root',
                'severity': 'HIGH',
                'description': f'Containers may run as root (no runAsNonRoot set): {", ".join(violations)}',
                'policy_template': 'library/pod-security-policy/users',
                'containers': violations
            }
        return None
    
    def detect_capabilities_added(self, config: Dict) -> Dict:
        """Detect dangerous capabilities added"""
        pod_spec = self.extract_pod_spec(config)
        containers = self.extract_containers(pod_spec)
        dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE']
        violations = []
        
        for container in containers:
            security_context = container.get('securityContext', {})
            capabilities = security_context.get('capabilities', {})
            add_caps = capabilities.get('add', [])
            
            dangerous_found = [cap for cap in add_caps if cap in dangerous_caps]
            if dangerous_found:
                violations.append({
                    'container': container.get('name', 'unknown'),
                    'capabilities': dangerous_found
                })
        
        if violations:
            return {
                'pattern': 'dangerous_capabilities',
                'severity': 'HIGH',
                'description': f'{len(violations)} container(s) with dangerous capabilities',
                'policy_template': 'library/pod-security-policy/capabilities',
                'violations': violations
            }
        return None
    
    def detect_rbac_violations(self, config: Dict) -> Dict:
        """Detect RBAC security issues"""
        kind = config.get('kind', '')
        
        if kind not in ['ClusterRoleBinding', 'RoleBinding']:
            return None
        
        violations = []
        
        # Check if binding to cluster-admin
        role_ref = config.get('roleRef', {})
        if role_ref.get('name') == 'cluster-admin':
            subjects = config.get('subjects', [])
            for subject in subjects:
                if subject.get('name') == 'default':
                    violations.append('Binding default ServiceAccount to cluster-admin')
        
        # Check for overly permissive bindings
        if kind == 'ClusterRoleBinding':
            violations.append('ClusterRoleBinding grants cluster-wide permissions')
        
        if violations:
            return {
                'pattern': 'rbac_violations',
                'severity': 'CRITICAL',
                'description': '; '.join(violations),
                'policy_template': 'library/general/block-cluster-admin-role-binding',
                'violations': violations
            }
        return None
    
    def detect_serviceaccount_automount(self, config: Dict) -> Dict:
        """Detect ServiceAccount token auto-mounting"""
        kind = config.get('kind', '')
        
        # Check ServiceAccount definition
        if kind == 'ServiceAccount':
            automount = config.get('automountServiceAccountToken', True)
            if automount:
                return {
                    'pattern': 'serviceaccount_automount',
                    'severity': 'MEDIUM',
                    'description': 'ServiceAccount auto-mounts tokens (should be disabled unless needed)',
                    'policy_template': 'library/pod-security-policy/automount-serviceaccount-token',
                    'details': 'automountServiceAccountToken: true'
                }
        
        # Check Pod using ServiceAccount
        pod_spec = self.extract_pod_spec(config)
        if pod_spec:
            automount = pod_spec.get('automountServiceAccountToken', True)
            sa_name = pod_spec.get('serviceAccountName', 'default')
            
            if automount and sa_name == 'default':
                return {
                    'pattern': 'serviceaccount_automount',
                    'severity': 'MEDIUM',
                    'description': 'Pod uses default ServiceAccount with token auto-mount',
                    'policy_template': 'library/pod-security-policy/automount-serviceaccount-token',
                    'details': f'serviceAccountName: {sa_name}, automountServiceAccountToken: true'
                }
        
        return None
    
    def detect_hostpath_volumes(self, config: Dict) -> Dict:
        """Detect hostPath volume mounts"""
        pod_spec = self.extract_pod_spec(config)
        if not pod_spec:
            return None
        
        volumes = pod_spec.get('volumes', [])
        hostpaths = []
        
        for volume in volumes:
            if 'hostPath' in volume:
                path = volume['hostPath'].get('path', 'unknown')
                hostpaths.append({
                    'name': volume.get('name', 'unknown'),
                    'path': path
                })
        
        if hostpaths:
            critical_paths = ['/', '/etc', '/var', '/sys', '/proc']
            is_critical = any(hp['path'] in critical_paths or hp['path'].startswith('/etc') 
                            for hp in hostpaths)
            
            severity = 'CRITICAL' if is_critical else 'HIGH'
            
            return {
                'pattern': 'hostpath_volumes',
                'severity': severity,
                'description': f'{len(hostpaths)} hostPath volumes mounted',
                'policy_template': 'library/pod-security-policy/host-filesystem',
                'volumes': hostpaths
            }
        return None
    
    def analyze_config(self, config: Dict) -> List[Dict]:
        """Run all detectors on a single config"""
        detectors = [
            self.detect_privileged_containers,
            self.detect_missing_resource_limits,
            self.detect_host_namespaces,
            self.detect_untrusted_registries,
            self.detect_privilege_escalation,
            self.detect_run_as_root,
            self.detect_capabilities_added,
            self.detect_rbac_violations,
            self.detect_serviceaccount_automount,
            self.detect_hostpath_volumes
        ]
        
        patterns = []
        for detector in detectors:
            result = detector(config)
            if result:
                patterns.append(result)
        
        return patterns
    
    def analyze_dataset(self, samples: List[Dict]) -> Tuple[List[Dict], Dict]:
        """Analyze entire dataset and return patterns + statistics"""
        all_patterns = []
        stats = {
            'total_samples': len(samples),
            'allowed': 0,
            'disallowed': 0,
            'pattern_counts': Counter(),
            'severity_counts': Counter(),
            'policy_categories': Counter()
        }
        
        for sample in samples:
            # Update basic stats
            stats[sample['label']] += 1
            stats['policy_categories'][sample['category']] += 1
            
            # Analyze configuration
            patterns = self.analyze_config(sample.get('content'))
            
            for pattern in patterns:
                all_patterns.append({
                    'sample_file': sample['file'],
                    'policy': sample['policy'],
                    'label': sample['label'],
                    **pattern
                })
                stats['pattern_counts'][pattern['pattern']] += 1
                stats['severity_counts'][pattern['severity']] += 1
        
        return all_patterns, stats
    
    def generate_report(self, stats: Dict) -> str:
        """Generate analysis report"""
        report = []
        report.append("=" * 70)
        report.append("ENHANCED KUBERNETES SECURITY PATTERN ANALYSIS")
        report.append("=" * 70)
        report.append("")
        
        report.append(f"Total Samples Analyzed: {stats['total_samples']}")
        report.append(f"  - Allowed (compliant): {stats['allowed']}")
        report.append(f"  - Disallowed (violations): {stats['disallowed']}")
        report.append("")
        
        report.append("Security Patterns Detected:")
        for pattern, count in stats['pattern_counts'].most_common():
            report.append(f"  - {pattern}: {count} occurrences")
        report.append("")
        
        report.append("Severity Distribution:")
        for severity, count in stats['severity_counts'].most_common():
            report.append(f"  - {severity}: {count}")
        report.append("")
        
        report.append("=" * 70)
        
        return "\n".join(report)


def main():
    """Main analysis function"""
    print("Loading Kubernetes samples...")
    analyzer = EnhancedSecurityAnalyzer()
    samples = analyzer.load_samples('gatekeeper_samples.json')
    
    print(f"Analyzing {len(samples)} samples with enhanced detection...")
    patterns, stats = analyzer.analyze_dataset(samples)
    
    print("\n" + analyzer.generate_report(stats))
    
    # Save detailed patterns
    output_file = 'enhanced_detected_patterns.json'
    with open(output_file, 'w') as f:
        json.dump({
            'patterns': patterns,
            'statistics': {
                'total_samples': stats['total_samples'],
                'allowed': stats['allowed'],
                'disallowed': stats['disallowed'],
                'pattern_counts': dict(stats['pattern_counts']),
                'severity_counts': dict(stats['severity_counts']),
                'policy_categories': dict(stats['policy_categories'])
            }
        }, f, indent=2)
    
    print(f"\nDetailed patterns saved to: {output_file}")
    print(f"Total patterns detected: {len(patterns)}")


if __name__ == "__main__":
    main()
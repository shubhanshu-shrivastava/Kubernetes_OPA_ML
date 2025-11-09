"""
Evaluation Framework - Benchmark Against Real Kubernetes Vulnerabilities
Tests detection accuracy on known insecure configurations
"""

import json
import yaml
from pathlib import Path
from pattern_detector import EnhancedSecurityAnalyzer
from policy_generator import PolicyGenerator


class SecurityEvaluationFramework:
    """Evaluate security detection against known vulnerabilities"""
    
    def __init__(self):
        self.analyzer = EnhancedSecurityAnalyzer()
        self.generator = PolicyGenerator()
        self.test_cases = []
        
    def create_vulnerability_test_suite(self):
        """Create comprehensive test suite of vulnerable configs"""
        
        # Test Case 1: Privileged container with host access
        self.test_cases.append({
            'name': 'Privileged Container with HostPath',
            'severity': 'CRITICAL',
            'expected_patterns': ['privileged_containers', 'hostpath_volumes', 
                                'run_as_root', 'privilege_escalation'],
            'cve_reference': 'CVE-2019-5736 (runc escape)',
            'config': """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-hostpath
spec:
  containers:
  - name: attacker
    image: ubuntu:24.04
    command: ["/bin/bash", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
"""
        })
        
        # Test Case 2: Host network with hostPID
        self.test_cases.append({
            'name': 'Host Network + PID Namespace Escape',
            'severity': 'HIGH',
            'expected_patterns': ['host_namespaces', 'missing_resource_limits'],
            'cve_reference': 'Container escape via host namespaces',
            'config': """
apiVersion: v1
kind: Pod
metadata:
  name: host-network-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: netprobe
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
"""
        })
        
        # Test Case 3: Dangerous capabilities
        self.test_cases.append({
            'name': 'SYS_ADMIN Capability (Container Breakout)',
            'severity': 'CRITICAL',
            'expected_patterns': ['dangerous_capabilities', 'run_as_root'],
            'cve_reference': 'CAP_SYS_ADMIN exploitation',
            'config': """
apiVersion: v1
kind: Pod
metadata:
  name: cap-sys-admin
spec:
  containers:
  - name: dangerous
    image: alpine:3.18
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
"""
        })
        
        # Test Case 4: Deployment running as root without limits
        self.test_cases.append({
            'name': 'Deployment - Root User No Limits',
            'severity': 'MEDIUM',
            'expected_patterns': ['run_as_root', 'missing_resource_limits', 
                                'untrusted_registries'],
            'cve_reference': 'Resource exhaustion + privilege escalation',
            'config': """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      containers:
      - name: app
        image: alpine:3.18
        command: ["/bin/sh", "-c", "sleep 3600"]
"""
        })
        
        # Test Case 5: CronJob with hostPath
        self.test_cases.append({
            'name': 'CronJob with Host Filesystem Access',
            'severity': 'HIGH',
            'expected_patterns': ['hostpath_volumes', 'privilege_escalation', 
                                'run_as_root'],
            'cve_reference': 'Scheduled persistence mechanism',
            'config': """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: malicious-cron
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: shell
            image: alpine:3.18
            command: ["/bin/sh", "-c", "echo pwned > /host/pwned.txt"]
            securityContext:
              allowPrivilegeEscalation: true
            volumeMounts:
            - name: host-fs
              mountPath: /host
          volumes:
          - name: host-fs
            hostPath:
              path: /tmp
              type: Directory
"""
        })
        
        # Test Case 6: ClusterRoleBinding to cluster-admin
        self.test_cases.append({
            'name': 'Default SA with cluster-admin',
            'severity': 'CRITICAL',
            'expected_patterns': ['rbac_violations'],
            'cve_reference': 'RBAC privilege escalation',
            'config': """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
"""
        })
        
        # Test Case 7: ServiceAccount auto-mount
        self.test_cases.append({
            'name': 'Default ServiceAccount Token Exposure',
            'severity': 'MEDIUM',
            'expected_patterns': ['serviceaccount_automount'],
            'cve_reference': 'Token theft and lateral movement',
            'config': """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: exposed-sa
automountServiceAccountToken: true
---
apiVersion: v1
kind: Pod
metadata:
  name: token-exposure
spec:
  serviceAccountName: exposed-sa
  automountServiceAccountToken: true
  containers:
  - name: app
    image: alpine:3.18
    command: ["sleep", "3600"]
"""
        })
        
        # Test Case 8: Secure baseline (should detect minimal issues)
        self.test_cases.append({
            'name': 'Secure Baseline Configuration',
            'severity': 'LOW',
            'expected_patterns': [],  # Should detect few/no issues
            'cve_reference': 'Best practices baseline',
            'config': """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: gcr.io/google-samples/nginx:1.21
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "250m"
        memory: "256Mi"
"""
        })
        
        return self.test_cases
    
    def evaluate_test_case(self, test_case):
        """Evaluate detection on a single test case"""
        try:
            # Parse YAML (handle multi-document)
            configs = list(yaml.safe_load_all(test_case['config']))
            
            all_patterns = []
            for config in configs:
                if config:  # Skip empty documents
                    patterns = self.analyzer.analyze_config(config)
                    all_patterns.extend(patterns)
            
            # Extract detected pattern types
            detected_patterns = set(p['pattern'] for p in all_patterns)
            expected_patterns = set(test_case['expected_patterns'])
            
            # Calculate metrics
            true_positives = len(detected_patterns & expected_patterns)
            false_negatives = len(expected_patterns - detected_patterns)
            false_positives = len(detected_patterns - expected_patterns)
            
            # Determine if critical patterns were detected
            severity = test_case['severity']
            detected_correctly = true_positives > 0 if expected_patterns else len(all_patterns) == 0
            
            return {
                'name': test_case['name'],
                'severity': severity,
                'expected_patterns': list(expected_patterns),
                'detected_patterns': list(detected_patterns),
                'patterns_detail': all_patterns,
                'true_positives': true_positives,
                'false_negatives': false_negatives,
                'false_positives': false_positives,
                'detection_success': detected_correctly,
                'cve_reference': test_case['cve_reference']
            }
            
        except Exception as e:
            return {
                'name': test_case['name'],
                'error': str(e)
            }
    
    def run_full_evaluation(self):
        """Run complete evaluation suite"""
        print("=" * 80)
        print("SECURITY DETECTION EVALUATION")
        print("=" * 80)
        print()
        
        # Create test suite
        print("Creating vulnerability test suite...")
        test_cases = self.create_vulnerability_test_suite()
        print(f"Created {len(test_cases)} test cases\n")
        
        # Run evaluation
        results = []
        for i, test_case in enumerate(test_cases, 1):
            print(f"[{i}/{len(test_cases)}] Testing: {test_case['name']}")
            result = self.evaluate_test_case(test_case)
            results.append(result)
            
            if 'error' in result:
                print(f"  ❌ Error: {result['error']}")
            else:
                status = "✅" if result['detection_success'] else "⚠️"
                print(f"  {status} Detected {len(result['detected_patterns'])} patterns")
                print(f"     Expected: {result['expected_patterns'][:3]}...")
                print(f"     Found: {result['detected_patterns'][:3]}...")
            print()
        
        return results
    
    def generate_evaluation_report(self, results):
        """Generate comprehensive evaluation report"""
        print("\n" + "=" * 80)
        print("EVALUATION RESULTS SUMMARY")
        print("=" * 80)
        print()
        
        # Overall metrics
        total_tests = len(results)
        successful_detections = sum(1 for r in results if r.get('detection_success', False))
        
        total_tp = sum(r.get('true_positives', 0) for r in results)
        total_fn = sum(r.get('false_negatives', 0) for r in results)
        total_fp = sum(r.get('false_positives', 0) for r in results)
        
        # Calculate metrics
        detection_rate = successful_detections / total_tests if total_tests > 0 else 0
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"Total Test Cases: {total_tests}")
        print(f"Successful Detections: {successful_detections} ({detection_rate:.1%})")
        print(f"\nPattern Detection Metrics:")
        print(f"  True Positives: {total_tp}")
        print(f"  False Negatives: {total_fn}")
        print(f"  False Positives: {total_fp}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall: {recall:.3f}")
        print(f"  F1-Score: {f1_score:.3f}")
        
        # Severity breakdown
        print(f"\nDetection by Severity:")
        severity_stats = {}
        for result in results:
            severity = result.get('severity', 'UNKNOWN')
            if severity not in severity_stats:
                severity_stats[severity] = {'total': 0, 'detected': 0}
            severity_stats[severity]['total'] += 1
            if result.get('detection_success', False):
                severity_stats[severity]['detected'] += 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_stats:
                stats = severity_stats[severity]
                rate = stats['detected'] / stats['total'] if stats['total'] > 0 else 0
                print(f"  {severity}: {stats['detected']}/{stats['total']} ({rate:.1%})")
        
        # Detailed results
        print(f"\nDetailed Test Results:")
        print("-" * 80)
        for result in results:
            if 'error' in result:
                print(f"❌ {result['name']}: ERROR - {result['error']}")
            else:
                status = "✅" if result['detection_success'] else "⚠️"
                print(f"{status} {result['name']} [{result['severity']}]")
                print(f"   CVE: {result['cve_reference']}")
                print(f"   Expected: {len(result['expected_patterns'])} patterns")
                print(f"   Detected: {len(result['detected_patterns'])} patterns")
                if result['false_negatives'] > 0:
                    missed = set(result['expected_patterns']) - set(result['detected_patterns'])
                    print(f"   Missed: {list(missed)}")
                print()
        
        return {
            'total_tests': total_tests,
            'successful_detections': successful_detections,
            'detection_rate': detection_rate,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'severity_breakdown': severity_stats,
            'detailed_results': results
        }
    
    def save_evaluation_results(self, report, output_path='evaluation_results.json'):
        """Save evaluation results to JSON"""
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nEvaluation results saved to: {output_path}")


def main():
    """Main evaluation pipeline"""
    print("=" * 80)
    print("KUBERNETES SECURITY DETECTION EVALUATION FRAMEWORK")
    print("=" * 80)
    print()
    
    # Initialize evaluator
    evaluator = SecurityEvaluationFramework()
    
    # Run evaluation
    results = evaluator.run_full_evaluation()
    
    # Generate report
    report = evaluator.generate_evaluation_report(results)
    
    # Save results
    evaluator.save_evaluation_results(report)
    
    print("\n" + "=" * 80)
    print("✅ EVALUATION COMPLETE!")
    print("=" * 80)
    print(f"\nKey Findings:")
    print(f"  - Detection Rate: {report['detection_rate']:.1%}")
    print(f"  - Precision: {report['precision']:.3f}")
    print(f"  - Recall: {report['recall']:.3f}")
    print(f"  - F1-Score: {report['f1_score']:.3f}")


if __name__ == "__main__":
    main()
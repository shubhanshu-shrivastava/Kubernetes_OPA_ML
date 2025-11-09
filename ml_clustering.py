"""
ML-Based Kubernetes Configuration Clustering
Groups configurations by security patterns and recommends policies
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import MiniBatchKMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from collections import Counter, defaultdict


class SecurityClusterer:
    """Cluster Kubernetes configs by security patterns"""
    
    def __init__(self, n_clusters=5):
        self.n_clusters = n_clusters
        self.kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=42, batch_size=100)
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=2)
        
    def load_data(self, samples_path='gatekeeper_samples.json', 
                  patterns_path='detected_patterns.json'):
        """Load samples and detected patterns"""
        with open(samples_path, 'r') as f:
            self.samples = json.load(f)
        
        with open(patterns_path, 'r') as f:
            patterns_data = json.load(f)
            self.patterns = patterns_data['patterns']
            self.statistics = patterns_data['statistics']
        
        print(f"Loaded {len(self.samples)} samples with {len(self.patterns)} patterns")
    
    def extract_features(self):
        """Extract numerical features from each sample"""
        features = []
        self.sample_metadata = []
        
        # Create pattern lookup by sample file
        pattern_by_file = defaultdict(list)
        for pattern in self.patterns:
            pattern_by_file[pattern['sample_file']].append(pattern)
        
        for sample in self.samples:
            sample_patterns = pattern_by_file.get(sample['file'], [])
            
            # Count patterns by type
            pattern_counts = Counter(p['pattern'] for p in sample_patterns)
            severity_counts = Counter(p['severity'] for p in sample_patterns)
            
            # Binary: is this allowed or disallowed?
            is_compliant = 1 if sample['label'] == 'allowed' else 0
            
            # Feature vector (12 features)
            feature_vector = [
                is_compliant,
                len(sample_patterns),  # Total patterns
                severity_counts.get('HIGH', 0),
                severity_counts.get('MEDIUM', 0),
                severity_counts.get('LOW', 0),
                pattern_counts.get('privileged_containers', 0),
                pattern_counts.get('missing_resource_limits', 0),
                pattern_counts.get('host_namespaces', 0),
                pattern_counts.get('untrusted_registries', 0),
                pattern_counts.get('privilege_escalation', 0),
                pattern_counts.get('run_as_root', 0),
                pattern_counts.get('dangerous_capabilities', 0)
            ]
            
            features.append(feature_vector)
            self.sample_metadata.append({
                'file': sample['file'],
                'policy': sample['policy'],
                'category': sample['category'],
                'label': sample['label'],
                'patterns': sample_patterns
            })
        
        return np.array(features)
    
    def cluster_configurations(self):
        """Perform clustering on extracted features"""
        print("Extracting features...")
        X = self.extract_features()
        
        print(f"Feature matrix shape: {X.shape}")
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Perform clustering
        print(f"Clustering into {self.n_clusters} groups...")
        self.labels = self.kmeans.fit_predict(X_scaled)
        
        # PCA for visualization
        self.X_pca = self.pca.fit_transform(X_scaled)
        
        print(f"Clustering complete. Explained variance: {self.pca.explained_variance_ratio_.sum():.2%}")
        
        return self.labels
    
    def analyze_clusters(self):
        """Analyze characteristics of each cluster"""
        cluster_info = []
        
        for cluster_id in range(self.n_clusters):
            # Get samples in this cluster
            cluster_mask = self.labels == cluster_id
            cluster_samples = [meta for i, meta in enumerate(self.sample_metadata) if cluster_mask[i]]
            
            # Aggregate statistics
            total = len(cluster_samples)
            compliant = sum(1 for s in cluster_samples if s['label'] == 'allowed')
            
            # Count patterns
            all_patterns = []
            for sample in cluster_samples:
                all_patterns.extend(sample['patterns'])
            
            pattern_counts = Counter(p['pattern'] for p in all_patterns)
            severity_counts = Counter(p['severity'] for p in all_patterns)
            policy_counts = Counter(s['policy'] for s in cluster_samples)
            
            # Determine cluster security level
            avg_patterns = len(all_patterns) / max(total, 1)
            high_severity = severity_counts.get('HIGH', 0)
            
            if avg_patterns < 2 or compliant / max(total, 1) > 0.8:
                security_level = "SECURE"
            elif high_severity > 5 or avg_patterns > 4:
                security_level = "HIGH RISK"
            else:
                security_level = "MODERATE RISK"
            
            cluster_info.append({
                'cluster_id': cluster_id,
                'size': total,
                'compliant_ratio': compliant / max(total, 1),
                'avg_patterns_per_config': avg_patterns,
                'security_level': security_level,
                'top_patterns': pattern_counts.most_common(3),
                'severity_distribution': dict(severity_counts),
                'top_policies': policy_counts.most_common(3),
                'sample_files': [s['file'] for s in cluster_samples[:3]]  # First 3 examples
            })
        
        return cluster_info
    
    def recommend_policies(self, cluster_info):
        """Recommend policy templates for each cluster"""
        policy_mapping = {
            'privileged_containers': 'library/pod-security-policy/privileged-containers',
            'missing_resource_limits': 'library/general/containerlimits',
            'host_namespaces': 'library/pod-security-policy/host-namespaces',
            'untrusted_registries': 'library/general/allowedrepos',
            'privilege_escalation': 'library/pod-security-policy/allow-privilege-escalation',
            'run_as_root': 'library/pod-security-policy/users',
            'dangerous_capabilities': 'library/pod-security-policy/capabilities'
        }
        
        for cluster in cluster_info:
            recommended = []
            for pattern_name, count in cluster['top_patterns']:
                if pattern_name in policy_mapping:
                    recommended.append({
                        'pattern': pattern_name,
                        'occurrences': count,
                        'template': policy_mapping[pattern_name]
                    })
            cluster['recommended_policies'] = recommended
        
        return cluster_info
    
    def visualize_clusters(self, cluster_info, save_path='cluster_visualization.png'):
        """Create visualization of clusters"""
        plt.figure(figsize=(14, 6))
        
        # Subplot 1: Cluster scatter plot
        plt.subplot(1, 2, 1)
        scatter = plt.scatter(
            self.X_pca[:, 0], 
            self.X_pca[:, 1], 
            c=self.labels, 
            cmap='viridis', 
            alpha=0.6,
            s=50
        )
        plt.colorbar(scatter, label='Cluster')
        plt.xlabel(f'PC1 ({self.pca.explained_variance_ratio_[0]:.1%})')
        plt.ylabel(f'PC2 ({self.pca.explained_variance_ratio_[1]:.1%})')
        plt.title('Kubernetes Configuration Clusters\n(by Security Patterns)')
        plt.grid(True, alpha=0.3)
        
        # Add cluster centers
        centers_pca = self.pca.transform(self.scaler.transform(self.kmeans.cluster_centers_))
        plt.scatter(centers_pca[:, 0], centers_pca[:, 1], 
                   c='red', marker='X', s=200, edgecolors='black', linewidths=2,
                   label='Cluster Centers')
        plt.legend()
        
        # Subplot 2: Cluster security levels
        plt.subplot(1, 2, 2)
        security_levels = [c['security_level'] for c in cluster_info]
        sizes = [c['size'] for c in cluster_info]
        
        level_colors = {
            'SECURE': 'green',
            'MODERATE RISK': 'orange',
            'HIGH RISK': 'red'
        }
        colors = [level_colors[level] for level in security_levels]
        
        bars = plt.bar(range(len(cluster_info)), sizes, color=colors, alpha=0.7, edgecolor='black')
        plt.xlabel('Cluster ID')
        plt.ylabel('Number of Configurations')
        plt.title('Cluster Sizes by Security Level')
        plt.xticks(range(len(cluster_info)))
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=color, label=level) 
                          for level, color in level_colors.items()]
        plt.legend(handles=legend_elements, loc='upper right')
        
        # Add value labels on bars
        for i, (bar, size) in enumerate(zip(bars, sizes)):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{size}\n{security_levels[i]}',
                    ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Visualization saved to: {save_path}")
        plt.close()
    
    def generate_report(self, cluster_info):
        """Generate detailed clustering report"""
        report = []
        report.append("=" * 80)
        report.append("ML-BASED SECURITY CLUSTERING REPORT")
        report.append("=" * 80)
        report.append("")
        
        for cluster in cluster_info:
            report.append(f"CLUSTER {cluster['cluster_id']}: {cluster['security_level']}")
            report.append("-" * 80)
            report.append(f"Size: {cluster['size']} configurations")
            report.append(f"Compliant: {cluster['compliant_ratio']:.1%}")
            report.append(f"Avg Patterns per Config: {cluster['avg_patterns_per_config']:.1f}")
            report.append("")
            
            report.append("Top Security Patterns:")
            for pattern, count in cluster['top_patterns']:
                report.append(f"  - {pattern}: {count} occurrences")
            report.append("")
            
            report.append("Severity Distribution:")
            for severity, count in cluster['severity_distribution'].items():
                report.append(f"  - {severity}: {count}")
            report.append("")
            
            report.append("Recommended OPA Policies:")
            for policy in cluster['recommended_policies']:
                report.append(f"  - {policy['pattern']}: {policy['template']}")
                report.append(f"    (addresses {policy['occurrences']} occurrences)")
            report.append("")
            
            report.append("Example Configurations:")
            for file in cluster['sample_files'][:2]:
                report.append(f"  - {file}")
            report.append("")
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results(self, cluster_info, output_path='cluster_results.json'):
        """Save clustering results to JSON"""
        results = {
            'n_clusters': self.n_clusters,
            'total_samples': len(self.samples),
            'clusters': cluster_info,
            'model_info': {
                'algorithm': 'MiniBatchKMeans',
                'n_features': 12,
                'explained_variance': float(self.pca.explained_variance_ratio_.sum())
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Cluster results saved to: {output_path}")


def main():
    """Main clustering pipeline"""
    print("Starting ML-based security clustering...\n")
    
    # Initialize clusterer
    clusterer = SecurityClusterer(n_clusters=5)
    
    # Load data
    clusterer.load_data()
    
    # Perform clustering
    clusterer.cluster_configurations()
    
    # Analyze clusters
    print("\nAnalyzing clusters...")
    cluster_info = clusterer.analyze_clusters()
    
    # Add policy recommendations
    print("Generating policy recommendations...")
    cluster_info = clusterer.recommend_policies(cluster_info)
    
    # Generate report
    report = clusterer.generate_report(cluster_info)
    print("\n" + report)
    
    # Save results
    clusterer.save_results(cluster_info)
    
    # Create visualization
    print("Creating visualization...")
    clusterer.visualize_clusters(cluster_info)
    
    print("\n✅ Clustering complete!")
    print(f"   - {clusterer.n_clusters} clusters identified")
    print(f"   - Results saved to cluster_results.json")
    print(f"   - Visualization saved to cluster_visualization.png")


if __name__ == "__main__":
    main()
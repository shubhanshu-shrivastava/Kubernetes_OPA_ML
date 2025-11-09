"""
Supervised ML Classifier for Kubernetes Security Risk Assessment
Uses Random Forest to predict security compliance and risk levels
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix, 
                             accuracy_score, precision_recall_fscore_support,
                             roc_curve, auc, roc_auc_score)
from sklearn.preprocessing import StandardScaler, label_binarize
from collections import Counter, defaultdict
import pickle


class SecurityRiskClassifier:
    """Supervised classifier for security risk prediction"""
    
    def __init__(self, n_estimators=100, random_state=42):
        self.classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=10,
            min_samples_split=5,
            random_state=random_state,
            n_jobs=-1  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.feature_names = []
        
    def load_data(self, samples_path='gatekeeper_samples.json', 
                  patterns_path='detected_patterns.json'):
        """Load samples and detected patterns"""
        with open(samples_path, 'r') as f:
            self.samples = json.load(f)
        
        with open(patterns_path, 'r') as f:
            patterns_data = json.load(f)
            self.patterns = patterns_data['patterns']
        
        print(f"Loaded {len(self.samples)} samples with {len(self.patterns)} patterns")
    
    def extract_features(self):
        """Extract comprehensive feature set for classification"""
        features = []
        labels = []
        self.sample_metadata = []
        
        # Create pattern lookup by sample file
        pattern_by_file = defaultdict(list)
        for pattern in self.patterns:
            pattern_by_file[pattern['sample_file']].append(pattern)
        
        # Define feature names
        self.feature_names = [
            'total_patterns',
            'high_severity_count',
            'medium_severity_count',
            'low_severity_count',
            'critical_severity_count',
            'privileged_containers',
            'missing_resource_limits',
            'host_namespaces',
            'untrusted_registries',
            'privilege_escalation',
            'run_as_root',
            'dangerous_capabilities',
            'rbac_violations',
            'serviceaccount_automount',
            'hostpath_volumes',
            'has_security_context',
            'severity_ratio',  # high / total
            'pattern_diversity'  # unique pattern types
        ]
        
        for sample in self.samples:
            sample_patterns = pattern_by_file.get(sample['file'], [])
            
            # Count patterns by type
            pattern_counts = Counter(p['pattern'] for p in sample_patterns)
            severity_counts = Counter(p['severity'] for p in sample_patterns)
            
            # Calculate derived features
            total_patterns = len(sample_patterns)
            high_count = severity_counts.get('HIGH', 0)
            severity_ratio = high_count / max(total_patterns, 1)
            pattern_diversity = len(set(p['pattern'] for p in sample_patterns))
            
            # Binary label: 1 = compliant (allowed), 0 = non-compliant (disallowed)
            label = 1 if sample['label'] == 'allowed' else 0
            
            # Check if has any security context
            has_security_context = int(any(
                'security' in str(p.get('description', '')).lower() 
                for p in sample_patterns
            ))
            
            # Feature vector (18 features)
            feature_vector = [
                total_patterns,
                high_count,
                severity_counts.get('MEDIUM', 0),
                severity_counts.get('LOW', 0),
                severity_counts.get('CRITICAL', 0),
                pattern_counts.get('privileged_containers', 0),
                pattern_counts.get('missing_resource_limits', 0),
                pattern_counts.get('host_namespaces', 0),
                pattern_counts.get('untrusted_registries', 0),
                pattern_counts.get('privilege_escalation', 0),
                pattern_counts.get('run_as_root', 0),
                pattern_counts.get('dangerous_capabilities', 0),
                pattern_counts.get('rbac_violations', 0),
                pattern_counts.get('serviceaccount_automount', 0),
                pattern_counts.get('hostpath_volumes', 0),
                has_security_context,
                severity_ratio,
                pattern_diversity
            ]
            
            features.append(feature_vector)
            labels.append(label)
            
            self.sample_metadata.append({
                'file': sample['file'],
                'policy': sample['policy'],
                'category': sample['category'],
                'label': sample['label'],
                'patterns': sample_patterns
            })
        
        return np.array(features), np.array(labels)
    
    def train_classifier(self, test_size=0.25):
        """Train Random Forest classifier with train/test split"""
        print("Extracting features...")
        X, y = self.extract_features()
        
        print(f"Feature matrix shape: {X.shape}")
        print(f"Class distribution: {Counter(y)}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nTrain set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train classifier
        print("\nTraining Random Forest classifier...")
        self.classifier.fit(X_train_scaled, y_train)
        
        # Predictions
        y_train_pred = self.classifier.predict(X_train_scaled)
        y_test_pred = self.classifier.predict(X_test_scaled)
        
        # Store for evaluation
        self.X_train = X_train_scaled
        self.X_test = X_test_scaled
        self.y_train = y_train
        self.y_test = y_test
        self.y_train_pred = y_train_pred
        self.y_test_pred = y_test_pred
        
        # Cross-validation
        print("\nPerforming 5-fold cross-validation...")
        cv_scores = cross_val_score(
            self.classifier, X_train_scaled, y_train, cv=5, scoring='accuracy'
        )
        
        self.cv_scores = cv_scores
        
        print(f"CV Accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
        
        return {
            'train_accuracy': accuracy_score(y_train, y_train_pred),
            'test_accuracy': accuracy_score(y_test, y_test_pred),
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std()
        }
    
    def evaluate_classifier(self):
        """Comprehensive evaluation of classifier performance"""
        print("\n" + "=" * 80)
        print("CLASSIFICATION EVALUATION REPORT")
        print("=" * 80)
        
        # Training set performance
        train_acc = accuracy_score(self.y_train, self.y_train_pred)
        print(f"\nTraining Set Accuracy: {train_acc:.3f}")
        
        # Test set performance
        test_acc = accuracy_score(self.y_test, self.y_test_pred)
        print(f"Test Set Accuracy: {test_acc:.3f}")
        
        # Classification report
        print("\nClassification Report (Test Set):")
        print(classification_report(
            self.y_test, 
            self.y_test_pred,
            target_names=['Non-Compliant', 'Compliant']
        ))
        
        # Detailed metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            self.y_test, self.y_test_pred, average=None
        )
        
        metrics = {
            'train_accuracy': train_acc,
            'test_accuracy': test_acc,
            'cv_mean': self.cv_scores.mean(),
            'cv_std': self.cv_scores.std(),
            'precision_non_compliant': precision[0],
            'recall_non_compliant': recall[0],
            'f1_non_compliant': f1[0],
            'precision_compliant': precision[1],
            'recall_compliant': recall[1],
            'f1_compliant': f1[1],
            'confusion_matrix': confusion_matrix(self.y_test, self.y_test_pred).tolist()
        }
        
        return metrics
    
    def feature_importance_analysis(self):
        """Analyze feature importance"""
        importances = self.classifier.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\n" + "=" * 80)
        print("FEATURE IMPORTANCE ANALYSIS")
        print("=" * 80)
        print("\nTop 10 Most Important Features:")
        
        feature_importance = []
        for i in range(min(10, len(self.feature_names))):
            idx = indices[i]
            importance = importances[idx]
            feature_name = self.feature_names[idx]
            print(f"{i+1}. {feature_name}: {importance:.4f}")
            feature_importance.append({
                'rank': i + 1,
                'feature': feature_name,
                'importance': float(importance)
            })
        
        return feature_importance
    
    def visualize_results(self, save_dir='ml_evaluation'):
        """Create comprehensive visualizations"""
        import os
        os.makedirs(save_dir, exist_ok=True)
        
        # 1. Confusion Matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(self.y_test, self.y_test_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Non-Compliant', 'Compliant'],
                   yticklabels=['Non-Compliant', 'Compliant'])
        plt.title('Confusion Matrix - Security Risk Classification')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(f'{save_dir}/confusion_matrix.png', dpi=300)
        plt.close()
        
        # 2. Feature Importance
        plt.figure(figsize=(10, 6))
        importances = self.classifier.feature_importances_
        indices = np.argsort(importances)[::-1][:10]
        
        plt.bar(range(10), importances[indices])
        plt.xticks(range(10), [self.feature_names[i] for i in indices], rotation=45, ha='right')
        plt.xlabel('Features')
        plt.ylabel('Importance')
        plt.title('Top 10 Feature Importance - Random Forest')
        plt.tight_layout()
        plt.savefig(f'{save_dir}/feature_importance.png', dpi=300)
        plt.close()
        
        # 3. ROC Curve
        plt.figure(figsize=(8, 6))
        y_pred_proba = self.classifier.predict_proba(self.X_test)[:, 1]
        fpr, tpr, _ = roc_curve(self.y_test, y_pred_proba)
        roc_auc = auc(fpr, tpr)
        
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve - Security Compliance Classifier')
        plt.legend(loc="lower right")
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(f'{save_dir}/roc_curve.png', dpi=300)
        plt.close()
        
        # 4. Cross-Validation Scores
        plt.figure(figsize=(8, 5))
        plt.bar(range(1, 6), self.cv_scores)
        plt.axhline(y=self.cv_scores.mean(), color='r', linestyle='--', 
                   label=f'Mean: {self.cv_scores.mean():.3f}')
        plt.xlabel('Fold')
        plt.ylabel('Accuracy')
        plt.title('5-Fold Cross-Validation Scores')
        plt.ylim([0.7, 1.0])
        plt.legend()
        plt.grid(alpha=0.3, axis='y')
        plt.tight_layout()
        plt.savefig(f'{save_dir}/cv_scores.png', dpi=300)
        plt.close()
        
        print(f"\n✅ Visualizations saved to {save_dir}/")
    
    def save_model(self, model_path='trained_classifier.pkl'):
        """Save trained model and scaler"""
        model_data = {
            'classifier': self.classifier,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Model saved to: {model_path}")
    
    def predict_risk_level(self, config_features):
        """Predict risk level for new configuration"""
        # Scale features
        features_scaled = self.scaler.transform([config_features])
        
        # Predict
        prediction = self.classifier.predict(features_scaled)[0]
        probability = self.classifier.predict_proba(features_scaled)[0]
        
        # Map to risk levels
        if prediction == 1:
            if probability[1] > 0.9:
                risk_level = "SECURE"
            else:
                risk_level = "LOW RISK"
        else:
            if probability[0] > 0.8:
                risk_level = "HIGH RISK"
            else:
                risk_level = "MODERATE RISK"
        
        return {
            'compliant': bool(prediction),
            'risk_level': risk_level,
            'confidence': float(max(probability)),
            'probability_compliant': float(probability[1]),
            'probability_non_compliant': float(probability[0])
        }


def main():
    """Main training and evaluation pipeline"""
    print("=" * 80)
    print("SUPERVISED ML CLASSIFIER FOR SECURITY RISK ASSESSMENT")
    print("=" * 80)
    print()
    
    # Initialize classifier
    classifier = SecurityRiskClassifier(n_estimators=100)
    
    # Load data
    classifier.load_data()
    
    # Train
    print("\n" + "=" * 80)
    print("TRAINING PHASE")
    print("=" * 80)
    training_results = classifier.train_classifier(test_size=0.25)
    
    print(f"\nTraining Results:")
    print(f"  Training Accuracy: {training_results['train_accuracy']:.3f}")
    print(f"  Test Accuracy: {training_results['test_accuracy']:.3f}")
    print(f"  CV Accuracy: {training_results['cv_mean']:.3f} (+/- {training_results['cv_std']:.3f})")
    
    # Evaluate
    metrics = classifier.evaluate_classifier()
    
    # Feature importance
    feature_importance = classifier.feature_importance_analysis()
    
    # Visualize
    classifier.visualize_results()
    
    # Save model
    classifier.save_model()
    
    # Save results
    results = {
        'training_results': training_results,
        'evaluation_metrics': metrics,
        'feature_importance': feature_importance,
        'model_info': {
            'algorithm': 'Random Forest',
            'n_estimators': 100,
            'n_features': len(classifier.feature_names),
            'feature_names': classifier.feature_names
        }
    }
    
    with open('classification_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 80)
    print("✅ CLASSIFICATION COMPLETE!")
    print("=" * 80)
    print(f"\nResults Summary:")
    print(f"  - Test Accuracy: {metrics['test_accuracy']:.1%}")
    print(f"  - Precision (Non-Compliant): {metrics['precision_non_compliant']:.1%}")
    print(f"  - Recall (Non-Compliant): {metrics['recall_non_compliant']:.1%}")
    print(f"  - F1-Score (Compliant): {metrics['f1_compliant']:.3f}")
    print(f"\nOutputs saved:")
    print(f"  - classification_results.json")
    print(f"  - trained_classifier.pkl")
    print(f"  - ml_evaluation/ (visualizations)")


if __name__ == "__main__":
    main()
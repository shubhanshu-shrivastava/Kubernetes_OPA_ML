import os
import yaml
import json
from pathlib import Path
from typing import List, Dict

class GatekeeperDataExtractor:
    """Extract YAML samples from gatekeeper-library for ML training"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.library_path = self.repo_path / "library"
        
    def extract_all_samples(self) -> List[Dict]:
        """Extract all allowed/disallowed YAML samples"""
        samples = []
        
        for policy_dir in self.library_path.rglob("samples/*"):
            if policy_dir.is_dir():
                sample_data = self.extract_policy_samples(policy_dir)
                if sample_data:
                    samples.extend(sample_data)
        
        return samples
    
    def extract_policy_samples(self, sample_dir: Path) -> List[Dict]:
        """Extract samples from a single policy sample directory"""
        samples = []
        policy_name = sample_dir.parent.parent.name
        category = sample_dir.parent.parent.parent.name
        
        # Get constraint (policy parameters)
        constraint_file = sample_dir / "constraint.yaml"
        constraint = None
        if constraint_file.exists():
            with open(constraint_file, 'r') as f:
                constraint = yaml.safe_load(f)
        
        # Extract allowed samples
        for allowed_file in sample_dir.glob("*allowed*.yaml"):
            if allowed_file.name == "constraint.yaml":
                continue
            samples.append({
                'policy': policy_name,
                'category': category,
                'label': 'allowed',
                'file': str(allowed_file),
                'content': self.load_yaml(allowed_file),
                'constraint': constraint
            })
        
        # Extract disallowed samples
        for disallowed_file in sample_dir.glob("*disallowed*.yaml"):
            samples.append({
                'policy': policy_name,
                'category': category,
                'label': 'disallowed',
                'file': str(disallowed_file),
                'content': self.load_yaml(disallowed_file),
                'constraint': constraint
            })
        
        return samples
    
    def load_yaml(self, filepath: Path) -> Dict:
        """Load YAML file"""
        try:
            with open(filepath, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
            return None
    
    def save_dataset(self, output_path: str):
        """Save extracted dataset to JSON"""
        samples = self.extract_all_samples()
        
        with open(output_path, 'w') as f:
            json.dump(samples, f, indent=2, default=str)
        
        print(f"Extracted {len(samples)} samples to {output_path}")
        
        # Print statistics
        allowed = sum(1 for s in samples if s['label'] == 'allowed')
        disallowed = sum(1 for s in samples if s['label'] == 'disallowed')
        print(f"Allowed: {allowed}, Disallowed: {disallowed}")

# Usage
if __name__ == "__main__":
    extractor = GatekeeperDataExtractor("./gatekeeper-library")
    extractor.save_dataset("gatekeeper_samples.json")
"""
ML-Driven OPA Policy Generator - Streamlit Demo
Interactive web interface for automated security policy generation
"""

import streamlit as st
import yaml
import json
from policy_generator import PolicyGenerator
from pattern_detector import EnhancedSecurityAnalyzer

# Page configuration
st.set_page_config(
    page_title="OPA Policy Generator",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #555;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-high {
        background-color: #ffebee;
        border-left: 4px solid #d32f2f;
        padding: 0.5rem;
        margin: 0.5rem 0;
    }
    .severity-medium {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 0.5rem;
        margin: 0.5rem 0;
    }
    .severity-low {
        background-color: #e8f5e9;
        border-left: 4px solid #388e3c;
        padding: 0.5rem;
        margin: 0.5rem 0;
    }
    .success-box {
        background-color: #e8f5e9;
        border: 1px solid #4caf50;
        border-radius: 4px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Example configurations
EXAMPLE_CONFIGS = {
    "Secure Pod": """apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  labels:
    app: secure
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: nginx
    image: gcr.io/google-samples/nginx:1.21
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "250m"
        memory: "256Mi"
""",
    "Insecure Pod (Multiple Issues)": """apiVersion: v1
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
""",
    "Missing Resource Limits": """apiVersion: v1
kind: Pod
metadata:
  name: no-limits-pod
spec:
  containers:
  - name: app
    image: ubuntu:20.04
    command: ["sleep", "infinity"]
""",
    "Host Namespace Violation": """apiVersion: v1
kind: Pod
metadata:
  name: host-access-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: debug
    image: busybox:latest
    securityContext:
      privileged: true
"""
}

# Initialize session state
if 'generated_policies' not in st.session_state:
    st.session_state.generated_policies = None
if 'detected_patterns' not in st.session_state:
    st.session_state.detected_patterns = None

def analyze_and_generate(yaml_config):
    """Analyze configuration and generate policies"""
    try:
        # Parse YAML
        config = yaml.safe_load(yaml_config)
        
        # Detect patterns
        analyzer = EnhancedSecurityAnalyzer()
        patterns = analyzer.analyze_config(config)
        
        # Generate policies
        generator = PolicyGenerator()
        policies = generator.generate_policies_from_config(yaml_config)
        
        return patterns, policies, None
    
    except yaml.YAMLError as e:
        return None, None, f"Invalid YAML format: {e}"
    except Exception as e:
        return None, None, f"Error during analysis: {e}"

def display_patterns(patterns):
    """Display detected patterns with severity indicators"""
    if not patterns:
        st.markdown("""
        <div class="success-box">
            <h3>✅ No Security Issues Detected!</h3>
            <p>This configuration appears to follow security best practices.</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    st.markdown("### 🔍 Detected Security Patterns")
    
    # Group by severity
    high_severity = [p for p in patterns if p['severity'] == 'HIGH']
    medium_severity = [p for p in patterns if p['severity'] == 'MEDIUM']
    low_severity = [p for p in patterns if p['severity'] == 'LOW']
    
    # Display high severity
    if high_severity:
        st.markdown("#### 🔴 HIGH Severity Issues")
        for pattern in high_severity:
            st.markdown(f"""
            <div class="severity-high">
                <strong>{pattern['pattern'].replace('_', ' ').title()}</strong><br>
                {pattern['description']}
            </div>
            """, unsafe_allow_html=True)
    
    # Display medium severity
    if medium_severity:
        st.markdown("#### 🟡 MEDIUM Severity Issues")
        for pattern in medium_severity:
            st.markdown(f"""
            <div class="severity-medium">
                <strong>{pattern['pattern'].replace('_', ' ').title()}</strong><br>
                {pattern['description']}
            </div>
            """, unsafe_allow_html=True)
    
    # Display low severity
    if low_severity:
        st.markdown("#### 🟢 LOW Severity Issues")
        for pattern in low_severity:
            st.markdown(f"""
            <div class="severity-low">
                <strong>{pattern['pattern'].replace('_', ' ').title()}</strong><br>
                {pattern['description']}
            </div>
            """, unsafe_allow_html=True)
    
    # Summary statistics
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Issues", len(patterns))
    with col2:
        st.metric("High Severity", len(high_severity))
    with col3:
        st.metric("Medium Severity", len(medium_severity))

def display_policies(policies):
    """Display generated OPA policies"""
    st.markdown("### 📜 Generated OPA Policies")
    
    if not policies:
        st.info("No policies generated - configuration is secure!")
        return
    
    # Check for messages
    if len(policies) == 1 and 'message' in policies[0]:
        st.success(policies[0]['message'])
        return
    
    st.info(f"Generated {len(policies)} OPA Gatekeeper Constraints to address detected issues")
    
    for i, policy in enumerate(policies, 1):
        if 'error' in policy:
            st.error(policy['error'])
            continue
        
        with st.expander(f"Policy {i}: {policy['pattern'].replace('_', ' ').title()} - [{policy['severity']}]"):
            # Policy details
            st.markdown(f"**Description:** {policy['description']}")
            st.markdown(f"**Template:** `{policy['template']}`")
            st.markdown(f"**Constraint Kind:** `{policy['constraint']['kind']}`")
            
            # YAML output
            st.markdown("**Generated Constraint YAML:**")
            constraint_yaml = yaml.dump(policy['constraint'], 
                                       default_flow_style=False, 
                                       sort_keys=False)
            st.code(constraint_yaml, language='yaml')
            
            # Download button
            st.download_button(
                label=f"📥 Download {policy['constraint']['metadata']['name']}.yaml",
                data=constraint_yaml,
                file_name=f"{policy['constraint']['metadata']['name']}.yaml",
                mime="text/yaml",
                key=f"download_{i}"
            )

def main():
    """Main Streamlit app"""
    
    # Header
    st.markdown('<p class="main-header">🛡️ ML-Driven OPA Policy Generator</p>', 
                unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Automated Kubernetes Security Policy Generation using Machine Learning</p>', 
                unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("📖 About")
        st.markdown("""
        This tool automatically generates Open Policy Agent (OPA) policies 
        for Kubernetes configurations using machine learning pattern detection.
        
        **Features:**
        - 🔍 Detects 7+ security anti-patterns
        - 🤖 ML-based configuration clustering
        - 📜 Auto-generates OPA Gatekeeper policies
        - ⚡ Instant policy validation
        """)
        
        st.markdown("---")
        st.header("📊 Project Stats")
        
        # Load and display stats
        try:
            with open('detected_patterns.json', 'r') as f:
                data = json.load(f)
                stats = data['statistics']
            
            st.metric("Configs Analyzed", stats['total_samples'])
            st.metric("Patterns Detected", len(data['patterns']))
            st.metric("Policy Templates", 7)
        except:
            st.info("Run analysis to see stats")
        
        st.markdown("---")
        st.markdown("**Research Project**")
        st.markdown("Cloud Computing & Security")
        st.markdown("*Shubhanshu Shrivastava*")
    
    # Main content
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📝 Input Configuration")
        
        # Example selector
        example_choice = st.selectbox(
            "Load Example Configuration:",
            [""] + list(EXAMPLE_CONFIGS.keys())
        )
        
        # Text area for YAML input
        if example_choice:
            default_yaml = EXAMPLE_CONFIGS[example_choice]
        else:
            default_yaml = "# Paste your Kubernetes YAML configuration here\n"
        
        yaml_input = st.text_area(
            "Kubernetes Configuration (YAML):",
            value=default_yaml,
            height=400,
            help="Paste a Pod, Deployment, or any Kubernetes resource YAML"
        )
        
        # Generate button
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            generate_btn = st.button("🚀 Analyze & Generate Policies", 
                                     type="primary", 
                                     use_container_width=True)
        with col_btn2:
            clear_btn = st.button("🔄 Clear", use_container_width=True)
        
        if clear_btn:
            st.session_state.generated_policies = None
            st.session_state.detected_patterns = None
            st.rerun()
    
    with col2:
        st.markdown("### 📊 Analysis Results")
        
        if generate_btn and yaml_input.strip():
            with st.spinner("Analyzing configuration and generating policies..."):
                patterns, policies, error = analyze_and_generate(yaml_input)
                
                if error:
                    st.error(error)
                else:
                    st.session_state.detected_patterns = patterns
                    st.session_state.generated_policies = policies
        
        # Display results
        if st.session_state.detected_patterns is not None:
            display_patterns(st.session_state.detected_patterns)
        
        if st.session_state.generated_policies is not None:
            st.markdown("---")
            display_policies(st.session_state.generated_policies)
    
    # Footer with workflow
    st.markdown("---")
    st.markdown("### 🔄 How It Works")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        **1️⃣ Parse Config**
        
        Extract security-relevant features from Kubernetes YAML
        """)
    
    with col2:
        st.markdown("""
        **2️⃣ Detect Patterns**
        
        ML models identify security anti-patterns and violations
        """)
    
    with col3:
        st.markdown("""
        **3️⃣ Generate Policies**
        
        Auto-generate OPA Gatekeeper Constraints from templates
        """)
    
    with col4:
        st.markdown("""
        **4️⃣ Deploy & Enforce**
        
        Apply policies to Kubernetes cluster for enforcement
        """)

if __name__ == "__main__":
    main()
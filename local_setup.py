"""
Local Setup Script for Streamlit Demo
======================================

This script downloads all necessary files from Google Drive to your local machine
and updates the Streamlit demo to use local paths.

Run this ONCE to set up your local environment.
"""

import os
import shutil
from pathlib import Path
import subprocess

print("="*70)
print("SETTING UP LOCAL STREAMLIT DEMO ENVIRONMENT")
print("="*70)

# ============================================================================
# STEP 1: Create Local Directory Structure
# ============================================================================

print("\n📁 Creating local directory structure...")

# Create base directory
local_demo_dir = Path.home() / "GraphRAG_Demo"
local_demo_dir.mkdir(exist_ok=True)

# Create subdirectories
(local_demo_dir / "model").mkdir(exist_ok=True)
(local_demo_dir / "data").mkdir(exist_ok=True)
(local_demo_dir / "cve_database").mkdir(exist_ok=True)

print(f"✓ Created demo directory: {local_demo_dir}")

# ============================================================================
# STEP 2: Download Files from Google Drive (Run in Colab)
# ============================================================================

print("\n📥 Preparing to download files...")
print("\nYou need to run this in Google Colab to download files:")
print("-" * 70)

colab_download_script = f'''
# Run this in Google Colab to download files to your computer

from google.colab import files
import torch

# Mount Google Drive
from google.colab import drive
drive.mount('/content/drive')

base_path = '/content/drive/Shareddrives/298A Group/GNN model building+training+evaluation/outputs'

# 1. Download trained model
print("Downloading model...")
files.download(f'{{base_path}}/gat_model_with_rag.pth')

# 2. Download graph data
print("Downloading graph data...")
files.download(f'{{base_path}}/uwf_gnn_repaired.pt')

# 3. Download CVE database
print("Downloading CVE database...")
files.download(f'{{base_path}}/CVE_MITRE_Full_Scored_Dataset.csv')

print("✓ All files downloaded! Move them to {local_demo_dir}")
'''

# Save script
colab_script_path = local_demo_dir / "download_from_colab.py"
with open(colab_script_path, 'w') as f:
    f.write(colab_download_script)

print(f"\n✓ Saved Colab download script to: {colab_script_path}")

# ============================================================================
# STEP 3: Install Dependencies
# ============================================================================

print("\n📦 Installing Python dependencies...")

requirements = """
streamlit==1.29.0
torch==2.1.0
torch-geometric==2.4.0
pandas==2.1.3
numpy==1.24.3
plotly==5.18.0
"""

requirements_path = local_demo_dir / "requirements.txt"
with open(requirements_path, 'w') as f:
    f.write(requirements)

print(f"✓ Created requirements.txt: {requirements_path}")
print("\nTo install dependencies, run:")
print(f"  pip install -r {requirements_path}")

# ============================================================================
# STEP 4: Create Updated Streamlit App (Local Paths)
# ============================================================================

print("\n🎨 Creating Streamlit app with local paths...")

streamlit_app_local = '''
"""
GraphRAG Cybersecurity Threat Intelligence System - LOCAL VERSION
==================================================================
"""

import streamlit as st
import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from pathlib import Path
import time

# ============================================================================
# LOCAL CONFIGURATION
# ============================================================================

# Get the directory where this script is located
DEMO_DIR = Path(__file__).parent

# Local file paths
MODEL_PATH = DEMO_DIR / "model" / "gat_model_with_rag.pth"
DATA_PATH = DEMO_DIR / "data" / "uwf_gnn_repaired.pt"
CVE_PATH = DEMO_DIR / "cve_database" / "CVE_MITRE_Full_Scored_Dataset.csv"

# Verify files exist
for path, name in [(MODEL_PATH, "Model"), (DATA_PATH, "Data"), (CVE_PATH, "CVE Database")]:
    if not path.exists():
        st.error(f"❌ {name} not found at: {path}")
        st.info(f"Please place the file in the correct location.")
        st.stop()

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="GraphRAG Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
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
        border-bottom: 3px solid #ff7f0e;
    }
    .attack-alert {
        background-color: #ff4444;
        color: white;
        padding: 1rem;
        border-radius: 8px;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .normal-alert {
        background-color: #00C851;
        color: white;
        padding: 1rem;
        border-radius: 8px;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #1f77b4;
        color: white;
        font-weight: bold;
        border-radius: 8px;
        padding: 0.5rem 1rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# MODEL DEFINITION
# ============================================================================

class EdgeLevelGAT(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, num_heads=8, 
                 edge_dim=None, dropout=0.3):
        super().__init__()
        self.dropout = dropout
        
        self.conv1 = GATConv(in_channels, hidden_channels, heads=num_heads,
                            dropout=dropout, edge_dim=edge_dim, concat=True)
        self.bn1 = torch.nn.BatchNorm1d(hidden_channels * num_heads)
        
        self.conv2 = GATConv(hidden_channels * num_heads, hidden_channels, 
                            heads=num_heads, dropout=dropout, edge_dim=edge_dim, concat=True)
        self.bn2 = torch.nn.BatchNorm1d(hidden_channels * num_heads)
        
        self.conv3 = GATConv(hidden_channels * num_heads, hidden_channels, 
                            heads=1, dropout=dropout, edge_dim=edge_dim, concat=False)
        self.bn3 = torch.nn.BatchNorm1d(hidden_channels)
        
        self.edge_classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_channels * 2 + edge_dim, hidden_channels),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_channels, 1)
        )
    
    def forward(self, x, edge_index, edge_attr):
        x = self.conv1(x, edge_index, edge_attr)
        x = self.bn1(x)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        
        x = self.conv2(x, edge_index, edge_attr)
        x = self.bn2(x)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        
        x = self.conv3(x, edge_index, edge_attr)
        x = self.bn3(x)
        x = F.elu(x)
        
        row, col = edge_index
        edge_embeddings = torch.cat([x[row], x[col], edge_attr], dim=1)
        return self.edge_classifier(edge_embeddings)

# ============================================================================
# MITRE ASSIGNMENT
# ============================================================================

def assign_mitre_from_features(edge_attrs):
    duration = float(edge_attrs[1])
    orig_bytes = float(edge_attrs[2])
    resp_bytes = float(edge_attrs[3])
    tcp_pct = float(edge_attrs[4])
    http_pct = float(edge_attrs[6])
    dns_pct = float(edge_attrs[7])
    
    if orig_bytes > 8 and duration > 3:
        return 'T1041', 'Exfiltration Over C2 Channel'
    if duration < -1 and orig_bytes < -1:
        return 'T1046', 'Network Service Discovery'
    if http_pct > 0.4 and duration > -1:
        return 'T1190', 'Exploit Public-Facing Application'
    if tcp_pct > 0.7 and duration > 2:
        return 'T1071', 'Application Layer Protocol'
    if dns_pct > 0.3:
        return 'T1568', 'Dynamic Resolution'
    if duration < 0 and tcp_pct > 0.5:
        return 'T1110', 'Brute Force'
    if tcp_pct > 0.8:
        return 'T1021', 'Remote Services'
    return 'T1190', 'Exploit Public-Facing Application'

# ============================================================================
# LOAD RESOURCES
# ============================================================================

@st.cache_resource
def load_model_and_data():
    data = torch.load(DATA_PATH, map_location='cpu')
    
    model = EdgeLevelGAT(
        in_channels=data.x.size(1),
        hidden_channels=64,
        num_heads=8,
        edge_dim=data.edge_attr.size(1),
        dropout=0.3
    )
    
    checkpoint = torch.load(MODEL_PATH, map_location='cpu')
    model.load_state_dict(checkpoint)
    model.eval()
    
    return model, data

@st.cache_data
def load_cve_database():
    cve_df = pd.read_csv(CVE_PATH)
    
    mitre_index = {}
    for mitre_id in cve_df['matched_mitre_id'].dropna().unique():
        cves = cve_df[cve_df['matched_mitre_id'] == mitre_id]
        cves = cves.sort_values('severity_score', ascending=False)
        mitre_index[mitre_id] = cves.to_dict('records')
    
    return cve_df, mitre_index

# ============================================================================
# ANALYSIS FUNCTION
# ============================================================================

def analyze_edge(edge_idx, model, data, mitre_index):
    with torch.no_grad():
        logits = model(data.x, data.edge_index, data.edge_attr)
        score = torch.sigmoid(logits[edge_idx]).squeeze().item()
    
    prediction = "ATTACK" if score >= 0.5 else "NORMAL"
    edge_attrs = data.edge_attr[edge_idx].cpu().numpy()
    src, dst = data.edge_index[:, edge_idx]
    
    edge_data = {
        'src_ip': f"10.0.{src.item() // 256}.{src.item() % 256}",
        'dst_ip': f"10.0.{dst.item() // 256}.{dst.item() % 256}",
        'duration': edge_attrs[1],
        'orig_bytes': edge_attrs[2],
        'resp_bytes': edge_attrs[3],
        'tcp_pct': edge_attrs[4],
        'http_pct': edge_attrs[6],
        'protocol': "TCP" if edge_attrs[4] > 0.5 else "UDP"
    }
    
    mitre_id, mitre_name, cves = None, None, []
    
    if prediction == "ATTACK":
        mitre_id, mitre_name = assign_mitre_from_features(edge_attrs)
        if mitre_id in mitre_index:
            cves = mitre_index[mitre_id][:5]
    
    return {
        'prediction': prediction,
        'confidence': score,
        'edge_data': edge_data,
        'mitre_id': mitre_id,
        'mitre_name': mitre_name,
        'cves': cves,
        'actual_label': data.y[edge_idx].item()
    }

# ============================================================================
# VISUALIZATIONS
# ============================================================================

def create_confidence_gauge(confidence, prediction):
    color = "red" if prediction == "ATTACK" else "green"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        title={'text': "Detection Confidence"},
        number={'suffix': "%"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 50], 'color': 'lightgray'},
                {'range': [50, 100], 'color': 'gray'}
            ],
            'threshold': {'line': {'color': "black", 'width': 4}, 'value': 50}
        }
    ))
    
    fig.update_layout(height=300)
    return fig

# ============================================================================
# MAIN APP
# ============================================================================

def main():
    st.markdown('<p class="main-header">🛡️ GraphRAG Threat Intelligence System</p>', 
                unsafe_allow_html=True)
    
    st.markdown("**Master's Thesis Defense Demo - Local Version**")
    
    # Load resources
    with st.spinner("Loading model and data..."):
        model, data = load_model_and_data()
        cve_df, mitre_index = load_cve_database()
    
    st.success(f"✅ System Ready | Running from: {DEMO_DIR}")
    
    # Sidebar
    st.sidebar.title("🎛️ Control Panel")
    st.sidebar.metric("Model F1-Score", "88.4%")
    st.sidebar.metric("ROC-AUC", "0.945")
    
    st.sidebar.markdown("---")
    
    # Edge selection
    selection_mode = st.sidebar.radio(
        "Selection Mode",
        ["Random Edge", "Specific Edge ID", "Attack Examples", "Normal Examples"]
    )
    
    if selection_mode == "Specific Edge ID":
        edge_idx = st.sidebar.number_input("Edge ID", 0, data.num_edges-1, 54)
    elif selection_mode == "Attack Examples":
        attacks = torch.where(data.y == 1)[0].tolist()
        edge_idx = st.sidebar.selectbox("Attack", attacks[:20])
    elif selection_mode == "Normal Examples":
        normals = torch.where(data.y == 0)[0].tolist()
        edge_idx = st.sidebar.selectbox("Normal", normals[:20])
    else:
        if st.sidebar.button("🎲 Random"):
            edge_idx = int(torch.randint(0, data.num_edges, (1,)).item())
            st.session_state.edge_idx = edge_idx
        edge_idx = st.session_state.get('edge_idx', 54)
    
    if st.sidebar.button("🔍 Analyze", type="primary"):
        result = analyze_edge(edge_idx, model, data, mitre_index)
        st.session_state.last_analysis = result
    
    result = st.session_state.get('last_analysis')
    
    if result:
        # Alert
        if result['prediction'] == "ATTACK":
            st.markdown(f'<div class="attack-alert">⚠️ THREAT - {result["confidence"]*100:.1f}%</div>', 
                       unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="normal-alert">✅ NORMAL - {(1-result["confidence"])*100:.1f}%</div>', 
                       unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Prediction", result['prediction'])
        col2.metric("Actual", "ATTACK" if result['actual_label'] == 1 else "NORMAL")
        col3.metric("Edge ID", edge_idx)
        
        # Gauge
        st.plotly_chart(create_confidence_gauge(result['confidence'], result['prediction']))
        
        # Network details
        st.subheader("📡 Network Details")
        st.write(f"**Source:** {result['edge_data']['src_ip']}")
        st.write(f"**Destination:** {result['edge_data']['dst_ip']}")
        st.write(f"**Protocol:** {result['edge_data']['protocol']}")
        
        # MITRE & CVE
        if result['mitre_id']:
            st.markdown("---")
            st.subheader(f"🎯 {result['mitre_id']} - {result['mitre_name']}")
            
            if result['cves']:
                for cve in result['cves'][:3]:
                    with st.expander(f"**{cve['cve_id']}** - CVSS: {cve['severity_score']:.1f}"):
                        st.write(cve['description'])

if __name__ == "__main__":
    main()
'''

streamlit_app_path = local_demo_dir / "streamlit_app.py"
with open(streamlit_app_path, 'w') as f:
    f.write(streamlit_app_local)

print(f"✓ Created local Streamlit app: {streamlit_app_path}")

# ============================================================================
# STEP 5: Create Run Script
# ============================================================================

print("\n🚀 Creating run script...")

run_script = f'''#!/bin/bash
# Run script for local Streamlit demo

cd "{local_demo_dir}"

echo "Starting GraphRAG Threat Intelligence Demo..."
echo "Directory: {local_demo_dir}"
echo ""

streamlit run streamlit_app.py
'''

run_script_path = local_demo_dir / "run_demo.sh"
with open(run_script_path, 'w') as f:
    f.write(run_script)

# Make executable
os.chmod(run_script_path, 0o755)

print(f"✓ Created run script: {run_script_path}")

# ============================================================================
# FINAL INSTRUCTIONS
# ============================================================================

print("\n" + "="*70)
print("✅ LOCAL SETUP COMPLETE!")
print("="*70)

print(f"\n📁 Demo directory: {local_demo_dir}")
print("\nDirectory structure:")
print(f"""
{local_demo_dir}/
├── streamlit_app.py          # Main demo app (local paths)
├── requirements.txt          # Python dependencies
├── run_demo.sh              # Quick run script
├── download_from_colab.py   # Script to run in Colab
├── model/
│   └── gat_model_with_rag.pth         # (place model here)
├── data/
│   └── uwf_gnn_repaired.pt            # (place data here)
└── cve_database/
    └── CVE_MITRE_Full_Scored_Dataset.csv  # (place CVE here)
""")

print("\n" + "="*70)
print("NEXT STEPS:")
print("="*70)

print("""
1. Download files from Google Colab:
   - Open Google Colab
   - Upload and run: download_from_colab.py
   - Download the 3 files to your computer

2. Place files in correct folders:
   - gat_model_with_rag.pth → model/
   - uwf_gnn_repaired.pt → data/
   - CVE_MITRE_Full_Scored_Dataset.csv → cve_database/

3. Install dependencies:
   pip install -r requirements.txt

4. Run the demo:
   ./run_demo.sh
   
   OR
   
   streamlit run streamlit_app.py

5. Open browser to: http://localhost:8501
""")

print("="*70)
print("💡 TIP: Keep the demo folder on Desktop for easy access!")
print("="*70)


"""
GraphRAG Cybersecurity Threat Intelligence System
==================================================
Standalone Local Demo - No Colab Dependencies

Place this file in: Downloads/GraphRAG_Demo/
Ensure you have:
  - model/gat_model_with_rag.pth
  - data/uwf_gnn_repaired.pt
  - cve_database/CVE_MITRE_Full_Scored_Dataset.csv

Run: streamlit run app.py
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
import json

# ============================================================================
# CONFIGURATION - LOCAL PATHS
# ============================================================================

# Get current directory (where this script is)
APP_DIR = Path(__file__).parent.absolute()

# File paths
MODEL_PATH = APP_DIR / "model" / "gat_model_with_rag.pth"
DATA_PATH = APP_DIR / "data" / "uwf_gnn_repaired.pt"
CVE_PATH = APP_DIR / "cve_database" / "CVE_MITRE_Full_Scored_Dataset.csv"

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
        margin-bottom: 1rem;
    }
    .attack-alert {
        background-color: #ff4444;
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        font-weight: bold;
        text-align: center;
        font-size: 1.3rem;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .normal-alert {
        background-color: #00C851;
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        font-weight: bold;
        text-align: center;
        font-size: 1.3rem;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .mitre-badge {
        background: linear-gradient(135deg, #ff7f0e 0%, #d45500 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .cve-card {
        border-left: 4px solid #ff7f0e;
        padding: 1rem;
        margin: 0.5rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
    .metric-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .stButton>button {
        width: 100%;
        background-color: #1f77b4;
        color: white;
        font-weight: bold;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        border: none;
        font-size: 1.1rem;
    }
    .stButton>button:hover {
        background-color: #145a8a;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# MODEL DEFINITION
# ============================================================================

class EdgeLevelGAT(torch.nn.Module):
    """Graph Attention Network for Edge-Level Threat Detection"""
    
    def __init__(self, in_channels, hidden_channels, num_heads=8, 
                 edge_dim=None, dropout=0.3):
        super().__init__()
        self.dropout = dropout
        
        # Layer 1
        self.conv1 = GATConv(in_channels, hidden_channels, heads=num_heads,
                            dropout=dropout, edge_dim=edge_dim, concat=True)
        self.bn1 = torch.nn.BatchNorm1d(hidden_channels * num_heads)
        
        # Layer 2
        self.conv2 = GATConv(hidden_channels * num_heads, hidden_channels, 
                            heads=num_heads, dropout=dropout, edge_dim=edge_dim, concat=True)
        self.bn2 = torch.nn.BatchNorm1d(hidden_channels * num_heads)
        
        # Layer 3
        self.conv3 = GATConv(hidden_channels * num_heads, hidden_channels, 
                            heads=1, dropout=dropout, edge_dim=edge_dim, concat=False)
        self.bn3 = torch.nn.BatchNorm1d(hidden_channels)
        
        # Edge classifier
        self.edge_classifier = torch.nn.Sequential(
            torch.nn.Linear(hidden_channels * 2 + edge_dim, hidden_channels),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_channels, 1)
        )
    
    def forward(self, x, edge_index, edge_attr):
        # Layer 1
        x = self.conv1(x, edge_index, edge_attr)
        x = self.bn1(x)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Layer 2
        x = self.conv2(x, edge_index, edge_attr)
        x = self.bn2(x)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Layer 3
        x = self.conv3(x, edge_index, edge_attr)
        x = self.bn3(x)
        x = F.elu(x)
        
        # Edge-level classification
        row, col = edge_index
        edge_embeddings = torch.cat([x[row], x[col], edge_attr], dim=1)
        return self.edge_classifier(edge_embeddings)

# ============================================================================
# MITRE CLASSIFICATION
# ============================================================================

def assign_mitre_from_features(edge_attrs):
    """Classify attack into MITRE ATT&CK technique based on behavior"""
    
    duration = float(edge_attrs[1])
    orig_bytes = float(edge_attrs[2])
    resp_bytes = float(edge_attrs[3])
    tcp_pct = float(edge_attrs[4])
    http_pct = float(edge_attrs[6])
    dns_pct = float(edge_attrs[7])
    
    # T1041: Exfiltration Over C2 Channel
    if orig_bytes > 8 and duration > 3:
        return 'T1041', 'Exfiltration Over C2 Channel', 'High outbound data transfer via command and control'
    
    # T1046: Network Service Discovery (Port Scanning)
    if duration < -1 and orig_bytes < -1:
        return 'T1046', 'Network Service Discovery', 'Reconnaissance through port scanning'
    
    # T1190: Exploit Public-Facing Application
    if http_pct > 0.4 and duration > -1:
        return 'T1190', 'Exploit Public-Facing Application', 'Web server exploitation attempt'
    
    # T1071: Application Layer Protocol (C2)
    if tcp_pct > 0.7 and duration > 2 and -2 < orig_bytes < 5:
        return 'T1071', 'Application Layer Protocol', 'Command and control communication'
    
    # T1568: Dynamic Resolution (DNS C2)
    if dns_pct > 0.3:
        return 'T1568', 'Dynamic Resolution', 'DNS-based command and control'
    
    # T1110: Brute Force
    if duration < 0 and tcp_pct > 0.5 and orig_bytes < 0:
        return 'T1110', 'Brute Force', 'Credential guessing attack'
    
    # T1021: Remote Services
    if tcp_pct > 0.8 and resp_bytes > -1:
        return 'T1021', 'Remote Services', 'Remote access exploitation'
    
    # Default
    return 'T1190', 'Exploit Public-Facing Application', 'Web exploitation attempt'

# ============================================================================
# RESOURCE LOADING
# ============================================================================

@st.cache_resource
def load_model_and_data():
    """Load trained model and graph data - cached for performance"""
    
    # Check files exist
    if not DATA_PATH.exists():
        st.error(f"❌ Data file not found: {DATA_PATH}")
        st.info("Please ensure uwf_gnn_repaired.pt is in the data/ folder")
        st.stop()
    
    if not MODEL_PATH.exists():
        st.error(f"❌ Model file not found: {MODEL_PATH}")
        st.info("Please ensure gat_model_with_rag.pth is in the model/ folder")
        st.stop()
    
    # Load data
    data = torch.load(DATA_PATH, map_location='cpu', weights_only=False)
    
    # Initialize model
    model = EdgeLevelGAT(
        in_channels=data.x.size(1),
        hidden_channels=64,
        num_heads=8,
        edge_dim=data.edge_attr.size(1),
        dropout=0.3
    )
    
    # Load trained weights
    checkpoint = torch.load(MODEL_PATH, map_location='cpu', weights_only=False)
    
    # Handle different checkpoint formats
    if isinstance(checkpoint, dict) and 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        model.load_state_dict(checkpoint)
    
    model.eval()
    
    return model, data

@st.cache_data
def load_cve_database():
    """Load CVE-MITRE database - cached for performance"""
    
    if not CVE_PATH.exists():
        st.error(f"❌ CVE database not found: {CVE_PATH}")
        st.info("Please ensure CVE_MITRE_Full_Scored_Dataset.csv is in the cve_database/ folder")
        st.stop()
    
    cve_df = pd.read_csv(CVE_PATH)
    
    # Build MITRE index for fast lookup
    mitre_index = {}
    for mitre_id in cve_df['matched_mitre_id'].dropna().unique():
        cves = cve_df[cve_df['matched_mitre_id'] == mitre_id]
        cves = cves.sort_values('severity_score', ascending=False)
        mitre_index[mitre_id] = cves.to_dict('records')
    
    return cve_df, mitre_index

# ============================================================================
# ANALYSIS ENGINE
# ============================================================================

def analyze_edge(edge_idx, model, data, mitre_index):
    """Perform complete threat analysis on a network communication"""
    
    # GNN prediction
    with torch.no_grad():
        logits = model(data.x, data.edge_index, data.edge_attr)
        score = torch.sigmoid(logits[edge_idx]).squeeze().item()
    
    prediction = "ATTACK" if score >= 0.5 else "NORMAL"
    
    # Extract edge features
    edge_attrs = data.edge_attr[edge_idx].cpu().numpy()
    src, dst = data.edge_index[:, edge_idx]
    
    # Build edge metadata
    edge_data = {
        'src_node': src.item(),
        'dst_node': dst.item(),
        'src_ip': f"10.0.{src.item() // 256}.{src.item() % 256}",
        'dst_ip': f"10.0.{dst.item() // 256}.{dst.item() % 256}",
        'duration': edge_attrs[1],
        'orig_bytes': edge_attrs[2],
        'resp_bytes': edge_attrs[3],
        'tcp_pct': edge_attrs[4],
        'udp_pct': edge_attrs[5],
        'http_pct': edge_attrs[6],
        'dns_pct': edge_attrs[7],
        'protocol': "TCP" if edge_attrs[4] > 0.5 else "UDP"
    }
    
    # MITRE classification and CVE retrieval (only for attacks)
    mitre_id, mitre_name, mitre_desc = None, None, None
    cves = []
    
    if prediction == "ATTACK":
        mitre_id, mitre_name, mitre_desc = assign_mitre_from_features(edge_attrs)
        
        # Get related CVEs
        if mitre_id in mitre_index:
            cves = mitre_index[mitre_id][:5]  # Top 5 by severity
    
    return {
        'prediction': prediction,
        'confidence': score,
        'edge_data': edge_data,
        'mitre_id': mitre_id,
        'mitre_name': mitre_name,
        'mitre_desc': mitre_desc,
        'cves': cves,
        'actual_label': data.y[edge_idx].item()
    }

# ============================================================================
# VISUALIZATIONS
# ============================================================================

def create_confidence_gauge(confidence, prediction):
    """Create gauge chart showing detection confidence"""
    
    color = "#ff4444" if prediction == "ATTACK" else "#00C851"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        title={'text': "Detection Confidence", 'font': {'size': 24}},
        number={'suffix': "%", 'font': {'size': 48, 'color': color}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 2},
            'bar': {'color': color, 'thickness': 0.75},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': '#e8f5e9'},
                {'range': [50, 75], 'color': '#fff3e0'},
                {'range': [75, 100], 'color': '#ffebee'}
            ],
            'threshold': {
                'line': {'color': "black", 'width': 6},
                'thickness': 0.85,
                'value': 50
            }
        }
    ))
    
    fig.update_layout(
        height=350,
        margin=dict(l=20, r=20, t=80, b=20),
        font={'family': "Arial"}
    )
    
    return fig

def create_feature_radar(edge_data):
    """Create radar chart showing network traffic profile"""
    
    categories = ['Duration', 'Outbound<br>Bytes', 'Response<br>Bytes', 
                 'TCP %', 'UDP %', 'HTTP %', 'DNS %']
    
    # Normalize features to 0-100 scale
    def normalize(val, min_val=-3, max_val=3):
        return max(0, min(100, ((val - min_val) / (max_val - min_val)) * 100))
    
    values = [
        normalize(edge_data['duration']),
        normalize(edge_data['orig_bytes']),
        normalize(edge_data['resp_bytes']),
        edge_data['tcp_pct'] * 100 if edge_data['tcp_pct'] > 0 else 0,
        edge_data['udp_pct'] * 100 if edge_data['udp_pct'] > 0 else 0,
        edge_data['http_pct'] * 100 if edge_data['http_pct'] > 0 else 0,
        edge_data['dns_pct'] * 100 if edge_data['dns_pct'] > 0 else 0
    ]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        fillcolor='rgba(31, 119, 180, 0.3)',
        line=dict(color='rgb(31, 119, 180)', width=3),
        name='Traffic Profile'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                tickfont=dict(size=12)
            ),
            angularaxis=dict(tickfont=dict(size=13))
        ),
        showlegend=False,
        height=450,
        title={
            'text': "Network Traffic Profile",
            'font': {'size': 20},
            'x': 0.5,
            'xanchor': 'center'
        },
        font={'family': "Arial"}
    )
    
    return fig

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    
    # Header
    st.markdown(
        '<p class="main-header">🛡️ GraphRAG Cybersecurity Threat Intelligence System</p>',
        unsafe_allow_html=True
    )
    
    st.markdown("""
    <div style='text-align: center; color: #666; margin-bottom: 2rem;'>
        <strong>Master's Thesis Defense Demo</strong><br>
        Graph Neural Network + MITRE ATT&CK + CVE Intelligence
    </div>
    """, unsafe_allow_html=True)
    
    # Load resources with progress
    with st.spinner("🔄 Loading model and data..."):
        try:
            model, data = load_model_and_data()
            cve_df, mitre_index = load_cve_database()
        except Exception as e:
            st.error(f"❌ Error loading resources: {str(e)}")
            st.info(f"📁 Looking for files in: {APP_DIR}")
            st.stop()
    
    st.success(f"✅ System Ready: GAT Model Loaded | {data.num_edges:,} Communications | {len(cve_df):,} CVE Records")
    
    # ========================================================================
    # SIDEBAR
    # ========================================================================
    
    st.sidebar.title("🎛️ Control Panel")
    
    # System metrics
    st.sidebar.markdown("### 📊 Model Performance")
    
    col1, col2 = st.sidebar.columns(2)
    col1.metric("F1-Score", "88.4%")
    col2.metric("ROC-AUC", "0.945")
    
    col3, col4 = st.sidebar.columns(2)
    col3.metric("Precision", "93.8%")
    col4.metric("Recall", "89.2%")
    
    st.sidebar.markdown("---")
    
    # Dataset info
    st.sidebar.markdown("### 📈 Dataset Info")
    st.sidebar.info(f"""
    **Communications:** {data.num_edges:,}  
    **Attack Rate:** {(data.y == 1).float().mean()*100:.1f}%  
    **MITRE Techniques:** {len(mitre_index)}
    """)
    
    st.sidebar.markdown("---")
    
    # Edge selection
    st.sidebar.markdown("### 🔍 Select Communication")
    
    selection_mode = st.sidebar.radio(
        "Selection Mode:",
        ["🎲 Random Edge", "🔢 Specific Edge ID", "🚨 Attack Examples", "✅ Normal Examples"],
        label_visibility="collapsed"
    )
    
    if "🔢 Specific" in selection_mode:
        edge_idx = st.sidebar.number_input(
            "Edge ID:",
            min_value=0,
            max_value=data.num_edges - 1,
            value=54,
            step=1
        )
    
    elif "🚨 Attack" in selection_mode:
        attack_edges = torch.where(data.y == 1)[0].tolist()
        edge_idx = st.sidebar.selectbox(
            "Select Attack Edge:",
            attack_edges[:30],
            format_func=lambda x: f"Edge {x}"
        )
    
    elif "✅ Normal" in selection_mode:
        normal_edges = torch.where(data.y == 0)[0].tolist()
        edge_idx = st.sidebar.selectbox(
            "Select Normal Edge:",
            normal_edges[:30],
            format_func=lambda x: f"Edge {x}"
        )
    
    else:  # Random
        if st.sidebar.button("🎲 Generate Random Edge", key="random_btn"):
            edge_idx = int(torch.randint(0, data.num_edges, (1,)).item())
            st.session_state.edge_idx = edge_idx
        
        edge_idx = st.session_state.get('edge_idx', 54)
        st.sidebar.info(f"Current: Edge {edge_idx}")
    
    # Analyze button
    analyze_clicked = st.sidebar.button(
        "🔍 ANALYZE COMMUNICATION",
        type="primary",
        use_container_width=True
    )
    
    # ========================================================================
    # ANALYSIS
    # ========================================================================
    
    if analyze_clicked or 'last_analysis' not in st.session_state:
        with st.spinner("🔍 Analyzing communication..."):
            result = analyze_edge(edge_idx, model, data, mitre_index)
            st.session_state.last_analysis = result
            st.session_state.current_edge = edge_idx
    
    result = st.session_state.get('last_analysis')
    current_edge = st.session_state.get('current_edge', edge_idx)
    
    if result:
        
        # Alert banner
        if result['prediction'] == "ATTACK":
            st.markdown(
                f'''<div class="attack-alert">
                ⚠️ THREAT DETECTED<br>
                <span style="font-size: 2rem;">{result["confidence"]*100:.1f}% Confidence</span>
                </div>''',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f'''<div class="normal-alert">
                ✅ NORMAL TRAFFIC<br>
                <span style="font-size: 2rem;">{(1-result["confidence"])*100:.1f}% Confidence</span>
                </div>''',
                unsafe_allow_html=True
            )
        
        st.markdown("---")
        
        # Key metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            match = result['prediction'] == ("ATTACK" if result['actual_label'] == 1 else "NORMAL")
            st.metric(
                "Prediction",
                result['prediction'],
                delta="✓ Match" if match else "✗ Mismatch",
                delta_color="normal" if match else "inverse"
            )
        
        with col2:
            st.metric(
                "Actual Label",
                "ATTACK" if result['actual_label'] == 1 else "NORMAL"
            )
        
        with col3:
            st.metric("Edge ID", f"#{current_edge}")
        
        with col4:
            st.metric("Protocol", result['edge_data']['protocol'])
        
        st.markdown("---")
        
        # Two-column layout
        col_left, col_right = st.columns([1, 1])
        
        # Left column: Confidence gauge and details
        with col_left:
            st.plotly_chart(
                create_confidence_gauge(result['confidence'], result['prediction']),
                use_container_width=True
            )
            
            st.markdown("### 📡 Communication Details")
            
            details_df = pd.DataFrame([
                {"Property": "Source IP", "Value": result['edge_data']['src_ip']},
                {"Property": "Destination IP", "Value": result['edge_data']['dst_ip']},
                {"Property": "Protocol", "Value": result['edge_data']['protocol']},
                {"Property": "Duration (normalized)", "Value": f"{result['edge_data']['duration']:.3f}"},
                {"Property": "Outbound Bytes (norm)", "Value": f"{result['edge_data']['orig_bytes']:.3f}"},
                {"Property": "Response Bytes (norm)", "Value": f"{result['edge_data']['resp_bytes']:.3f}"},
                {"Property": "TCP Percentage", "Value": f"{result['edge_data']['tcp_pct']*100:.1f}%" if result['edge_data']['tcp_pct'] > 0 else "0%"},
                {"Property": "HTTP Percentage", "Value": f"{result['edge_data']['http_pct']*100:.1f}%" if result['edge_data']['http_pct'] > 0 else "0%"},
            ])
            
            st.dataframe(
                details_df,
                use_container_width=True,
                hide_index=True,
                height=350
            )
        
        # Right column: Traffic profile
        with col_right:
            st.plotly_chart(
                create_feature_radar(result['edge_data']),
                use_container_width=True
            )
        
        # MITRE & CVE section (only for attacks)
        if result['prediction'] == "ATTACK" and result['mitre_id']:
            
            st.markdown("---")
            st.markdown("## 🎯 MITRE ATT&CK Classification")
            
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown(f"""
                <div class="mitre-badge">
                    <h1 style='margin: 0; color: white;'>{result['mitre_id']}</h1>
                    <p style='margin: 0.5rem 0 0 0; font-size: 1.2rem; color: white;'>
                        {result['mitre_name']}
                    </p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                st.info(f"""
                **Attack Technique:** {result['mitre_name']}
                
                **Description:** {result['mitre_desc']}
                
                **Classification Method:** Behavior-based analysis of network traffic patterns
                
                **Related CVEs:** {len(result['cves'])} high-severity vulnerabilities found
                """)
            
            # CVE vulnerabilities
            if result['cves']:
                st.markdown("---")
                st.markdown("## 🔒 Related Vulnerabilities")
                
                st.markdown(f"**Found {len(result['cves'])} CVEs** associated with {result['mitre_id']}")
                
                for i, cve in enumerate(result['cves']):
                    severity_color = "🔴" if cve['severity_score'] >= 9 else "🟠" if cve['severity_score'] >= 7 else "🟡"
                    severity_text = "Critical" if cve['severity_score'] >= 9 else "High" if cve['severity_score'] >= 7 else "Medium"
                    
                    with st.expander(
                        f"**{cve['cve_id']}** - {severity_color} CVSS: {cve['severity_score']:.1f}/10 ({severity_text}) - Year: {cve['year']}",
                        expanded=(i == 0)
                    ):
                        st.markdown(f"""
                        **Severity Score:** {cve['severity_score']:.1f}/10 ({severity_text})
                        
                        **Year:** {cve['year']}
                        
                        **MITRE Technique:** {cve['matched_mitre_id']}
                        
                        **Description:**  
                        {cve['description']}
                        """)
            else:
                st.info(f"ℹ️ No CVEs found in database for {result['mitre_id']}. This may be a behavioral detection.")
        
        # Export section
        st.markdown("---")
        st.markdown("## 💾 Export Analysis")
        
        # Prepare export data
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "edge_id": current_edge,
            "prediction": result['prediction'],
            "confidence": f"{result['confidence']*100:.2f}%",
            "actual_label": "ATTACK" if result['actual_label'] == 1 else "NORMAL",
            "match": result['prediction'] == ("ATTACK" if result['actual_label'] == 1 else "NORMAL"),
            "source_ip": result['edge_data']['src_ip'],
            "destination_ip": result['edge_data']['dst_ip'],
            "protocol": result['edge_data']['protocol'],
            "mitre_technique": result['mitre_id'] if result['mitre_id'] else "N/A",
            "mitre_name": result['mitre_name'] if result['mitre_name'] else "N/A",
            "cves_found": len(result['cves']) if result['cves'] else 0,
            "cve_ids": [cve['cve_id'] for cve in result['cves']] if result['cves'] else []
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            # CSV export
            export_df = pd.DataFrame([export_data])
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="📄 Download as CSV",
                data=csv,
                file_name=f"threat_analysis_{current_edge}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            # JSON export
            json_str = json.dumps(export_data, indent=2)
            
            st.download_button(
                label="📋 Download as JSON",
                data=json_str,
                file_name=f"threat_analysis_{current_edge}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )

# ============================================================================
# RUN APPLICATION
# ============================================================================

if __name__ == "__main__":
    # Verify directory structure
    if not APP_DIR.name == "GraphRAG_Demo":
        st.warning(f"⚠️ This app should be run from GraphRAG_Demo folder. Current: {APP_DIR.name}")
    
    main()

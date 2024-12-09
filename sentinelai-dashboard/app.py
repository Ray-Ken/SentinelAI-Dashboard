import os
import pandas as pd
import numpy as np
from dash import Dash, dcc, html, Input, Output, State
import dash_table
import plotly.express as px
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from sklearn.preprocessing import StandardScaler
import joblib

# Load models
supervised_models = joblib.load("models/supervised_models.pkl")
unsupervised_models = joblib.load("models/unsupervised_models.pkl")
rf, xgb, svm, stacking = supervised_models
iso_forest, autoencoder, one_class_svm = unsupervised_models

# Setup directories
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize Dash app
app = Dash(__name__)
app.title = "SentinelAI Dashboard"

# Dash Layout
app.layout = html.Div([
    html.H1("SentinelAI Dashboard", style={"textAlign": "center"}),
    html.Hr(),

    html.Div([
        html.H3("Upload Packet Data (PCAP Format)"),
        dcc.Upload(
            id="upload-packet",
            children=html.Div(["Drag and Drop or ", html.A("Select File")]),
            style={
                "width": "100%",
                "height": "60px",
                "lineHeight": "60px",
                "borderWidth": "1px",
                "borderStyle": "dashed",
                "borderRadius": "5px",
                "textAlign": "center",
                "margin": "10px",
            },
            multiple=False,
        ),
        html.Div(id="upload-status"),
    ]),
    html.Hr(),

    html.Div([
        html.H3("Visualization of Behaviors and Attack Types"),
        dcc.Graph(id="behavior-chart"),
        dcc.Graph(id="attack-chart"),
    ]),
    html.Hr(),

    html.Div([
        html.H3("Response Mechanisms"),
        dash_table.DataTable(id="response-log", style_table={'overflowX': 'auto'}),
    ]),
    html.Hr(),

    html.Div([
        html.H3("Generate Report"),
        html.Button("Generate Report", id="generate-report", n_clicks=0, style={"margin": "10px"}),
        html.Div(id="report-output", style={"marginTop": "20px"}),
    ]),
])

# Helper Functions
def process_pcap(file_path):
    """Process PCAP file into features."""
    packets = rdpcap(file_path)
    rows = []
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0
            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
            rows.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
            })
    return pd.DataFrame(rows)

def preprocess_data(df):
    """Preprocess the data for prediction."""
    scaler = StandardScaler()
    return scaler.fit_transform(df)

def hybrid_model_inference(X):
    """Run predictions using the hybrid model."""
    behavior_preds = svm.predict(X)
    attack_preds = stacking.predict(X)
    return behavior_preds, attack_preds

def respond_to_threat(label, attack_type, metadata):
    """
    Trigger appropriate response based on threat detection and attack type.
    """
    response = {}
    if label == 1:  # Suspicious
        response["action"] = "Alert Sent"
        response["message"] = f"Suspicious activity detected: {attack_type}. Security team notified."
    elif label == 2:  # Anomalous
        response["action"] = "Isolation"
        response["message"] = f"Anomalous behavior detected: {attack_type}. System {metadata.get('src_ip', 'Unknown')} isolated."
    else:
        response["action"] = "Monitor"
        response["message"] = "Behavior is benign. Monitoring for further analysis."
    return response

def generate_visualizations(behavior_preds, attack_preds):
    """Generate plots for behavior and attack type distribution."""
    behavior_fig = px.histogram(
        pd.Series(behavior_preds, name="Behavior Prediction"),
        title="Behavior Prediction Distribution",
        labels={"value": "Behavior"},
        nbins=3,
    )
    attack_fig = px.histogram(
        pd.Series(attack_preds, name="Attack Type Prediction"),
        title="Attack Type Prediction Distribution",
        labels={"value": "Attack Type"},
    )
    return behavior_fig, attack_fig

def generate_report(behavior_preds, attack_preds):
    """Generate a text report summarizing analysis."""
    report_path = os.path.join(UPLOAD_DIR, "APT_Detection_Report.txt")
    with open(report_path, "w") as f:
        f.write("SentinelAI APT Detection Report\n")
        f.write("=" * 60 + "\n\n")
        f.write("Behavior Analysis:\n")
        f.write(pd.Series(behavior_preds).value_counts().to_string() + "\n\n")
        f.write("Attack Type Analysis:\n")
        f.write(pd.Series(attack_preds).value_counts().to_string() + "\n\n")
        f.write("Recommendations:\n")
        f.write("- Keep all systems and software up-to-date.\n")
        f.write("- Use intrusion detection systems to monitor traffic.\n")
        f.write("- Isolate infected systems from the network.\n")
        f.write("- Conduct regular security training for employees.\n")
    return report_path

# Callbacks
@app.callback(
    [
        Output("upload-status", "children"),
        Output("behavior-chart", "figure"),
        Output("attack-chart", "figure"),
        Output("response-log", "data"),
        Output("response-log", "columns"),
    ],
    Input("upload-packet", "contents"),
    State("upload-packet", "filename"),
)
def handle_upload(contents, filename):
    if contents is not None:
        # Save file
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(contents.encode("utf-8"))

        # Process and predict
        df = process_pcap(file_path)
        if df.empty:
            return "Uploaded file contains no packets!", {}, {}, [], []
        X = preprocess_data(df)
        behavior_preds, attack_preds = hybrid_model_inference(X)

        # Generate visualizations
        behavior_fig, attack_fig = generate_visualizations(behavior_preds, attack_preds)

        # Generate response log
        response_log = []
        for i, (label, attack_type) in enumerate(zip(behavior_preds, attack_preds)):
            metadata = df.iloc[i].to_dict()
            response = respond_to_threat(label, attack_type, metadata)
            response_log.append({
                "Source IP": metadata.get("src_ip", "Unknown"),
                "Destination IP": metadata.get("dst_ip", "Unknown"),
                "Action": response["action"],
                "Message": response["message"],
            })
        columns = [{"name": col, "id": col} for col in response_log[0].keys()] if response_log else []
        return f"File {filename} uploaded and processed successfully!", behavior_fig, attack_fig, response_log, columns
    return "No file uploaded", {}, {}, [], []

@app.callback(
    Output("report-output", "children"),
    Input("generate-report", "n_clicks"),
    State("upload-packet", "filename"),
)
def handle_report(n_clicks, filename):
    if n_clicks > 0 and filename:
        file_path = os.path.join(UPLOAD_DIR, filename)
        df = process_pcap(file_path)
        X = preprocess_data(df)
        behavior_preds, attack_preds = hybrid_model_inference(X)
        report_path = generate_report(behavior_preds, attack_preds)
        return f"Report generated: {report_path}"
    return "No report generated yet."

# Run server
if __name__ == "__main__":
    app.run_server(debug=True)

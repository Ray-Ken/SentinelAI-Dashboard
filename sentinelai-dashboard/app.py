import os
import base64
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from dash import Dash, dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc
import plotly.express as px
import random

# ============================
# Constants and Mappings
# ============================
BEHAVIOR_MAP = {0: "Benign", 1: "Suspicious", 2: "Anomalous"}
ATTACK_MAP = {
    0: "Normal", 1: "DoS", 2: "Reconnaissance", 3: "DDoS", 4: "Brute Force",
    5: "Botnet", 6: "Web Exploitation", 7: "Infiltration", 8: "Heartbleed",
    9: "Exploitation", 10: "Fuzzing", 11: "Code Injection", 12: "Malware",
    13: "Information Gathering", 14: "Backdoor"
}

# ============================
# Initialize Dash App
# ============================
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "SentinelAI Dashboard"

# ============================
# Helper Functions
# ============================
def process_pcap(file_path):
    """Processes a PCAP file into a structured DataFrame."""
    packets = rdpcap(file_path)
    rows = []
    for pkt in packets:
        if IP in pkt:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            rows.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "protocol": proto,
                "length": len(pkt),
                "payload": pkt[Raw].load.decode(errors="ignore") if Raw in pkt else "",
            })
    return pd.DataFrame(rows)

def random_behavior_and_attack(df):
    """Assigns diverse behaviors and attack types to the DataFrame."""
    behavior_options = [BEHAVIOR_MAP[0], BEHAVIOR_MAP[1], BEHAVIOR_MAP[2]]  # Benign, Suspicious, Anomalous
    attack_options = [ATTACK_MAP[i] for i in range(len(ATTACK_MAP))]

    df["behavior"] = df.index % 3  # Cycle through behaviors
    df["behavior"] = df["behavior"].map({0: "Benign", 1: "Suspicious", 2: "Anomalous"})  # Map to BEHAVIOR_MAP

    df["attack_type"] = df.index % len(attack_options)  # Cycle through attack types
    df["attack_type"] = df["attack_type"].map(lambda x: attack_options[x])  # Map to ATTACK_MAP

    print("Assigned Behaviors:", df["behavior"].unique())  # Debugging
    print("Assigned Attack Types:", df["attack_type"].unique())  # Debugging
    return df

def respond_to_threat(label, attack_type, metadata):
    """
    Trigger appropriate response based on threat detection and attack type.
    """
    response = {}
    if label == "Suspicious":
        response["action"] = "Alert Sent"
        response["message"] = f"Suspicious activity detected: {attack_type}. Security team notified."
    elif label == "Anomalous":
        response["action"] = "Isolation"
        response["message"] = f"Anomalous behavior detected: {attack_type}. System {metadata.get('src_ip', 'Unknown')} isolated."
    else:
        response["action"] = "Monitor"
        response["message"] = "Behavior is benign. Monitoring for further analysis."
    return response

def generate_behavior_chart(df):
    """Generates the behavior distribution pie chart."""
    behavior_counts = df["behavior"].value_counts()
    return px.pie(
        names=behavior_counts.index,
        values=behavior_counts.values,
        title="Behavior Distribution"
    )

def generate_attack_chart(df):
    """Generates the attack type distribution bar chart."""
    attack_counts = df["attack_type"].value_counts()
    return px.bar(
        x=attack_counts.index,
        y=attack_counts.values,
        title="Attack Type Distribution",
        labels={"x": "Attack Type", "y": "Count"}
    )

# ============================
# Layout
# ============================
app.layout = dbc.Container([
    html.H1("SentinelAI Dashboard", className="text-center text-primary mt-4"),
    html.P("Advanced Persistent Threat Detection (Mock) Dashboard", className="text-center text-secondary"),

    # File Upload
    dbc.Row([
        dbc.Col([
            dcc.Upload(
                id="upload-data",
                children=html.Div(["Drag and Drop or Click to Upload"]),
                style={
                    "width": "100%", "height": "60px", "lineHeight": "60px",
                    "borderWidth": "1px", "borderStyle": "dashed",
                    "borderRadius": "5px", "textAlign": "center", "margin": "10px"
                }
            ),
            html.Div(id="upload-status", className="text-center text-info mt-2")
        ], width=12)
    ], className="mb-4"),

    # Charts Row
    dbc.Row([
        dbc.Col(dbc.Card([dbc.CardHeader("Behavior Prediction"), dbc.CardBody(dcc.Graph(id="behavior-chart"))]), md=6),
        dbc.Col(dbc.Card([dbc.CardHeader("Attack Type Prediction"), dbc.CardBody(dcc.Graph(id="attack-chart"))]), md=6),
    ], className="mb-4"),

    # Response Log
    dbc.Row([
        dbc.Col([
            html.H3("Response Log", className="text-center mt-4"),
            dash_table.DataTable(
                id="response-log",
                style_table={"overflowX": "auto"},
                style_data={"whiteSpace": "normal"},
                style_header={"backgroundColor": "lightblue", "fontWeight": "bold"},
            )
        ], width=12)
    ])
], fluid=True)

# ============================
# Callbacks
# ============================
@app.callback(
    [
        Output("upload-status", "children"),
        Output("behavior-chart", "figure"),
        Output("attack-chart", "figure"),
        Output("response-log", "data"),
        Output("response-log", "columns"),
    ],
    Input("upload-data", "contents"),
    State("upload-data", "filename"),
)
def update_dashboard(contents, filename):
    if contents:
        try:
            content_type, content_string = contents.split(",")
            decoded = base64.b64decode(content_string)
            file_path = f"uploads/{filename}"
            os.makedirs("uploads", exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(decoded)

            # Process the PCAP file
            df = process_pcap(file_path)

            # Assign random behaviors and attack types
            df = random_behavior_and_attack(df)

            # Generate responses
            responses = []
            for _, row in df.iterrows():
                response = respond_to_threat(row["behavior"], row["attack_type"], row)
                responses.append({**response, "Behavior": row["behavior"], "Attack": row["attack_type"]})

            # Generate charts
            behavior_fig = generate_behavior_chart(df)
            attack_fig = generate_attack_chart(df)

            # Response log table
            response_columns = [{"name": col, "id": col} for col in responses[0].keys()] if responses else []
            return (
                f"File '{filename}' uploaded successfully!",
                behavior_fig,
                attack_fig,
                responses,
                response_columns
            )

        except Exception as e:
            return f"Error: {str(e)}", {}, {}, [{"Error": str(e)}], [{"name": "Error", "id": "Error"}]
    return "No file uploaded.", {}, {}, [], []

# ============================
# Run the App
# ============================
if __name__ == "__main__":
    app.run_server(debug=True)

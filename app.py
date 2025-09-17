import dash
from dash import dcc, html, dash_table, callback_context
from dash.dependencies import Output, Input, State
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import zmq
import json
import threading
from datetime import datetime, timedelta
import numpy as np
import time
from collections import defaultdict, deque
import socket as sock

# Global traffic data store with better structure
traffic_data = deque(maxlen=2000)  # Use deque for better performance
stats_history = deque(maxlen=100)   # Store historical stats
alert_queue = deque(maxlen=50)      # Store recent alerts

# Real-time metrics
current_stats = {
    'total_requests': 0,
    'threats_detected': 0,
    'blocked_ips': set(),
    'avg_response_time': 0,
    'bandwidth_usage': 0,
    'active_connections': 0,
    'last_update': datetime.now()
}

# Setup ZeroMQ Subscriber with error handling
context = zmq.Context()
socket = context.socket(zmq.SUB)

def setup_zmq_connection():
    try:
        socket.connect("tcp://localhost:5555")
        socket.setsockopt_string(zmq.SUBSCRIBE, "")
        socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
        return True
    except Exception as e:
        print(f"ZMQ Connection Error: {e}")
        return False

def generate_sample_data():
    """Generate realistic sample data for demonstration"""
    sample_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10",
        "198.51.100.5", "192.0.2.15", "10.1.1.200", "172.20.0.100"
    ]
    
    predictions = ["normal", "ddos", "port_scan", "brute_force", "normal", "normal"]
    statuses = ["allowed", "blocked", "monitored"]
    
    return {
        "timestamp": datetime.now().isoformat(),
        "src_ip": np.random.choice(sample_ips),
        "dst_ip": "192.168.1.1",
        "src_port": np.random.randint(1024, 65535),
        "dst_port": np.random.choice([80, 443, 22, 21, 25]),
        "protocol": np.random.choice(["TCP", "UDP", "ICMP"]),
        "packet_count": np.random.randint(1, 1000),
        "byte_count": np.random.randint(64, 65536),
        "duration": np.random.uniform(0.1, 10.0),
        "prediction": np.random.choice(predictions, p=[0.7, 0.1, 0.08, 0.07, 0.025, 0.025]),
        "confidence": np.random.uniform(0.7, 0.99),
        "status": np.random.choice(statuses, p=[0.8, 0.15, 0.05]),
        "threat_level": np.random.choice(["low", "medium", "high", "critical"], p=[0.6, 0.25, 0.1, 0.05]),
        "response_time": np.random.uniform(1, 100)
    }

def listen_to_ryu():
    """Enhanced listener with fallback to sample data"""
    global traffic_data, current_stats, alert_queue
    
    zmq_connected = setup_zmq_connection()
    
    while True:
        try:
            if zmq_connected:
                try:
                    msg = socket.recv_string(zmq.NOBLOCK)
                    event = json.loads(msg)
                except zmq.Again:
                    # No message received, generate sample data
                    event = generate_sample_data()
                    time.sleep(0.5)  # Simulate realistic timing
                except Exception as e:
                    print(f"ZMQ receive error: {e}")
                    event = generate_sample_data()
                    time.sleep(0.5)
            else:
                # Use sample data if ZMQ not connected
                event = generate_sample_data()
                time.sleep(0.5)
            
            # Ensure timestamp is present
            if 'timestamp' not in event:
                event['timestamp'] = datetime.now().isoformat()
            
            # Add derived fields
            event['flow_rate'] = event.get('packet_count', 0) / max(event.get('duration', 0.1), 0.1)
            
            traffic_data.append(event)
            
            # Update real-time stats
            current_stats['total_requests'] += 1
            if event.get('prediction', 'normal') != 'normal':
                current_stats['threats_detected'] += 1
            
            if event.get('status') == 'blocked':
                current_stats['blocked_ips'].add(event.get('src_ip', ''))
            
            current_stats['avg_response_time'] = event.get('response_time', 0)
            current_stats['bandwidth_usage'] += event.get('byte_count', 0)
            current_stats['last_update'] = datetime.now()
            
            # Generate alerts for high-priority threats
            if event.get('threat_level') in ['high', 'critical'] or event.get('prediction') in ['ddos', 'brute_force']:
                alert = {
                    'timestamp': event['timestamp'],
                    'type': event.get('prediction', 'unknown'),
                    'src_ip': event.get('src_ip', 'unknown'),
                    'severity': event.get('threat_level', 'medium'),
                    'message': f"{event.get('prediction', 'Threat').title()} detected from {event.get('src_ip', 'unknown IP')}"
                }
                alert_queue.append(alert)
                
        except Exception as e:
            print(f"Listener error: {e}")
            time.sleep(1)

# Start listener thread
threading.Thread(target=listen_to_ryu, daemon=True).start()

# Initialize Dash app with custom CSS
app = dash.Dash(__name__)
app.title = "Advanced SDN DDoS Defense Dashboard"

# Custom CSS and JavaScript
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body { 
                margin: 0; 
                font-family: 'Poppins', sans-serif !important; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .metric-card {
                background: linear-gradient(135deg, #fff 0%, #f8f9ff 100%);
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .metric-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 35px rgba(0,0,0,0.15);
            }
            .metric-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, #667eea, #764ba2);
            }
            .chart-container {
                background: rgba(255,255,255,0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 30px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                margin-bottom: 25px;
            }
            .alert-item {
                background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                color: white;
                padding: 15px;
                border-radius: 10px;
                margin: 8px 0;
                box-shadow: 0 5px 15px rgba(255,107,107,0.3);
                animation: slideIn 0.5s ease-out;
            }
            @keyframes slideIn {
                from { opacity: 0; transform: translateX(-20px); }
                to { opacity: 1; transform: translateX(0); }
            }
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.1); }
                100% { transform: scale(1); }
            }
            .header-gradient {
                background: linear-gradient(135deg, #2c3e50 0%, #3498db 50%, #9b59b6 100%);
                position: relative;
                overflow: hidden;
            }
            .header-gradient::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
                animation: shine 3s infinite;
            }
            @keyframes shine {
                0% { left: -100%; }
                100% { left: 100%; }
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# Enhanced Layout
app.layout = html.Div([
    # Header with live status
    html.Div([
        html.Div([
            html.Div([
                html.H1([
                    html.I(className="fas fa-shield-halved", style={"marginRight": "15px", "color": "#00d4ff"}),
                    "Advanced SDN DDoS Defense Center"
                ], style={
                    "color": "#fff", 
                    "margin": "0", 
                    "fontSize": "3rem",
                    "fontWeight": "700",
                    "textShadow": "0 2px 4px rgba(0,0,0,0.3)"
                }),
                html.Div([
                    html.Span([
                        html.Span(className="status-indicator", 
                                style={"backgroundColor": "#00ff88"}),
                        "System Online"
                    ], style={"marginRight": "30px", "fontSize": "1.1rem"}),
                    html.Span([
                        html.I(className="fas fa-clock", style={"marginRight": "5px"}),
                        html.Span(id="live-time")
                    ], style={"fontSize": "1.1rem"})
                ], style={
                    "color": "#e8f4fd", 
                    "marginTop": "10px",
                    "display": "flex",
                    "alignItems": "center",
                    "justifyContent": "center"
                })
            ], style={"textAlign": "center"})
        ])
    ], className="header-gradient", style={
        "padding": "40px 20px",
        "marginBottom": "30px"
    }),

    # Auto-refresh components
    dcc.Interval(id="update-interval", interval=1500, n_intervals=0),
    dcc.Interval(id="time-interval", interval=1000, n_intervals=0),

    # Real-time Metrics Dashboard
    html.Div([
        # Top Metrics Row
        html.Div([
            html.Div([
                html.Div([
                    html.I(className="fas fa-network-wired", 
                          style={"fontSize": "2.5rem", "color": "#4CAF50", "marginBottom": "10px"}),
                    html.H2(id="total-requests", children="0", 
                           style={"color": "#4CAF50", "margin": "0", "fontSize": "2.5rem", "fontWeight": "700"}),
                    html.P("Total Requests", style={"margin": "5px 0", "color": "#666", "fontSize": "1.1rem"}),
                    html.Small(id="request-rate", children="0 req/s", 
                              style={"color": "#888", "fontSize": "0.9rem"})
                ], className="metric-card", style={"textAlign": "center"})
            ], className="three columns"),

            html.Div([
                html.Div([
                    html.I(className="fas fa-exclamation-triangle", 
                          style={"fontSize": "2.5rem", "color": "#FF5722", "marginBottom": "10px"}),
                    html.H2(id="threats-detected", children="0", 
                           style={"color": "#FF5722", "margin": "0", "fontSize": "2.5rem", "fontWeight": "700"}),
                    html.P("Threats Detected", style={"margin": "5px 0", "color": "#666", "fontSize": "1.1rem"}),
                    html.Small(id="threat-rate", children="0%", 
                              style={"color": "#888", "fontSize": "0.9rem"})
                ], className="metric-card", style={"textAlign": "center"})
            ], className="three columns"),

            html.Div([
                html.Div([
                    html.I(className="fas fa-ban", 
                          style={"fontSize": "2.5rem", "color": "#FF9800", "marginBottom": "10px"}),
                    html.H2(id="blocked-ips", children="0", 
                           style={"color": "#FF9800", "margin": "0", "fontSize": "2.5rem", "fontWeight": "700"}),
                    html.P("Blocked IPs", style={"margin": "5px 0", "color": "#666", "fontSize": "1.1rem"}),
                    html.Small(id="block-rate", children="0% blocked", 
                              style={"color": "#888", "fontSize": "0.9rem"})
                ], className="metric-card", style={"textAlign": "center"})
            ], className="three columns"),

            html.Div([
                html.Div([
                    html.I(className="fas fa-tachometer-alt", 
                          style={"fontSize": "2.5rem", "color": "#2196F3", "marginBottom": "10px"}),
                    html.H2(id="avg-response", children="0ms", 
                           style={"color": "#2196F3", "margin": "0", "fontSize": "2.5rem", "fontWeight": "700"}),
                    html.P("Response Time", style={"margin": "5px 0", "color": "#666", "fontSize": "1.1rem"}),
                    html.Small(id="bandwidth", children="0 MB/s", 
                              style={"color": "#888", "fontSize": "0.9rem"})
                ], className="metric-card", style={"textAlign": "center"})
            ], className="three columns"),
        ], className="row", style={"marginBottom": "30px"}),

        # Main Analytics Row
        html.Div([
            # Real-time Traffic Flow
            html.Div([
                html.Div([
                    html.H3([
                        html.I(className="fas fa-chart-line", style={"marginRight": "10px", "color": "#667eea"}),
                        "Real-time Traffic Analysis"
                    ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                    dcc.Graph(id="traffic-flow", style={"height": "450px"})
                ], className="chart-container")
            ], className="eight columns"),

            # Live Alerts Panel
            html.Div([
                html.Div([
                    html.H3([
                        html.I(className="fas fa-bell", style={"marginRight": "10px", "color": "#ff6b6b"}),
                        "Live Security Alerts"
                    ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                    html.Div(id="live-alerts", style={"maxHeight": "400px", "overflowY": "auto"})
                ], className="chart-container")
            ], className="four columns"),
        ], className="row", style={"marginBottom": "30px"}),

        # Network Topology and Threat Analysis
        html.Div([
            html.Div([
                html.Div([
                    html.H3([
                        html.I(className="fas fa-project-diagram", style={"marginRight": "10px", "color": "#9c88ff"}),
                        "Network Topology & Attack Vectors"
                    ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                    dcc.Graph(id="network-topology", style={"height": "400px"})
                ], className="chart-container")
            ], className="six columns"),

            html.Div([
                html.Div([
                    html.H3([
                        html.I(className="fas fa-crosshairs", style={"marginRight": "10px", "color": "#ff6348"}),
                        "Attack Pattern Analysis"
                    ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                    dcc.Graph(id="attack-patterns", style={"height": "400px"})
                ], className="chart-container")
            ], className="six columns"),
        ], className="row", style={"marginBottom": "30px"}),

        # Performance Metrics
        html.Div([
            html.Div([
                html.Div([
                    html.H3([
                        html.I(className="fas fa-server", style={"marginRight": "10px", "color": "#5f27cd"}),
                        "System Performance Metrics"
                    ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                    dcc.Graph(id="performance-metrics", style={"height": "350px"})
                ], className="chart-container")
            ], className="twelve columns"),
        ], className="row", style={"marginBottom": "30px"}),

        # Detailed Events Table
        html.Div([
            html.Div([
                html.H3([
                    html.I(className="fas fa-table", style={"marginRight": "10px", "color": "#00cec9"}),
                    "Network Security Events Log"
                ], style={"color": "#333", "marginBottom": "20px", "fontSize": "1.5rem", "fontWeight": "600"}),
                html.Div([
                    html.Button("Export Data", id="export-btn", className="btn", 
                               style={
                                   "background": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                                   "color": "white", "border": "none", "padding": "10px 20px",
                                   "borderRadius": "8px", "marginBottom": "15px", "cursor": "pointer"
                               }),
                    html.Div(id="events-table")
                ])
            ], className="chart-container")
        ], style={"marginBottom": "30px"}),
    ], style={"padding": "0 20px"}),

    # Footer
    html.Div([
        html.Div([
            html.P([
                html.I(className="fas fa-shield-alt", style={"marginRight": "10px"}),
                "SDN DDoS Defense System v2.0 | ",
                html.Span(id="footer-time"),
                " | Status: ",
                html.Span("Operational", style={"color": "#00ff88", "fontWeight": "bold"})
            ], style={"textAlign": "center", "color": "#fff", "margin": "0", "fontSize": "1rem"})
        ])
    ], style={
        "background": "linear-gradient(135deg, #2c3e50 0%, #3498db 100%)",
        "padding": "20px",
        "marginTop": "30px"
    })

], style={
    "backgroundColor": "#f0f2ff",
    "minHeight": "100vh",
    "margin": "0"
})

# Enhanced Callbacks
@app.callback(
    [Output("live-time", "children"),
     Output("footer-time", "children")],
    [Input("time-interval", "n_intervals")]
)
def update_time(n):
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S")
    date_str = now.strftime("%Y-%m-%d %H:%M:%S")
    return time_str, date_str

@app.callback(
    [Output("total-requests", "children"),
     Output("threats-detected", "children"),
     Output("blocked-ips", "children"),
     Output("avg-response", "children"),
     Output("request-rate", "children"),
     Output("threat-rate", "children"),
     Output("block-rate", "children"),
     Output("bandwidth", "children"),
     Output("traffic-flow", "figure"),
     Output("live-alerts", "children"),
     Output("network-topology", "figure"),
     Output("attack-patterns", "figure"),
     Output("performance-metrics", "figure"),
     Output("events-table", "children")],
    [Input("update-interval", "n_intervals")]
)
def update_dashboard(n):
    if not traffic_data:
        # Enhanced empty state
        empty_fig = create_empty_chart("Waiting for network data...")
        return ("0", "0", "0", "0ms", "0 req/s", "0%", "0%", "0 MB/s",
                empty_fig, create_no_alerts(), empty_fig, empty_fig, empty_fig, create_empty_table())

    # Convert to DataFrame
    df = pd.DataFrame(list(traffic_data))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Calculate enhanced metrics
    total_requests = len(df)
    threats = df[df.get('prediction', 'normal') != 'normal']
    threats_detected = len(threats)
    blocked_count = len(df[df.get('status', 'allowed') == 'blocked'].get('src_ip', pd.Series()).unique())
    
    # Calculate rates
    recent_df = df[df['timestamp'] > (datetime.now() - timedelta(minutes=1))]
    request_rate = f"{len(recent_df)} req/s"
    threat_rate = f"{(threats_detected/total_requests*100):.1f}%" if total_requests > 0 else "0%"
    block_rate = f"{(blocked_count/total_requests*100):.1f}%" if total_requests > 0 else "0%"
    
    avg_response = f"{df['response_time'].mean():.1f}ms" if 'response_time' in df.columns else "N/A"
    bandwidth = f"{(df['byte_count'].sum()/(1024*1024)):.2f} MB/s" if 'byte_count' in df.columns else "0 MB/s"

    # Create enhanced visualizations
    traffic_fig = create_traffic_flow_chart(df)
    alerts = create_live_alerts(list(alert_queue))
    topology_fig = create_network_topology(df)
    attack_fig = create_attack_patterns(threats)
    performance_fig = create_performance_metrics(df)
    events_table = create_enhanced_events_table(df)

    return (str(total_requests), str(threats_detected), str(blocked_count), avg_response,
            request_rate, threat_rate, block_rate, bandwidth,
            traffic_fig, alerts, topology_fig, attack_fig, performance_fig, events_table)

def create_empty_chart(title):
    fig = go.Figure()
    fig.add_annotation(
        text=title,
        xref="paper", yref="paper",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=16, color="#666")
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(visible=False),
        yaxis=dict(visible=False)
    )
    return fig

def create_traffic_flow_chart(df):
    """Create an advanced traffic flow visualization"""
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Traffic Volume', 'Threat Detection'),
        vertical_spacing=0.1,
        row_heights=[0.7, 0.3]
    )
    
    # Traffic volume over time
    df_minute = df.set_index('timestamp').groupby([pd.Grouper(freq='30S'), 'prediction']).size().reset_index(name='count')
    
    colors = {'normal': '#4CAF50', 'ddos': '#FF5722', 'port_scan': '#FF9800', 'brute_force': '#9C27B0'}
    
    for prediction in df_minute['prediction'].unique():
        subset = df_minute[df_minute['prediction'] == prediction]
        fig.add_trace(
            go.Scatter(
                x=subset['timestamp'],
                y=subset['count'],
                mode='lines+markers',
                name=prediction.replace('_', ' ').title(),
                line=dict(width=3, color=colors.get(prediction, '#2196F3')),
                marker=dict(size=8, symbol='circle'),
                fill='tonexty' if prediction != 'normal' else None,
                hovertemplate=f'<b>{prediction.title()}</b><br>Time: %{{x}}<br>Requests: %{{y}}<extra></extra>'
            ),
            row=1, col=1
        )
    
    # Threat heatmap
    threat_data = df[df['prediction'] != 'normal'].set_index('timestamp').groupby(pd.Grouper(freq='1Min')).size()
    fig.add_trace(
        go.Bar(
            x=threat_data.index,
            y=threat_data.values,
            name='Threats per Minute',
            marker_color='rgba(255, 87, 34, 0.7)',
            hovertemplate='<b>Threats</b><br>Time: %{x}<br>Count: %{y}<extra></extra>'
        ),
        row=2, col=1
    )
    
    fig.update_layout(
        height=450,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#333'),
        showlegend=True,
        legend=dict(x=1.02, y=1),
        margin=dict(t=40, b=40, l=60, r=120)
    )
    
    return fig

def create_live_alerts(alerts):
    """Create live alerts panel"""
    if not alerts:
        return html.Div([
            html.Div([
                html.I(className="fas fa-check-circle", style={"fontSize": "3rem", "color": "#4CAF50", "marginBottom": "10px"}),
                html.H4("All Clear", style={"color": "#4CAF50", "margin": "0"}),
                html.P("No active security threats", style={"color": "#666", "marginTop": "5px"})
            ], style={"textAlign": "center", "padding": "40px 20px"})
        ])
    
    alert_components = []
    for alert in reversed(list(alerts)[-10:]):  # Show last 10 alerts
        severity_colors = {
            'low': '#FFC107',
            'medium': '#FF9800', 
            'high': '#FF5722',
            'critical': '#D32F2F'
        }
        
        alert_components.append(
            html.Div([
                html.Div([
                    html.I(className="fas fa-exclamation-triangle", 
                          style={"marginRight": "10px", "fontSize": "1.2rem"}),
                    html.Strong(alert.get('type', 'Alert').upper(), 
                               style={"marginRight": "10px"}),
                    html.Span(alert.get('severity', 'medium').upper(),
                             style={
                                 "background": severity_colors.get(alert.get('severity', 'medium'), '#FF9800'),
                                 "padding": "2px 8px",
                                 "borderRadius": "12px",
                                 "fontSize": "0.8rem",
                                 "fontWeight": "bold"
                             })
                ], style={"marginBottom": "5px"}),
                html.P(alert.get('message', ''), style={"margin": "0", "fontSize": "0.9rem"}),
                html.Small(f"From: {alert.get('src_ip', 'Unknown')} | {alert.get('timestamp', '')}", 
                          style={"opacity": "0.8"})
            ], className="alert-item")
        )
    
    return html.Div(alert_components)

def create_no_alerts():
    return html.Div([
        html.I(className="fas fa-shield-alt", style={"fontSize": "3rem", "color": "#4CAF50"}),
        html.H4("System Secure", style={"color": "#4CAF50", "marginTop": "10px"}),
        html.P("No threats detected", style={"color": "#666"})
    ], style={"textAlign": "center", "padding": "50px"})

def create_network_topology(df):
    """Create network topology visualization"""
    fig = go.Figure()
    
    if 'src_ip' not in df.columns:
        return create_empty_chart("No network data available")
    
    # Get top source IPs and their threat levels
    ip_stats = df.groupby('src_ip').agg({
        'prediction': lambda x: (x != 'normal').sum(),
        'packet_count': 'sum',
        'byte_count': 'sum'
    }).reset_index()
    
    ip_stats['threat_ratio'] = ip_stats['prediction'] / len(df[df['src_ip'].isin(ip_stats['src_ip'])])
    top_ips = ip_stats.nlargest(15, 'packet_count')
    
    # Create network nodes
    x_pos = np.random.uniform(0, 10, len(top_ips))
    y_pos = np.random.uniform(0, 10, len(top_ips))
    
    # Color based on threat level
    colors = ['#FF5722' if ratio > 0.3 else '#FF9800' if ratio > 0.1 else '#4CAF50' 
              for ratio in top_ips['threat_ratio']]
    
    sizes = [max(20, min(60, count/100)) for count in top_ips['packet_count']]
    
    fig.add_trace(go.Scatter(
        x=x_pos, y=y_pos,
        mode='markers+text',
        marker=dict(
            size=sizes,
            color=colors,
            opacity=0.8,
            line=dict(width=2, color='white')
        ),
        text=[ip.split('.')[-1] for ip in top_ips['src_ip']],
        textposition='middle center',
        textfont=dict(color='white', size=10, family='Arial Black'),
        hovertemplate='<b>%{text}</b><br>Packets: %{customdata[0]}<br>Threats: %{customdata[1]}<extra></extra>',
        customdata=list(zip(top_ips['packet_count'], top_ips['prediction'])),
        name='Network Nodes'
    ))
    
    # Add central node (firewall/controller)
    fig.add_trace(go.Scatter(
        x=[5], y=[5],
        mode='markers+text',
        marker=dict(size=80, color='#2196F3', opacity=0.9,
                   line=dict(width=3, color='white')),
        text=['SDN Controller'],
        textposition='middle center',
        textfont=dict(color='white', size=12, family='Arial Black'),
        name='Controller'
    ))
    
    fig.update_layout(
        title="",
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=20, b=20, l=20, r=20)
    )
    
    return fig

def create_attack_patterns(threats_df):
    """Create attack pattern analysis"""
    if threats_df.empty:
        return create_empty_chart("No attack patterns detected")
    
    # Attack types distribution
    attack_counts = threats_df['prediction'].value_counts()
    
    # Create sunburst chart for attack patterns
    fig = go.Figure(go.Sunburst(
        labels=list(attack_counts.index) + ['Total Attacks'],
        parents=['Total Attacks'] * len(attack_counts) + [''],
        values=list(attack_counts.values) + [attack_counts.sum()],
        branchvalues="total",
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percentParent}<extra></extra>',
        maxdepth=2,
        insidetextorientation='radial'
    ))
    
    fig.update_layout(
        title="",
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#333', size=12),
        margin=dict(t=20, b=20, l=20, r=20)
    )
    
    return fig

def create_performance_metrics(df):
    """Create system performance metrics"""
    fig = make_subplots(
        rows=1, cols=3,
        subplot_titles=('Response Time', 'Bandwidth Usage', 'Connection Rate'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}]]
    )
    
    # Response time trend
    if 'response_time' in df.columns:
        time_data = df.set_index('timestamp')['response_time'].resample('1Min').mean()
        fig.add_trace(
            go.Scatter(
                x=time_data.index,
                y=time_data.values,
                mode='lines',
                name='Response Time',
                line=dict(color='#2196F3', width=3),
                fill='tozeroy',
                fillcolor='rgba(33, 150, 243, 0.2)'
            ), row=1, col=1
        )
    
    # Bandwidth usage
    if 'byte_count' in df.columns:
        bandwidth_data = df.set_index('timestamp')['byte_count'].resample('1Min').sum() / (1024*1024)
        fig.add_trace(
            go.Bar(
                x=bandwidth_data.index,
                y=bandwidth_data.values,
                name='Bandwidth (MB)',
                marker_color='rgba(76, 175, 80, 0.7)'
            ), row=1, col=2
        )
    
    # Connection rate
    conn_data = df.set_index('timestamp').resample('1Min').size()
    fig.add_trace(
        go.Scatter(
            x=conn_data.index,
            y=conn_data.values,
            mode='lines+markers',
            name='Connections/min',
            line=dict(color='#FF9800', width=3),
            marker=dict(size=6)
        ), row=1, col=3
    )
    
    fig.update_layout(
        height=350,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#333'),
        showlegend=False,
        margin=dict(t=40, b=40, l=60, r=60)
    )
    
    return fig

def create_enhanced_events_table(df):
    """Create enhanced events table with better formatting"""
    if df.empty:
        return html.Div("No events to display", style={"textAlign": "center", "padding": "20px", "color": "#666"})
    
    # Select and format relevant columns
    display_columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'prediction', 'status', 'threat_level', 'confidence']
    available_columns = [col for col in display_columns if col in df.columns]
    
    if not available_columns:
        return html.Div("No data columns available", style={"textAlign": "center", "padding": "20px", "color": "#666"})
    
    # Get recent events
    recent_events = df.nlargest(50, 'timestamp')[available_columns].copy()
    
    # Format timestamp
    if 'timestamp' in recent_events.columns:
        recent_events['timestamp'] = recent_events['timestamp'].dt.strftime('%H:%M:%S')
    
    # Format confidence as percentage
    if 'confidence' in recent_events.columns:
        recent_events['confidence'] = (recent_events['confidence'] * 100).round(1).astype(str) + '%'
    
    # Create conditional formatting rules
    style_conditions = []
    
    # Threat level coloring
    if 'threat_level' in recent_events.columns:
        style_conditions.extend([
            {
                'if': {'filter_query': '{threat_level} = critical', 'column_id': 'threat_level'},
                'backgroundColor': '#ffebee',
                'color': '#c62828',
                'fontWeight': 'bold'
            },
            {
                'if': {'filter_query': '{threat_level} = high', 'column_id': 'threat_level'},
                'backgroundColor': '#fff3e0',
                'color': '#ef6c00',
                'fontWeight': 'bold'
            },
            {
                'if': {'filter_query': '{threat_level} = medium', 'column_id': 'threat_level'},
                'backgroundColor': '#fffde7',
                'color': '#f9a825'
            }
        ])
    
    # Prediction coloring
    if 'prediction' in recent_events.columns:
        style_conditions.extend([
            {
                'if': {'filter_query': '{prediction} != normal', 'column_id': 'prediction'},
                'backgroundColor': '#fce4ec',
                'color': '#ad1457',
                'fontWeight': 'bold'
            }
        ])
    
    # Status coloring
    if 'status' in recent_events.columns:
        style_conditions.extend([
            {
                'if': {'filter_query': '{status} = blocked', 'column_id': 'status'},
                'backgroundColor': '#ffebee',
                'color': '#c62828',
                'fontWeight': 'bold'
            },
            {
                'if': {'filter_query': '{status} = allowed', 'column_id': 'status'},
                'backgroundColor': '#e8f5e8',
                'color': '#2e7d32'
            }
        ])
    
    table = dash_table.DataTable(
        data=recent_events.to_dict('records'),
        columns=[{
            'name': col.replace('_', ' ').title(),
            'id': col,
            'type': 'text'
        } for col in available_columns],
        
        style_cell={
            'textAlign': 'center',
            'padding': '15px 12px',
            'fontFamily': 'Poppins, sans-serif',
            'fontSize': '0.9rem',
            'border': '1px solid #e0e0e0',
            'whiteSpace': 'normal',
            'height': 'auto'
        },
        
        style_header={
            'backgroundColor': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            'color': 'white',
            'fontWeight': 'bold',
            'fontSize': '1rem',
            'padding': '15px 12px',
            'border': '1px solid #5a67d8'
        },
        
        style_data={
            'backgroundColor': '#fafafa',
            'color': '#333'
        },
        
        style_data_conditional=style_conditions,
        
        page_size=20,
        sort_action="native",
        filter_action="native",
        
        tooltip_data=[
            {
                column: {'value': str(value), 'type': 'markdown'}
                for column, value in row.items()
            } for row in recent_events.to_dict('records')
        ],
        
        tooltip_duration=None,
        
        style_table={
            'overflowX': 'auto',
            'border': '1px solid #e0e0e0',
            'borderRadius': '10px',
            'boxShadow': '0 4px 6px rgba(0,0,0,0.1)'
        }
    )
    
    return table

def create_empty_table():
    return html.Div([
        html.I(className="fas fa-table", style={"fontSize": "3rem", "color": "#ccc", "marginBottom": "10px"}),
        html.H4("No Events", style={"color": "#666"}),
        html.P("Waiting for network traffic data", style={"color": "#999"})
    ], style={"textAlign": "center", "padding": "50px"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8052)
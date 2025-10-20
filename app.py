import dash
from dash import dcc, html, dash_table, Input, Output, State
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import zmq
import json
import threading
from datetime import datetime, timedelta
import numpy as np
import time
from collections import deque

# ========== CONFIGURATION ==========
ZMQ_ADDRESS = "tcp://localhost:5555"
MAX_EVENTS = 5000
UPDATE_INTERVAL = 500  # ms

# ========== GLOBAL DATA STORE ==========
traffic_events = deque(maxlen=MAX_EVENTS)
alert_queue = deque(maxlen=100)
system_stats = {
    'total_requests': 0,
    'threats_detected': 0,
    'blocked_count': 0,
    'avg_response_time': 0,
    'total_bandwidth': 0,
    'start_time': datetime.now(),
    'last_event_time': None,
    'connection_status': 'Connecting...'
}

blocked_ips_set = set()
is_paused = False
zmq_connected = False

# ========== ZMQ SUBSCRIBER ==========
def zmq_subscriber():
    """Real-time ZMQ subscriber thread"""
    global traffic_events, alert_queue, system_stats, blocked_ips_set, zmq_connected
    
    context = zmq.Context()
    subscriber = context.socket(zmq.SUB)
    
    try:
        subscriber.connect(ZMQ_ADDRESS)
        subscriber.setsockopt_string(zmq.SUBSCRIBE, "")
        subscriber.setsockopt(zmq.RCVTIMEO, 1000)
        zmq_connected = True
        system_stats['connection_status'] = 'Connected'
        print(f"✅ Connected to ZMQ at {ZMQ_ADDRESS}")
    except Exception as e:
        print(f"❌ ZMQ Connection Failed: {e}")
        zmq_connected = False
        system_stats['connection_status'] = 'Disconnected'
        return
    
    while True:
        try:
            if not is_paused:
                message = subscriber.recv_string(flags=zmq.NOBLOCK)
                event = json.loads(message)
                
                traffic_events.append(event)
                system_stats['total_requests'] += 1
                system_stats['last_event_time'] = datetime.now()
                
                if event.get('prediction') != 'normal':
                    system_stats['threats_detected'] += 1
                
                if event.get('status') == 'blocked':
                    system_stats['blocked_count'] += 1
                    blocked_ips_set.add(event.get('src_ip'))
                
                system_stats['avg_response_time'] = event.get('response_time', 0)
                system_stats['total_bandwidth'] += event.get('byte_count', 0)
                
                if event.get('threat_level') in ['high', 'critical']:
                    alert = {
                        'timestamp': event['timestamp'],
                        'type': event.get('prediction', 'threat'),
                        'src_ip': event.get('src_ip'),
                        'severity': event.get('threat_level'),
                        'message': f"{event.get('prediction', 'unknown').upper()}: {event.get('src_ip')} → {event.get('dst_ip')}:{event.get('dst_port')}"
                    }
                    alert_queue.append(alert)
                    print(f"🚨 ALERT: {alert['message']}")
                
                zmq_connected = True
                system_stats['connection_status'] = 'Connected'
                
        except zmq.Again:
            time.sleep(0.01)
        except Exception as e:
            print(f"⚠️ Subscriber error: {e}")
            zmq_connected = False
            system_stats['connection_status'] = 'Error'
            time.sleep(1)

# Start subscriber thread
subscriber_thread = threading.Thread(target=zmq_subscriber, daemon=True)
subscriber_thread.start()

# ========== DASH APP ==========
app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "SDN DDoS Defense - Real-Time Monitor"

# Enhanced Modern CSS
app.index_string = '''
<!DOCTYPE html>
<html>
<head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0e27;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            z-index: -1;
            animation: bgShift 20s ease infinite;
        }
        
        @keyframes bgShift {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.1); }
        }
        
        .header-bar {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.95) 0%, rgba(31, 41, 55, 0.95) 100%);
            backdrop-filter: blur(20px) saturate(180%);
            border-bottom: 1px solid rgba(99, 102, 241, 0.2);
            padding: 28px 40px;
            margin-bottom: 32px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }
        
        .header-content {
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .header-title {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .header-title h1 {
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 50%, #ec4899 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }
        
        .header-icon {
            font-size: 2.5rem;
            color: #60a5fa;
            filter: drop-shadow(0 0 10px rgba(96, 165, 250, 0.5));
            animation: pulse 3s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .header-status {
            display: flex;
            align-items: center;
            gap: 24px;
        }
        
        .main-container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 0 24px 40px;
        }
        
        .control-panel {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.8) 0%, rgba(31, 41, 55, 0.8) 100%);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 32px;
            border: 1px solid rgba(99, 102, 241, 0.2);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
        }
        
        .control-buttons {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }
        
        .btn-modern {
            padding: 12px 28px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            border-radius: 10px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-modern:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
        }
        
        .btn-modern:active {
            transform: translateY(0);
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 24px;
            margin-bottom: 32px;
        }
        
        .metric-card {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(31, 41, 55, 0.9) 100%);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 28px;
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(99, 102, 241, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--card-color), transparent);
        }
        
        .metric-card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: 0 12px 48px rgba(0, 0, 0, 0.4);
            border-color: var(--card-color);
        }
        
        .metric-icon {
            font-size: 3rem;
            margin-bottom: 16px;
            opacity: 0.9;
            filter: drop-shadow(0 4px 8px rgba(0, 0, 0, 0.3));
        }
        
        .metric-value {
            font-size: 3rem;
            font-weight: 900;
            line-height: 1;
            margin: 16px 0 12px;
            color: var(--card-color);
            text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }
        
        .metric-label {
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: rgba(255, 255, 255, 0.6);
        }
        
        .chart-card {
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(31, 41, 55, 0.9) 100%);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 28px;
            margin-bottom: 24px;
            border: 1px solid rgba(99, 102, 241, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s ease;
        }
        
        .chart-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }
        
        .chart-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: #e5e7eb;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            padding-bottom: 16px;
            border-bottom: 2px solid rgba(99, 102, 241, 0.2);
        }
        
        .chart-title i {
            color: #60a5fa;
            filter: drop-shadow(0 2px 4px rgba(96, 165, 250, 0.3));
        }
        
        .alert-high, .alert-critical {
            border-radius: 12px;
            padding: 20px;
            margin: 12px 0;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
            animation: slideInRight 0.4s ease-out;
            backdrop-filter: blur(10px);
        }
        
        .alert-high {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.9) 0%, rgba(220, 38, 38, 0.9) 100%);
            border: 1px solid rgba(239, 68, 68, 0.5);
            color: white;
        }
        
        .alert-critical {
            background: linear-gradient(135deg, rgba(220, 38, 38, 0.95) 0%, rgba(185, 28, 28, 0.95) 100%);
            border: 1px solid rgba(220, 38, 38, 0.6);
            color: white;
            animation: pulseAlert 1.5s infinite, slideInRight 0.4s ease-out;
        }
        
        @keyframes pulseAlert {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.85; transform: scale(0.98); }
        }
        
        @keyframes slideInRight {
            from { opacity: 0; transform: translateX(30px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            animation: statusPulse 2s infinite;
        }
        
        .status-connected {
            background: #10b981;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.6);
        }
        
        .status-disconnected {
            background: #ef4444;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.6);
        }
        
        @keyframes statusPulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.3); opacity: 0.7; }
        }
        
        .live-indicator {
            display: inline-flex;
            align-items: center;
            background: rgba(16, 185, 129, 0.15);
            padding: 8px 16px;
            border-radius: 24px;
            border: 1px solid rgba(16, 185, 129, 0.3);
            font-weight: 600;
            color: #10b981;
        }
        
        .live-indicator::before {
            content: '●';
            color: #10b981;
            font-size: 1.2rem;
            margin-right: 8px;
            animation: blink 1.5s infinite;
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .blocked-port-card {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%);
            border: 2px solid rgba(239, 68, 68, 0.5);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 4px 16px rgba(239, 68, 68, 0.2);
            transition: all 0.3s ease;
            animation: slideInUp 0.4s ease-out;
        }
        
        @keyframes slideInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .blocked-port-card:hover {
            transform: translateX(4px);
            box-shadow: 0 6px 24px rgba(239, 68, 68, 0.3);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%);
        }
        
        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge-critical {
            background: linear-gradient(135deg, #dc2626, #991b1b);
            color: white;
            box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4);
        }
        
        .badge-blocked {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }
        
        .filter-button-group {
            display: inline-flex;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(99, 102, 241, 0.2);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: rgba(255, 255, 255, 0.5);
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.4;
        }
        
        .empty-state h4 {
            color: rgba(255, 255, 255, 0.7);
            font-size: 1.25rem;
            margin-top: 16px;
            font-weight: 700;
        }
        
        .empty-state p {
            color: rgba(255, 255, 255, 0.5);
            margin-top: 8px;
        }
        
        .grid-2col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }
        
        .grid-65-35 {
            display: grid;
            grid-template-columns: 65fr 35fr;
            gap: 24px;
        }
        
        @media (max-width: 1200px) {
            .grid-2col, .grid-65-35 {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                text-align: center;
            }
            
            .control-buttons {
                flex-direction: column;
                width: 100%;
            }
            
            .btn-modern {
                width: 100%;
                justify-content: center;
            }
        }
        
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(17, 24, 39, 0.5);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        }
        
        .dash-table-container {
            border-radius: 12px;
            overflow: hidden;
        }
        
        .dash-table-container .dash-spreadsheet-container {
            max-height: 600px;
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

# ========== LAYOUT ==========
app.layout = html.Div([
    html.Div([
        html.Div([
            html.Div([
                html.I(className="fas fa-shield-virus header-icon"),
                html.H1("SDN DDoS Defense System")
            ], className='header-title'),
            
            html.Div([
                html.Div(id='connection-status', className='live-indicator'),
                html.Div([
                    html.I(className="fas fa-clock", style={'marginRight': '8px', 'color': '#60a5fa'}),
                    html.Span(id='live-clock', style={'color': '#e5e7eb', 'fontSize': '1rem', 'fontWeight': '600'})
                ], style={'display': 'flex', 'alignItems': 'center'})
            ], className='header-status')
        ], className='header-content')
    ], className='header-bar'),
    
    html.Div([
        html.Div([
            html.Div([
                html.Button([html.I(className="fas fa-pause"), 'Pause'], 
                           id='pause-btn', n_clicks=0, className='btn-modern',
                           style={'background': 'linear-gradient(135deg, #f59e0b, #d97706)', 'color': 'white'}),
                
                html.Button([html.I(className="fas fa-trash-alt"), 'Clear Data'], 
                           id='clear-btn', n_clicks=0, className='btn-modern',
                           style={'background': 'linear-gradient(135deg, #ef4444, #dc2626)', 'color': 'white'}),
                
                html.Div([
                    html.Button([html.I(className="fas fa-chart-line"), 'All Traffic'], 
                               id='filter-all-btn', n_clicks=0, className='btn-modern',
                               style={'background': 'linear-gradient(135deg, #3b82f6, #2563eb)', 'color': 'white', 
                                      'borderRadius': '10px 0 0 10px'}),
                    html.Button([html.I(className="fas fa-exclamation-triangle"), 'Attacks Only'], 
                               id='filter-attack-btn', n_clicks=0, className='btn-modern',
                               style={'background': 'linear-gradient(135deg, #ec4899, #db2777)', 'color': 'white', 
                                      'borderRadius': '0', 'marginLeft': '-1px'}),
                    html.Button([html.I(className="fas fa-check-circle"), 'Normal Only'], 
                               id='filter-normal-btn', n_clicks=0, className='btn-modern',
                               style={'background': 'linear-gradient(135deg, #10b981, #059669)', 'color': 'white', 
                                      'borderRadius': '0 10px 10px 0', 'marginLeft': '-1px'}),
                ], className='filter-button-group'),
            ], className='control-buttons')
        ], className='control-panel'),
        
        dcc.Store(id='pause-state', data=False),
        dcc.Store(id='filter-state', data='all'),
        dcc.Interval(id='fast-update', interval=UPDATE_INTERVAL, n_intervals=0),
        dcc.Interval(id='clock-update', interval=1000, n_intervals=0),
        
        html.Div([
            html.Div([
                html.I(className="fas fa-network-wired metric-icon", style={'color': '#3b82f6'}),
                html.H2(id='metric-total', children='0', className='metric-value'),
                html.P('Total Requests', className='metric-label')
            ], className='metric-card', style={'--card-color': '#3b82f6'}),
            
            html.Div([
                html.I(className="fas fa-skull-crossbones metric-icon", style={'color': '#ef4444'}),
                html.H2(id='metric-threats', children='0', className='metric-value'),
                html.P('Threats Detected', className='metric-label')
            ], className='metric-card', style={'--card-color': '#ef4444'}),
            
            html.Div([
                html.I(className="fas fa-ban metric-icon", style={'color': '#f59e0b'}),
                html.H2(id='metric-blocked', children='0', className='metric-value'),
                html.P('Blocked IPs', className='metric-label')
            ], className='metric-card', style={'--card-color': '#f59e0b'}),
            
            html.Div([
                html.I(className="fas fa-tachometer-alt metric-icon", style={'color': '#10b981'}),
                html.H2(id='metric-response', children='0ms', className='metric-value'),
                html.P('Response Time', className='metric-label')
            ], className='metric-card', style={'--card-color': '#10b981'}),
        ], className='metrics-grid'),
        
        html.Div([
            html.Div([
                html.Div([
                    html.I(className="fas fa-chart-area"),
                    html.Span('Real-Time Traffic Flow')
                ], className='chart-title'),
                dcc.Graph(id='traffic-chart', style={'height': '420px'}, config={'displayModeBar': False})
            ], className='chart-card'),
            
            html.Div([
                html.Div([
                    html.I(className="fas fa-bell"),
                    html.Span('Live Security Alerts')
                ], className='chart-title'),
                html.Div(id='alerts-panel', style={'maxHeight': '420px', 'overflowY': 'auto'})
            ], className='chart-card'),
        ], className='grid-65-35'),
        
        html.Div([
            html.Div([
                html.Div([
                    html.I(className="fas fa-chart-pie"),
                    html.Span('Attack Distribution')
                ], className='chart-title'),
                dcc.Graph(id='attack-dist', style={'height': '360px'}, config={'displayModeBar': False})
            ], className='chart-card'),
            
            html.Div([
                html.Div([
                    html.I(className="fas fa-shield-alt"),
                    html.Span('Blocked Ports Monitor')
                ], className='chart-title'),
                html.Div(id='blocked-ports-panel', style={'maxHeight': '360px', 'overflowY': 'auto'})
            ], className='chart-card'),
        ], className='grid-2col'),
        
        html.Div([
            html.Div([
                html.I(className="fas fa-crosshairs"),
                html.Span('Top Threat Sources')
            ], className='chart-title'),
            dcc.Graph(id='top-sources', style={'height': '360px'}, config={'displayModeBar': False})
        ], className='chart-card'),
        
        html.Div([
            html.Div([
                html.I(className="fas fa-table"),
                html.Span('Network Security Events Log')
            ], className='chart-title'),
            html.Div(id='events-table')
        ], className='chart-card'),
        
    ], className='main-container')
], style={'minHeight': '100vh'})

# ========== HELPER FUNCTIONS ==========

def create_traffic_chart(df, filter_text="All Traffic"):
    """Real-time traffic flow chart"""
    fig = make_subplots(rows=1, cols=1)
    
    if df.empty:
        fig.add_annotation(text="No data available", x=0.5, y=0.5, showarrow=False, 
                          font=dict(size=16, color='#9ca3af'))
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=40, r=40, t=40, b=40)
        )
        return fig
    
    df_time = df.set_index('timestamp').groupby([pd.Grouper(freq='5S'), 'prediction']).size().reset_index(name='count')
    
    colors = {
        'normal': '#10b981',
        'ddos': '#ef4444',
        'port_scan': '#f59e0b',
        'brute_force': '#a855f7'
    }
    
    for pred in df_time['prediction'].unique():
        subset = df_time[df_time['prediction'] == pred]
        fig.add_trace(go.Scatter(
            x=subset['timestamp'],
            y=subset['count'],
            mode='lines+markers',
            name=pred.upper(),
            line=dict(width=3, color=colors.get(pred, '#60a5fa')),
            marker=dict(size=6),
            fill='tonexty' if pred != 'normal' else None
        ))
    
    fig.update_layout(
        title=dict(text=f"<b>{filter_text}</b>", font=dict(size=13, color='#9ca3af'), x=0.5, xanchor='center'),
        xaxis_title='Time',
        yaxis_title='Packet Count',
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(17, 24, 39, 0.5)',
        hovermode='x unified',
        margin=dict(l=40, r=40, t=50, b=40),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1, 
                   font=dict(color='#e5e7eb')),
        font=dict(color='#e5e7eb'),
        xaxis=dict(gridcolor='rgba(99, 102, 241, 0.1)', color='#9ca3af'),
        yaxis=dict(gridcolor='rgba(99, 102, 241, 0.1)', color='#9ca3af')
    )
    
    return fig

def create_alerts_panel():
    """Create modern live alerts panel"""
    if not alert_queue:
        return html.Div([
            html.I(className="fas fa-shield-check", style={'fontSize': '4rem', 'color': '#10b981'}),
            html.H4('System Secure', style={'color': '#10b981', 'marginTop': '16px', 'fontWeight': '700'}),
            html.P('No active security threats detected', style={'color': '#9ca3af', 'marginTop': '8px'})
        ], className='empty-state')
    
    alerts_html = []
    for alert in reversed(list(alert_queue)[-15:]):
        severity_class = f"alert-{alert['severity']}" if alert['severity'] in ['high', 'critical'] else ''
        icon_class = "fas fa-skull-crossbones" if alert['severity'] == 'critical' else "fas fa-exclamation-triangle"
        
        alerts_html.append(html.Div([
            html.Div([
                html.I(className=icon_class, style={'marginRight': '12px', 'fontSize': '1.3rem'}),
                html.Strong(alert['type'].upper(), style={'fontSize': '1.1rem', 'letterSpacing': '0.5px'}),
                html.Span(
                    alert['severity'].upper(),
                    className='badge badge-critical' if alert['severity'] in ['high', 'critical'] else 'badge',
                    style={'marginLeft': '12px'}
                )
            ], style={'marginBottom': '10px', 'display': 'flex', 'alignItems': 'center'}),
            html.P(alert['message'], style={'margin': '8px 0', 'fontSize': '0.95rem', 'lineHeight': '1.5'}),
            html.Div([
                html.I(className="fas fa-map-marker-alt", style={'marginRight': '6px', 'fontSize': '0.85rem'}),
                html.Small(f"{alert['src_ip']}", style={'opacity': '0.9', 'marginRight': '16px'}),
                html.I(className="fas fa-clock", style={'marginRight': '6px', 'fontSize': '0.85rem'}),
                html.Small(alert['timestamp'][:19], style={'opacity': '0.9'})
            ], style={'display': 'flex', 'alignItems': 'center', 'marginTop': '8px'})
        ], className=severity_class))
    
    return html.Div(alerts_html)

def create_blocked_ports_panel(df):
    """Create modern blocked ports monitoring panel"""
    port_blocked = df[df['status'] == 'port_blocked']
    
    if port_blocked.empty:
        return html.Div([
            html.I(className="fas fa-lock-open", style={'fontSize': '4rem', 'color': '#10b981'}),
            html.H4('All Ports Open', style={'color': '#10b981', 'marginTop': '16px', 'fontWeight': '700'}),
            html.P('No ports are currently blocked', style={'color': '#9ca3af', 'marginTop': '8px'})
        ], className='empty-state')
    
    port_stats = port_blocked.groupby('dst_port').agg({
        'src_ip': 'count',
        'timestamp': 'max'
    }).reset_index()
    port_stats.columns = ['port', 'attack_count', 'last_attack']
    port_stats = port_stats.sort_values('attack_count', ascending=False)
    
    port_items = []
    for _, row in port_stats.head(10).iterrows():
        port_items.append(html.Div([
            html.Div([
                html.Div([
                    html.I(className="fas fa-shield-alt", style={'fontSize': '2rem', 'color': '#ef4444', 'marginRight': '16px'}),
                    html.Div([
                        html.Strong(f"Port {row['port']}", style={'fontSize': '1.4rem', 'color': '#e5e7eb', 'display': 'block'}),
                        html.Small(f"{row['attack_count']} attack attempts", style={'color': '#9ca3af', 'fontSize': '0.9rem'})
                    ])
                ], style={'display': 'flex', 'alignItems': 'center', 'marginBottom': '12px'}),
                html.Div([
                    html.Span('BLOCKED', className='badge badge-blocked', style={'marginRight': '12px'}),
                    html.Span([
                        html.I(className="fas fa-clock", style={'marginRight': '6px'}),
                        f"Last: {row['last_attack'].strftime('%H:%M:%S') if hasattr(row['last_attack'], 'strftime') else str(row['last_attack'])[:8]}"
                    ], style={'color': '#9ca3af', 'fontSize': '0.9rem'})
                ], style={'display': 'flex', 'alignItems': 'center'})
            ])
        ], className='blocked-port-card'))
    
    return html.Div(port_items)

def create_attack_distribution(df):
    """Attack types pie chart"""
    threats = df[df['prediction'] != 'normal']
    
    if threats.empty:
        fig = go.Figure()
        fig.add_annotation(text="No Threats Detected", x=0.5, y=0.5, showarrow=False, 
                          font=dict(size=16, color='#9ca3af'))
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=20, b=20)
        )
        return fig
    
    attack_counts = threats['prediction'].value_counts()
    
    fig = go.Figure(data=[go.Pie(
        labels=attack_counts.index,
        values=attack_counts.values,
        hole=0.4,
        marker=dict(colors=['#ef4444', '#f59e0b', '#a855f7', '#ec4899']),
        textinfo='label+percent',
        textfont=dict(size=12, color='white')
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=True,
        legend=dict(orientation='h', yanchor='bottom', y=-0.2, font=dict(color='#e5e7eb')),
        font=dict(color='#e5e7eb')
    )
    
    return fig

def create_top_sources(df):
    """Top threat sources bar chart"""
    threats = df[df['prediction'] != 'normal']
    
    if threats.empty:
        fig = go.Figure()
        fig.add_annotation(text="No Threat Sources", x=0.5, y=0.5, showarrow=False, 
                          font=dict(size=16, color='#9ca3af'))
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            margin=dict(l=20, r=20, t=20, b=20)
        )
        return fig
    
    top_ips = threats['src_ip'].value_counts().head(10)
    
    fig = go.Figure(data=[go.Bar(
        x=top_ips.values,
        y=top_ips.index,
        orientation='h',
        marker=dict(
            color='#ef4444',
            line=dict(color='#dc2626', width=2)
        ),
        text=top_ips.values,
        textposition='auto',
        textfont=dict(color='white')
    )])
    
    fig.update_layout(
        xaxis_title='Threat Count',
        yaxis_title='Source IP',
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(17, 24, 39, 0.5)',
        margin=dict(l=150, r=40, t=20, b=40),
        font=dict(color='#e5e7eb'),
        xaxis=dict(gridcolor='rgba(99, 102, 241, 0.1)', color='#9ca3af'),
        yaxis=dict(gridcolor='rgba(99, 102, 241, 0.1)', color='#9ca3af')
    )
    
    return fig

def create_events_table(df):
    """Recent events table"""
    if df.empty:
        return html.Div("No events to display", className='empty-state')
    
    recent = df.nlargest(50, 'timestamp').copy()
    recent['timestamp'] = recent['timestamp'].dt.strftime('%H:%M:%S')
    
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
               'prediction', 'status', 'threat_level', 'packet_count', 'byte_count']
    
    available_cols = [c for c in columns if c in recent.columns]
    display_df = recent[available_cols]
    
    style_conditions = [
        {
            'if': {'filter_query': '{prediction} != "normal"', 'column_id': 'prediction'},
            'backgroundColor': 'rgba(239, 68, 68, 0.2)',
            'color': '#fca5a5',
            'fontWeight': 'bold'
        },
        {
            'if': {'filter_query': '{status} = "blocked"', 'column_id': 'status'},
            'backgroundColor': 'rgba(239, 68, 68, 0.3)',
            'color': '#f87171',
            'fontWeight': 'bold'
        },
        {
            'if': {'filter_query': '{threat_level} = "critical"', 'column_id': 'threat_level'},
            'backgroundColor': '#dc2626',
            'color': 'white',
            'fontWeight': 'bold'
        },
        {
            'if': {'filter_query': '{threat_level} = "high"', 'column_id': 'threat_level'},
            'backgroundColor': '#f59e0b',
            'color': 'white'
        }
    ]
    
    table = dash_table.DataTable(
        data=display_df.to_dict('records'),
        columns=[{'name': c.replace('_', ' ').title(), 'id': c} for c in available_cols],
        style_cell={
            'textAlign': 'center',
            'padding': '12px',
            'fontSize': '0.875rem',
            'fontFamily': 'Inter, sans-serif',
            'backgroundColor': 'rgba(17, 24, 39, 0.8)',
            'color': '#e5e7eb',
            'border': '1px solid rgba(99, 102, 241, 0.2)'
        },
        style_header={
            'backgroundColor': 'rgba(59, 130, 246, 0.8)',
            'color': 'white',
            'fontWeight': 'bold',
            'fontSize': '0.9rem',
            'border': '1px solid rgba(99, 102, 241, 0.3)'
        },
        style_data_conditional=style_conditions,
        page_size=15,
        sort_action='native',
        filter_action='native',
        style_table={'overflowX': 'auto'}
    )
    
    return table

# ========== CALLBACKS ==========

@app.callback(
    [Output('metric-total', 'children'),
     Output('metric-threats', 'children'),
     Output('metric-blocked', 'children'),
     Output('metric-response', 'children'),
     Output('traffic-chart', 'figure'),
     Output('alerts-panel', 'children'),
     Output('attack-dist', 'figure'),
     Output('top-sources', 'figure'),
     Output('blocked-ports-panel', 'children'),
     Output('events-table', 'children')],
    [Input('fast-update', 'n_intervals')],
    [State('pause-state', 'data'),
     State('filter-state', 'data')]
)
def update_dashboard(n, paused, filter_mode):
    if paused:
        raise dash.exceptions.PreventUpdate
    
    if not traffic_events:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        return ('0', '0', '0', '0ms', empty_fig, 
                html.Div('No alerts', className='empty-state'), 
                empty_fig, empty_fig, 
                html.Div('No blocked ports', className='empty-state'), 
                html.Div())
    
    df = pd.DataFrame(list(traffic_events))
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_original = df.copy()
    
    if filter_mode == 'attack':
        df = df[df['prediction'] != 'normal']
        filter_text = "🚨 Showing Attacks Only"
        if df.empty:
            empty_msg = html.Div([
                html.I(className="fas fa-shield-alt", style={'fontSize': '3rem', 'color': '#10b981'}),
                html.H4('No Attacks Detected', style={'color': '#10b981', 'marginTop': '15px'}),
                html.P('System is secure - All traffic is normal', style={'color': '#9ca3af'})
            ], className='empty-state')
            empty_fig = go.Figure()
            empty_fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            return ('0', '0', '0', '0ms', empty_fig, empty_msg, empty_fig, empty_fig, 
                    html.Div('No blocked ports', className='empty-state'), empty_msg)
    elif filter_mode == 'normal':
        df = df[df['prediction'] == 'normal']
        filter_text = "✅ Showing Normal Traffic Only"
        if df.empty:
            empty_msg = html.Div([
                html.I(className="fas fa-exclamation-triangle", style={'fontSize': '3rem', 'color': '#f59e0b'}),
                html.H4('No Normal Traffic', style={'color': '#f59e0b', 'marginTop': '15px'}),
                html.P('All traffic is being flagged as threats', style={'color': '#9ca3af'})
            ], className='empty-state')
            empty_fig = go.Figure()
            empty_fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
            return ('0', '0', '0', '0ms', empty_fig, 
                    html.Div('All traffic blocked', className='empty-state'), 
                    empty_fig, empty_fig, 
                    html.Div('No blocked ports', className='empty-state'), empty_msg)
    else:
        filter_text = "📊 Showing All Traffic"
    
    total = len(df_original)
    threats = system_stats['threats_detected']
    blocked = len(blocked_ips_set)
    response = f"{system_stats['avg_response_time']:.1f}ms"
    
    traffic_fig = create_traffic_chart(df, filter_text)
    alerts_html = create_alerts_panel()
    attack_fig = create_attack_distribution(df_original)
    top_fig = create_top_sources(df_original)
    blocked_ports_html = create_blocked_ports_panel(df_original)
    table = create_events_table(df)
    
    return (str(total), str(threats), str(blocked), response, 
            traffic_fig, alerts_html, attack_fig, top_fig, 
            blocked_ports_html, table)

@app.callback(
    Output('pause-state', 'data'),
    [Input('pause-btn', 'n_clicks')],
    [State('pause-state', 'data')]
)
def toggle_pause(n, current):
    global is_paused
    if n:
        is_paused = not current
        return not current
    return False

@app.callback(
    Output('filter-state', 'data'),
    [Input('filter-all-btn', 'n_clicks'),
     Input('filter-attack-btn', 'n_clicks'),
     Input('filter-normal-btn', 'n_clicks')],
    [State('filter-state', 'data')]
)
def update_filter(all_clicks, attack_clicks, normal_clicks, current):
    ctx = dash.callback_context
    
    if not ctx.triggered:
        return 'all'
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'filter-all-btn':
        return 'all'
    elif button_id == 'filter-attack-btn':
        return 'attack'
    elif button_id == 'filter-normal-btn':
        return 'normal'
    
    return current

@app.callback(
    [Output('filter-all-btn', 'style'),
     Output('filter-attack-btn', 'style'),
     Output('filter-normal-btn', 'style')],
    [Input('filter-state', 'data')]
)
def update_filter_buttons(filter_mode):
    base_left = {
        'background': 'linear-gradient(135deg, #3b82f6, #2563eb)',
        'color': 'white',
        'borderRadius': '10px 0 0 10px',
        'opacity': '0.6'
    }
    base_mid = {
        'background': 'linear-gradient(135deg, #ec4899, #db2777)',
        'color': 'white',
        'borderRadius': '0',
        'marginLeft': '-1px',
        'opacity': '0.6'
    }
    base_right = {
        'background': 'linear-gradient(135deg, #10b981, #059669)',
        'color': 'white',
        'borderRadius': '0 10px 10px 0',
        'marginLeft': '-1px',
        'opacity': '0.6'
    }
    
    if filter_mode == 'all':
        base_left['opacity'] = '1'
        base_left['boxShadow'] = '0 0 20px rgba(59, 130, 246, 0.5)'
    elif filter_mode == 'attack':
        base_mid['opacity'] = '1'
        base_mid['boxShadow'] = '0 0 20px rgba(236, 72, 153, 0.5)'
    elif filter_mode == 'normal':
        base_right['opacity'] = '1'
        base_right['boxShadow'] = '0 0 20px rgba(16, 185, 129, 0.5)'
    
    return base_left, base_mid, base_right

@app.callback(
    Output('clear-btn', 'n_clicks'),
    [Input('clear-btn', 'n_clicks')]
)
def clear_data(n):
    if n:
        traffic_events.clear()
        alert_queue.clear()
        blocked_ips_set.clear()
        system_stats.update({
            'total_requests': 0,
            'threats_detected': 0,
            'blocked_count': 0
        })
    return 0

@app.callback(
    [Output('connection-status', 'children'),
     Output('live-clock', 'children')],
    [Input('clock-update', 'n_intervals')]
)
def update_status(n):
    status_text = f"Status: {system_stats['connection_status']}"
    clock_text = datetime.now().strftime('%H:%M:%S')
    return status_text, clock_text

# ========== RUN APP ==========
if __name__ == '__main__':
    print("🚀 Starting Modern Real-Time Dashboard...")
    print(f"📡 Listening to ZMQ: {ZMQ_ADDRESS}")
    print(f"🌐 Dashboard: http://localhost:8054")
    app.run(debug=True, host='localhost', port=8054)
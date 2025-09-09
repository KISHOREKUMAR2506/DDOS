import dash
from dash import dcc, html
from dash.dependencies import Output, Input
import plotly.express as px
import pandas as pd
import zmq
import json
import threading

# Global traffic data store
traffic_data = []

# Setup ZeroMQ Subscriber
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://localhost:5555")  # Connect to Ryu PUB
socket.setsockopt_string(zmq.SUBSCRIBE, "")

def listen_to_ryu():
    global traffic_data
    while True:
        try:
            msg = socket.recv_string()
            event = json.loads(msg)
            traffic_data.append(event)
        except Exception as e:
            print("Error receiving message:", e)

# Start listener thread
threading.Thread(target=listen_to_ryu, daemon=True).start()

# Dash app
app = dash.Dash(__name__)
app.title = "SDN DDoS Defense Dashboard"

app.layout = html.Div([
    html.H1(" Real-Time SDN DDoS Defense Dashboard", style={"textAlign": "center"}),

    dcc.Interval(id="update-interval", interval=2000, n_intervals=0),

    html.Div([
        html.Div([
            html.H3("📊 Traffic Overview"),
            dcc.Graph(id="traffic-graph")
        ], className="six columns"),

        html.Div([
            html.H3("🛡️ Mitigation Status"),
            dcc.Graph(id="mitigation-graph")
        ], className="six columns"),
    ], className="row"),

    html.Div([
        html.H3("🔎 Detailed Logs"),
        html.Div(id="log-table")
    ], style={"marginTop": "30px"})
], style={"padding": "20px", "fontFamily": "Arial"})

@app.callback(
    [Output("traffic-graph", "figure"),
     Output("mitigation-graph", "figure"),
     Output("log-table", "children")],
    [Input("update-interval", "n_intervals")]
)
def update_graphs(n):
    if not traffic_data:
        return px.bar(title="No data yet"), px.pie(title="No data yet"), "No logs yet"

    df = pd.DataFrame(traffic_data)

    # --- Traffic Overview ---
    fig1 = px.bar(
        df,
        x="src_ip",
        y="packet_count",
        color="prediction",
        title="Traffic by Source IP",
        barmode="stack"
    )

    # --- Mitigation Status ---
    fig2 = px.pie(
        df,
        names="status",
        title="Mitigation Results",
        hole=0.3
    )

    # --- Logs Table ---
    latest_df = df.tail(10)  # show last 10 events
    table = html.Table([
        html.Thead(html.Tr([html.Th(col) for col in latest_df.columns])),
        html.Tbody([
            html.Tr([html.Td(latest_df.iloc[i][col]) for col in latest_df.columns])
            for i in range(len(latest_df))
        ])
    ], style={"border": "1px solid black", "width": "100%", "textAlign": "center"})

    return fig1, fig2, table


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)

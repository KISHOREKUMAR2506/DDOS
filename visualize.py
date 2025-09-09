import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time

csv_file = "traffic_log.csv"

print("🌐 Starting Interactive Traffic Monitor...")
print("Press Ctrl+C to stop.")

while True:
    try:
        df = pd.read_csv(csv_file)

        if df.empty:
            time.sleep(2)
            continue

        # Ensure required columns exist
        if not {"src_ip","port","packet_count","byte_count","prediction"}.issubset(df.columns):
            print("❌ Missing columns in CSV")
            time.sleep(2)
            continue

        # 1️⃣ Line chart for packet/byte trends
        fig = go.Figure()
        fig.add_trace(go.Scatter(y=df["packet_count"], mode="lines+markers",
                                 name="Packets", line=dict(color="royalblue", width=2)))
        fig.add_trace(go.Scatter(y=df["byte_count"], mode="lines+markers",
                                 name="Bytes", line=dict(color="orange", width=2, dash="dash")))

        # 2️⃣ Pie chart for DDoS vs Normal
        ddos_count = df[df["prediction"] == 1].shape[0]
        normal_count = df[df["prediction"] == 0].shape[0]

        fig.add_trace(go.Pie(
            labels=["🚨 DDoS", "✅ Normal"],
            values=[ddos_count, normal_count],
            hole=0.4,
            textinfo="label+percent",
            domain=dict(x=[0.75, 1.0], y=[0.5, 1.0])
        ))

        # Layout
        fig.update_layout(
            title="📊 Real-Time IPv6 Traffic Monitoring",
            xaxis_title="Flow Index",
            yaxis_title="Count",
            template="plotly_dark",
            showlegend=True,
            autosize=True,
        )

        fig.show()

        time.sleep(5)  # refresh every 5 sec

    except KeyboardInterrupt:
        print("🛑 Stopped by user.")
        break
    except Exception as e:
        print("Error:", e)
        time.sleep(5)

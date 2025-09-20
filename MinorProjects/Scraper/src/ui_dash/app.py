import requests, pandas as pd
from dash import Dash, dcc, html
import plotly.express as px
## Initialize Dash app
app = Dash(__name__)
## Layout with interval for updates
app.layout = html.Div([
    html.H2("Wi-Fi Monitor"),
    dcc.Interval(id="interval", interval=5000, n_intervals=0),
    dcc.Graph(id="graph")
])
## callback to update graph
@app.callback(
    dcc.Output("graph", "figure"),
    dcc.Input("interval", "n_intervals")
)

## function to fetch data and update graph every interval 
def update_graph(n):
    try:
        data = requests.get("http://127.0.0.1:8000/api/latest?limit=50").json()
        df = pd.DataFrame(data, columns=["id","timestamp","ssid","bssid","signal","source"])
    except Exception:
        df = pd.DataFrame(columns=["timestamp","ssid","signal"])
    if df.empty:
        return px.bar(title="No data yet")
    fig = px.bar(df.groupby("ssid")["signal"].mean().reset_index(),
                 x="ssid", y="signal", title="Avg Signal per SSID")
    return fig
## Server port declaration!!
if __name__ == "__main__":
    app.run_server(port=8050)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server_monitor import get_server_metrics

app = FastAPI()

# CORS config so frontend can access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define servers to monitor
SERVERS = [
    {"name": "Server-01", "host": "192.168.1.10", "user": "ubuntu", "pass": "password123"},
    {"name": "Server-02", "host": "192.168.1.20", "user": "admin", "pass": "adminpass"},
]

@app.get("/api/servers")
def get_all_servers():
    result = []
    for srv in SERVERS:
        metrics = get_server_metrics(srv["host"], srv["user"], srv["pass"])
        result.append({
            "name": srv["name"],
            "status": metrics["status"],
            "cpu": metrics["cpu"],
            "memory": metrics["memory"],
            "uptime": metrics["uptime"]
        })
    return result

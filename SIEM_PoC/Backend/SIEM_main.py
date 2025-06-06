from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from server_monitor import get_server_metrics
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import os

app = FastAPI()

# CORS config so frontend can access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production to trusted domains
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define servers to monitor
SERVERS = [
    {"name": "Linux", "host": "192.168.1.10", "user": "ubuntu", "pass": "password123"},
    {"name": "Windows", "host": "192.168.1.20", "user": "admin", "pass": "adminpass"},
]

# Serve the static frontend folder at /static
app.mount("/static", StaticFiles(directory="static"), name="static")

# Root route: serve frontend index.html
@app.get("/")
def get_index():
    return FileResponse(os.path.join("static", "index.html"))

# API health check (optional at /api/health)
@app.get("/api/health")
def health_check():
    return {"message": "SIEM Backend API is running."}

# Get all servers and their metrics
@app.get("/api/servers")
def get_all_servers():
    result = []
    for srv in SERVERS:
        metrics = get_server_metrics(srv["host"], srv["user"], srv["pass"])
        result.append({
            "name": srv["name"],
            "status": metrics.get("status", "unknown"),
            "cpu": metrics.get("cpu", 0),
            "memory": metrics.get("memory", 0),
            "uptime": metrics.get("uptime", "Unavailable"),
            "error": metrics.get("error")
        })
    return {"servers": result}

# Get single server by name
@app.get("/api/servers/{server_name}")
def get_server(server_name: str):
    print(f"User requested server: {server_name}")
    for srv in SERVERS:
        print(f"Comparing to: {srv['name']}")
        if srv["name"].lower() == server_name.lower():
            metrics = get_server_metrics(srv["host"], srv["user"], srv["pass"])
            return {
                "name": srv["name"],
                "status": metrics.get("status", "unknown"),
                "cpu": metrics.get("cpu", 0),
                "memory": metrics.get("memory", 0),
                "uptime": metrics.get("uptime", "Unavailable"),
                "error": metrics.get("error")
            }
    raise HTTPException(status_code=404, detail="Server not found")

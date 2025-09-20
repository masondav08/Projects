from fastapi import FastAPI
from fastapi.responses import JSONResponse
import sqlite3
import uvicorn

app = FastAPI()

@app.get("/api/latest")
def get_latest(limit: int = 20):
    conn = sqlite3.connect("wifi_obs.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM wifi_obs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return JSONResponse(rows)

if __name__ == "__main__":
    
    uvicorn.run(app, host="127.0.0.1", port=8000)

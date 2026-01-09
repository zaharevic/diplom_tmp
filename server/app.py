from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import os
import json
from datetime import datetime, timezone

app = FastAPI()

DATA_DIR = os.environ.get("DATA_DIR", "/data/reports")
os.makedirs(DATA_DIR, exist_ok=True)


@app.post("/api/collect")
async def collect(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = payload.get("hostname", "unknown")
    safe_host = ''.join(c for c in host if c.isalnum() or c in ('-', '_')).rstrip()
    filename = f"report_{safe_host}_{ts}.json"
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    print(f"[+] Received report from {host}: saved to {path}")
    return JSONResponse({"status": "ok", "saved_to": path})


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)

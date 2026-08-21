from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from Scanner.tasks import scan_task


app = FastAPI(
    title="VulnScan Lite API",
    version="1.0.0"
)


# -----------------------------
# CORS
# -----------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Request Model
# -----------------------------

class ScanRequest(BaseModel):
    url: HttpUrl


# -----------------------------
# Health Check
# -----------------------------

@app.get("/")
def home():
    return {
        "message": "VulnScan Lite API is running"
    }


# -----------------------------
# Start Scan
# -----------------------------

@app.post("/scan")
def start_scan(request: ScanRequest):

    try:

        url = str(request.url)

        task = scan_task.delay(url)

        return {
            "task_id": task.id,
            "status": "started",
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# -----------------------------
# Check Scan Status
# -----------------------------

@app.get("/status/{task_id}")
def get_scan_status(task_id: str):

    task = scan_task.AsyncResult(task_id)

    if task.state == "PENDING":

        return {
            "task_id": task_id,
            "status": "pending"
        }

    if task.state == "STARTED":

        return {
            "task_id": task_id,
            "status": "running"
        }

    if task.state == "SUCCESS":

        return {
            "task_id": task_id,
            "status": "completed",
            "result": task.result
        }

    if task.state == "FAILURE":

        return {
            "task_id": task_id,
            "status": "failed",
            "error": str(task.result)
        }

    return {
        "task_id": task_id,
        "status": task.state.lower()
    }
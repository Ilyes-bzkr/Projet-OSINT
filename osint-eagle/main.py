"""
OSINT Eagle — Point d'entrée principal
Démarre le serveur FastAPI avec Uvicorn.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

app = FastAPI(
    title="OSINT Eagle",
    description="Personal OSINT & Data Intelligence Tool",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
static_path = Path(__file__).parent / "app" / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse(str(static_path / "index.html"))

@app.get("/health")
async def health_check():
    return {"status": "ok", "app": "OSINT Eagle", "version": "0.1.0"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )

"""
OSINT Eagle — Point d'entrée principal.
"""

import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from app.core.database import init_db
from app.core.logger import logger
from app.api.routes import router
from app.api.websocket import handle_search_websocket


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("OSINT Eagle démarré ✓")
    yield


app = FastAPI(
    title="OSINT Eagle",
    description="Personal OSINT & Data Intelligence Tool",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes HTTP
app.include_router(router)

# WebSocket
@app.websocket("/ws/search")
async def search_websocket(websocket: WebSocket):
    await handle_search_websocket(websocket)

# Static files
static_path = Path(__file__).parent / "app" / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse(str(static_path / "index.html"))

if __name__ == "__main__":
    # ws_ping_interval / ws_ping_timeout : ping WebSocket au niveau protocole
    # (renforce le heartbeat applicatif). Supportés par uvicorn >= 0.49 + le
    # backend "websockets" installé. Si une version d'uvicorn plus ancienne ne
    # les acceptait pas, uvicorn.run lèverait un TypeError explicite au démarrage.
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
        ws_ping_interval=20,
        ws_ping_timeout=60,
    )

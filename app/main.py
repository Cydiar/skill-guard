"""SkillGuard FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR
from app.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Ensure data directory exists
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)
    # Initialize database tables
    init_db()
    yield


app = FastAPI(
    title="SkillGuard",
    description="AI Agent Skill Security Audit Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
app.state.templates = templates

# Static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Register routers
from app.routers import scan, report, pages, deep_scan, rules  # noqa: E402

app.include_router(scan.router)
app.include_router(report.router)
app.include_router(deep_scan.router)
app.include_router(rules.router)
app.include_router(pages.router)

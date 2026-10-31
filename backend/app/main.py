import logging
import hmac
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.analyses import router as analyses_router
from app.api.baselines import router as baselines_router
from app.api.captures import router as captures_router
from app.api.live import get_live_manager, router as live_router
from app.api.processes import router as processes_router
from app.api.reports import router as reports_router
from app.api.settings import router as settings_router
from app.api.system import router as system_router
from app.config import settings
from app.database import engine, init_db
from app.logging_config import configure_logging, reconfigure_logging

logger = logging.getLogger(__name__)
_QUIET_PATHS = {"/api/health", "/api/live/status"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging(settings.log_level, settings.log_file)
    init_db()
    _apply_settings_at_startup()
    try:
        from app.services.capture_store import get_capture_store

        fixed = get_capture_store().fail_interrupted()
        if fixed:
            logger.warning("%d capture(s) from a previous run were left unfinished and were marked accordingly", fixed)
    except Exception:
        logger.exception("Could not reconcile the capture library at startup")
    logger.info("%s %s started on %s:%s", settings.app_name, settings.version, settings.host, settings.port)
    yield
    try:
        from app.services.app_settings import current_settings
        from app.services.storage import clear_temporary_uploads

        if current_settings().privacy.clear_temp_on_exit:
            clear_temporary_uploads()
    except Exception:
        logger.exception("Could not clear temporary capture data on exit")
    get_live_manager().shutdown()  # never leave a capture running after the backend exits
    from app.services.process_mapper import get_process_mapper

    get_process_mapper().shutdown()  # ... or a process watch


def _apply_settings_at_startup() -> None:
    """Make the saved Settings take effect: logging, retention, automatic cleanup; and follow later changes."""
    from app.services import database_admin, storage
    from app.services.app_settings import current_settings, get_settings_service
    from app.services.effective_config import log_level

    def apply_logging(*_args) -> None:
        s = current_settings()
        reconfigure_logging(log_level(s), settings.log_file, save_logs=s.diagnostics.save_logs, max_bytes=s.diagnostics.max_log_mb * 1024 * 1024,
                            rotation=s.diagnostics.rotation)

    def on_change(old, new) -> None:
        apply_logging()
        if old is None or old.ai != new.ai or old.ai_usage.cache_enabled != new.ai_usage.cache_enabled:
            from app.services.ai_usage import get_ai_usage

            get_ai_usage().clear_cache()

    try:
        apply_logging()
        get_settings_service().on_change(on_change)
        database_admin.prune_by_retention()
        storage.run_automatic_cleanup()
    except Exception:
        logger.exception("Could not apply the saved settings at startup")


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def require_token(request: Request, call_next):
        # Only active when the desktop shell started us with a per-launch token. Preflights and the readiness probe stay open
        # (the probe reveals nothing but the version); everything else needs the token.
        expected = settings.api_token.get_secret_value() if settings.api_token else ""
        path = request.url.path
        if expected and request.method != "OPTIONS" and path.startswith("/api") and path != "/api/health":
            given = request.headers.get("x-packetmind-token", "")
            if not hmac.compare_digest(given.encode(), expected.encode()):
                return JSONResponse(status_code=401, content={"detail": {
                    "code": "unauthorized", "message": "This request did not carry PacketMind's access token."}})
        return await call_next(request)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Log method and path only: never bodies, headers or query strings.
            logger.exception("Unhandled error: %s %s", request.method, request.url.path)
            return JSONResponse(status_code=500, content={"detail": {
                "code": "server_error", "message": "The backend hit an unexpected error. Details are in its log."}})
        if request.url.path not in _QUIET_PATHS:  # polled every few seconds by the UI
            logger.info("%s %s -> %s (%.0f ms)", request.method, request.url.path, response.status_code,
                        (time.perf_counter() - start) * 1000)
        return response

    @app.get("/api/health")
    def health() -> dict[str, str | int]:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "app": settings.app_name, "version": settings.version,
                "max_upload_bytes": settings.max_upload_bytes}

    app.include_router(analyses_router)
    app.include_router(baselines_router)
    app.include_router(captures_router)
    app.include_router(live_router)
    app.include_router(processes_router)
    app.include_router(reports_router)
    app.include_router(settings_router)
    app.include_router(system_router)

    return app


app = create_app()

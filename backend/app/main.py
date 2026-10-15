import asyncio
import contextlib
import logging
import re
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from .db import Session, engine
from .services import bootstrap, maintenance_once
from .api import router
from .reporting import router as reporting_router
from .enrollment import router as enrollment_router
from .runtime import router as runtime_router
from .monitoring import router as monitoring_router
from .insights import router as insights_router
from .sandbox_api import router as sandbox_router
from .localization import install_localization

log = logging.getLogger("honeyforge")


async def maintenance():
    while True:
        try:
            async with Session() as db:
                await maintenance_once(db)
        except Exception:
            log.error("Ошибка фонового обслуживания; попытка будет повторена", exc_info=False)
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app):
    async with Session() as db:
        await bootstrap(db)
    worker = asyncio.create_task(maintenance())
    yield
    worker.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await worker
    await engine.dispose()


app = FastAPI(title="HoneyForge", version="2.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.include_router(router)
app.include_router(reporting_router)
app.include_router(enrollment_router)
app.include_router(runtime_router)
app.include_router(monitoring_router)
app.include_router(insights_router)
app.include_router(sandbox_router)
install_localization(app)


@app.exception_handler(IntegrityError)
async def integrity_error(request, exception):
    return JSONResponse(status_code=409, content={"detail": "Конфликт: такое название, порт или связанный ресурс уже используются"})


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exception):
    log.error("Ошибка операции с базой данных", exc_info=False)
    return JSONResponse(status_code=503, content={"detail": "База данных недоступна. Повторите попытку позже"})


@app.middleware("http")
async def headers(request, call_next):
    length = request.headers.get("content-length", "0")
    if not length.isdigit() or int(length) > 1048576:
        return JSONResponse(status_code=413, content={"detail": "Превышен допустимый размер запроса"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
    return response


@app.get("/api/v1/health", summary="Проверка работы API")
async def health():
    return {"api": "ok"}


@app.get("/api/v1/ready", summary="Проверка готовности API и базы данных")
async def ready():
    async with Session() as db:
        await db.execute(text("SELECT 1"))
    return {"api": "ok", "database": "ok"}


frontend = Path(__file__).resolve().parents[2] / "frontend"


FONT_FILE = re.compile(r"^(Onest|Xolonium|Montserrat)-(Variable|Thin|ExtraLight|Light|Regular|Medium|SemiBold|Bold|ExtraBold|Black)\.(woff2|woff|ttf|otf)$")
FONT_WEIGHTS = {"Thin": 100, "ExtraLight": 200, "Light": 300, "Regular": 400, "Medium": 500, "SemiBold": 600,
                "Bold": 700, "ExtraBold": 800, "Black": 900}
FONT_FORMATS = {"woff2": "woff2", "woff": "woff", "ttf": "truetype", "otf": "opentype"}


@app.get("/fonts.css", include_in_schema=False)
async def font_faces():
    """Declare the licensed font files the operator placed in frontend/fonts; without them system fonts are used."""
    rules = []
    folder = frontend / "fonts"
    for path in sorted(folder.iterdir()) if folder.is_dir() else []:
        match = FONT_FILE.match(path.name)
        if not match:
            continue
        family, style, extension = match.groups()
        weight = "100 900" if style == "Variable" else FONT_WEIGHTS[style]
        rules.append('@font-face{font-family:"' + family + '";src:url("/fonts/' + path.name + '") format("' + FONT_FORMATS[extension]
                     + '");font-weight:' + str(weight) + ';font-style:normal;font-display:swap}')
    return Response("\n".join(rules) + "\n", media_type="text/css")


@app.get("/docs", include_in_schema=False)
async def api_documentation():
    return FileResponse(frontend / "api-docs.html")


if frontend.is_dir():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")

import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    WebSocket,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware

import uvicorn
import httpx
import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("X4G")

IRAN_TZ = ZoneInfo("Asia/Tehran")


app = FastAPI(
    title="X4G",
    docs_url=None,
    redoc_url=None,
)


DATA_DIR = Path(
    os.environ.get(
        "DATA_DIR",
        "/data"
    )
)

DATA_FILE = DATA_DIR / "x4g_state.json"
SECRET_FILE = DATA_DIR / "x4g_secret.key"

SAVE_LOCK = asyncio.Lock()


def _load_or_create_secret():

    env_secret = os.environ.get(
        "SECRET_KEY"
    )

    if env_secret:
        return env_secret

    try:
        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        if SECRET_FILE.exists():

            old = SECRET_FILE.read_text(
                encoding="utf-8"
            ).strip()

            if old:
                return old


        new_secret = secrets.token_urlsafe(
            32
        )

        SECRET_FILE.write_text(
            new_secret,
            encoding="utf-8"
        )

        return new_secret


    except Exception as e:

        logger.warning(
            f"secret persistence failed: {e}"
        )

        return secrets.token_urlsafe(
            32
        )


CONFIG = {

    "port":
        int(
            os.environ.get(
                "PORT",
                8000
            )
        ),

    "secret":
        _load_or_create_secret(),

    "host":
        os.environ.get(
            "RAILWAY_PUBLIC_DOMAIN",
            "localhost"
        ),
}


app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)



connections = {}

stats = {

    "total_bytes": 0,

    "total_requests": 0,

    "total_errors": 0,

    "start_time": time.time(),
}


error_logs = deque(
    maxlen=50
)

activity_logs = deque(
    maxlen=200
)

hourly_traffic = defaultdict(
    int
)


http_client = None


LINKS = {}
SUBS = {}

LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()


async def load_state():

    global LINKS, SUBS, AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        if not DATA_FILE.exists():

            return


        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            raw = await f.read()


        data = json.loads(
            raw
        )


        LINKS.update(
            data.get(
                "links",
                {}
            )
        )


        SUBS.update(
            data.get(
                "subs",
                {}
            )
        )


        if data.get(
            "password_hash"
        ):

            AUTH["password_hash"] = data[
                "password_hash"
            ]


        logger.info(
            "state loaded"
        )


    except Exception as e:

        logger.warning(
            f"load state failed: {e}"
        )



async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True
            )


            data = {

                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "password_hash":
                    AUTH["password_hash"],

                "saved_at":
                    datetime.now().isoformat(),
            }


            tmp = DATA_FILE.with_suffix(
                ".tmp"
            )


            async with aiofiles.open(
                tmp,
                "w",
                encoding="utf-8"
            ) as f:

                await f.write(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                        indent=2
                    )
                )


            tmp.replace(
                DATA_FILE
            )


        except Exception as e:

            logger.warning(
                f"save state failed: {e}"
            )



SESSION_COOKIE = "x4g_session"

SESSION_TTL = 60 * 60 * 24 * 365



def hash_password(
    pw: str
):

    return hashlib.sha256(
        f"{pw}{CONFIG['secret']}".encode()
    ).hexdigest()



AUTH = {

    "password_hash":
        hash_password(
            os.environ.get(
                "ADMIN_PASSWORD",
                "X4GKING"
            )
        )
}


SESSIONS = {}

SESSIONS_LOCK = asyncio.Lock()



async def create_session():

    token = secrets.token_urlsafe(
        32
    )

    async with SESSIONS_LOCK:

        SESSIONS[token] = (
            time.time()
            +
            SESSION_TTL
        )

    return token



async def is_valid_session(
    token
):

    if not token:

        return False


    async with SESSIONS_LOCK:

        exp = SESSIONS.get(
            token
        )

        if not exp:

            return False


        if exp < time.time():

            SESSIONS.pop(
                token,
                None
            )

            return False


        return True



async def require_auth(
    request: Request
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):

        raise HTTPException(
            401,
            "unauthorized"
        )

    return True



@asynccontextmanager
async def lifespan(
    app
):

    global http_client


    try:

        http_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=100
            ),

            timeout=httpx.Timeout(
                30,
                connect=10
            ),

            follow_redirects=True
        )


        await load_state()


        try:

            from telegram_bot import start_bot

            await start_bot()


        except Exception as e:

            logger.warning(
                f"telegram disabled: {e}"
            )


        logger.info(
            "X4G started"
        )


    except Exception as e:

        logger.exception(
            f"startup error: {e}"
        )


    yield



    try:

        await save_state()


    except Exception:

        pass



    try:

        from telegram_bot import stop_bot

        await stop_bot()


    except Exception:

        pass



    if http_client:

        await http_client.aclose()



app.router.lifespan_context = lifespan
def log_activity(
    kind: str,
    message: str,
    level: str = "info"
):

    activity_logs.append(
        {
            "kind": kind,
            "message": message,
            "level": level,
            "time": datetime.now().isoformat()
        }
    )



def get_host(
    request: Request | None = None
):

    if request:

        h = (
            request.headers.get(
                "x-forwarded-host"
            )
            or
            request.headers.get(
                "host"
            )
        )

        if h:

            CONFIG["host"] = h.split(":")[0]

            return CONFIG["host"]


    return CONFIG["host"]



def generate_uuid():

    h = secrets.token_hex(
        16
    )

    return (
        f"{h[:8]}-"
        f"{h[8:12]}-"
        f"{h[12:16]}-"
        f"{h[16:20]}-"
        f"{h[20:32]}"
    )



def now_ir():

    return datetime.now(
        IRAN_TZ
    )



def fmt_bytes(
    b
):

    if b < 1024:

        return f"{b} B"

    if b < 1024**2:

        return f"{b/1024:.1f} KB"

    if b < 1024**3:

        return f"{b/1024**2:.2f} MB"

    return f"{b/1024**3:.2f} GB"



def is_link_expired(
    link
):

    exp = link.get(
        "expires_at"
    )

    if not exp:

        return False

    try:

        return (
            datetime.now()
            >
            datetime.fromisoformat(
                exp
            )
        )

    except:

        return False



def is_link_allowed(
    link
):

    if not link:

        return False


    if not link.get(
        "active",
        True
    ):

        return False


    if is_link_expired(
        link
    ):

        return False


    limit = link.get(
        "limit_bytes",
        0
    )

    used = link.get(
        "used_bytes",
        0
    )


    if limit and used >= limit:

        return False


    return True



PROTOCOLS = (

    "vless-ws",

    "xhttp-packet-up",

    "xhttp-stream-up",

    "xhttp-stream-one",
)


DEFAULT_PROTOCOL = "vless-ws"


FINGERPRINTS = (

    "chrome",

    "firefox",

    "safari",

    "ios",

    "android",

    "edge",

    "random"
)


DEFAULT_FINGERPRINT = "chrome"



def generate_vless_link(
    uuid,
    host,
    remark="X4G",
    protocol=DEFAULT_PROTOCOL,
    fingerprint=DEFAULT_FINGERPRINT,
    alpn="",
    port=443
):

    fp = fingerprint

    if fp not in FINGERPRINTS:

        fp = DEFAULT_FINGERPRINT


    if protocol == "vless-ws":

        path = f"/ws/{uuid}"

        params = {

            "encryption":
                "none",

            "security":
                "tls",

            "type":
                "ws",

            "host":
                host,

            "path":
                path,

            "sni":
                host,

            "fp":
                fp
        }


    else:

        mode = protocol.replace(
            "xhttp-",
            ""
        )

        path = (
            f"/xhttp-siz10/"
            f"{mode}/"
            f"{uuid}"
        )


        params = {

            "encryption":
                "none",

            "security":
                "tls",

            "type":
                "xhttp",

            "mode":
                mode,

            "host":
                host,

            "path":
                path,

            "sni":
                host,

            "fp":
                fp
        }



    if alpn:

        params["alpn"] = alpn



    query = "&".join(

        f"{k}={quote(str(v))}"

        for k,v in params.items()

    )


    return (
        f"vless://{uuid}"
        f"@{host}:{port}"
        f"?{query}"
        f"#{quote(remark)}"
    )



@app.get("/")
async def root():

    return {

        "service":
            "X4G",

        "status":
            "active",

        "version":
            "10.0"
    }



@app.get("/health")
async def health():

    return {

        "status":
            "ok",

        "connections":
            len(connections)

    }



@app.post("/api/login")
async def login(
    request: Request
):

    body = await request.json()


    if hash_password(
        str(
            body.get(
                "password",
                ""
            )
        )
    ) != AUTH["password_hash"]:

        raise HTTPException(
            401,
            "wrong password"
        )


    token = await create_session()


    resp = JSONResponse(
        {
            "ok":
                True
        }
    )


    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        max_age=SESSION_TTL,
        samesite="lax"
    )


    return resp



@app.post("/api/logout")
async def logout(
    request: Request
):

    token = request.cookies.get(
        SESSION_COOKIE
    )


    if token:

        async with SESSIONS_LOCK:

            SESSIONS.pop(
                token,
                None
            )


    resp = JSONResponse(
        {
            "ok":
                True
        }
    )


    resp.delete_cookie(
        SESSION_COOKIE
    )


    return resp



@app.get("/api/me")
async def me(
    request: Request
):

    return {

        "authenticated":
            await is_valid_session(
                request.cookies.get(
                    SESSION_COOKIE
                )
            )

    }



@app.get("/stats")
async def stats_api(
    _=Depends(require_auth)
):
    return {
        "connections": len(connections),
        "traffic": fmt_bytes(stats["total_bytes"]),
        "requests": stats["total_requests"],
        "errors": stats["total_errors"]
    }


@app.get("/api/activity")
async def activity(
    _=Depends(require_auth)
):

    return {
        "logs":
            list(activity_logs)
    }



@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth)
):

    host = get_host(
        request
    )

    async with LINKS_LOCK:

        data = []

        for uid, link in LINKS.items():

            data.append(
                {
                    "uuid":
                        uid,

                    **link,

                    "vless_link":
                        generate_vless_link(
                            uid,
                            host,
                            link.get(
                                "label",
                                "X4G"
                            ),

                            link.get(
                                "protocol",
                                DEFAULT_PROTOCOL
                            ),

                            link.get(
                                "fingerprint",
                                DEFAULT_FINGERPRINT
                            ),

                            link.get(
                                "alpn",
                                ""
                            ),

                            link.get(
                                "port",
                                443
                            )
                        )
                }
            )


    return {
        "links":
            data
    }



@app.post("/api/links")
async def create_link(
    request: Request,
    _=Depends(require_auth)
):

    body = await request.json()


    uid = generate_uuid()


    link = {

        "label":
            str(
                body.get(
                    "label",
                    "لینک جدید"
                )
            )[:60],

        "limit_bytes":
            0,

        "used_bytes":
            0,

        "active":
            True,

        "created_at":
            datetime.now().isoformat(),

        "expires_at":
            None,

        "protocol":
            body.get(
                "protocol",
                DEFAULT_PROTOCOL
            ),

        "fingerprint":
            body.get(
                "fingerprint",
                DEFAULT_FINGERPRINT
            ),

        "alpn":
            body.get(
                "alpn",
                ""
            ),

        "port":
            int(
                body.get(
                    "port",
                    443
                )
            ),

        "note":
            body.get(
                "note",
                ""
            )

    }


    async with LINKS_LOCK:

        LINKS[uid] = link


    await save_state()


    log_activity(
        "link",
        f"کانفیگ {uid} ساخته شد",
        "ok"
    )


    return {

        "uuid":
            uid,

        **link

    }



@app.patch("/api/links/{uid}")
async def edit_link(
    uid: str,
    request: Request,
    _=Depends(require_auth)
):

    body = await request.json()


    async with LINKS_LOCK:

        if uid not in LINKS:

            raise HTTPException(
                404,
                "not found"
            )


        for key in (

            "label",

            "active",

            "note",

            "protocol",

            "fingerprint",

            "alpn"

        ):

            if key in body:

                LINKS[uid][key] = body[key]



    await save_state()


    return {
        "ok":
            True
    }



@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth)
):

    async with LINKS_LOCK:

        if uid in LINKS:

            del LINKS[uid]

        else:

            raise HTTPException(
                404,
                "not found"
            )


    await save_state()


    return {

        "ok":
            True

    }



@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard(
    request: Request
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):

        return RedirectResponse(
            "/login"
        )


    try:

        from pages import DASHBOARD_HTML

        return HTMLResponse(
            DASHBOARD_HTML
        )


    except Exception as e:

        return HTMLResponse(
            f"""
            <h2>
            Dashboard unavailable
            </h2>
            <pre>{e}</pre>
            """
        )



@app.get(
    "/login",
    response_class=HTMLResponse
)
async def login_page():

    try:

        from pages import LOGIN_HTML

        return HTMLResponse(
            LOGIN_HTML
        )


    except:

        return HTMLResponse(
            "<h2>Login</h2>"
        )



# فایل‌های جانبی اختیاری

try:

    from relay_vless import websocket_tunnel

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel
    )

except Exception as e:

    logger.warning(
        f"relay disabled: {e}"
    )

    app.include_router(
        xhttp_router
    )


except Exception as e:

    logger.warning(
        f"xhttp disabled: {e}"
    )



@app.get("/test-ws")
async def test_ws():

    return {
        "status":
            "ready"
    }



if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                8000
            )
        ),

        workers=1
    )

import asyncio
import base64
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


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط­ط§ظ„طھ ط¯ط±ظˆظ†â€Œط­ط§ظپط¸ظ‡â€Œط§غŒ
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

connections = {}   # conn_id -> {uuid, ip, transport, bytes, connected_at}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=50)
activity_logs = deque(maxlen=200)
hourly_traffic = defaultdict(int)

http_client = None

LINKS = {}
SUBS = {}

LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()


SESSION_COOKIE = "x4g_session"
SESSION_TTL = 60 * 60 * 24 * 365


def hash_password(pw: str):
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


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط°ط®غŒط±ظ‡/ط¨ط§ط±ع¯ط°ط§ط±غŒ ط­ط§ظ„طھ ط±ظˆغŒ ط¯غŒط³ع©
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

async def load_state():

    global LINKS, SUBS, AUTH

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
            raw = await f.read()

        data = json.loads(raw)

        LINKS.update(data.get("links", {}))
        SUBS.update(data.get("subs", {}))

        if data.get("password_hash"):
            AUTH["password_hash"] = data["password_hash"]

        logger.info("state loaded")

    except Exception as e:
        logger.warning(f"load state failed: {e}")


async def save_state():

    async with SAVE_LOCK:

        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)

            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }

            tmp = DATA_FILE.with_suffix(".tmp")

            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(
                    json.dumps(data, ensure_ascii=False, indent=2)
                )

            tmp.replace(DATA_FILE)

        except Exception as e:
            logger.warning(f"save state failed: {e}")


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط³ط´ظ† / ط§ط­ط±ط§ط² ظ‡ظˆغŒطھ
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

async def create_session():
    token = secrets.token_urlsafe(32)

    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL

    return token


async def is_valid_session(token):
    if not token:
        return False

    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)

        if not exp:
            return False

        if exp < time.time():
            SESSIONS.pop(token, None)
            return False

        return True


async def require_auth(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(401, "unauthorized")
    return True


@asynccontextmanager
async def lifespan(app):

    global http_client

    try:
        http_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=500,
                max_keepalive_connections=100
            ),
            timeout=httpx.Timeout(30, connect=10),
            follow_redirects=True
        )

        await load_state()

        try:
            from telegram_bot import start_bot
            await start_bot()
        except Exception as e:
            logger.warning(f"telegram disabled: {e}")

        logger.info("X4G started")

    except Exception as e:
        logger.exception(f"startup error: {e}")

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


@app.middleware("http")
async def count_requests(request: Request, call_next):
    stats["total_requests"] += 1
    response = await call_next(request)
    return response


def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "message": message,
        "level": level,
        "time": datetime.now().isoformat()
    })


def log_error(error: str, url: str = ""):
    stats["total_errors"] += 1
    error_logs.append({
        "time": datetime.now().isoformat(),
        "error": error,
        "url": url,
    })


def get_host(request: Request | None = None):
    if request:
        h = (
            request.headers.get("x-forwarded-host")
            or request.headers.get("host")
        )
        if h:
            CONFIG["host"] = h.split(":")[0]
            return CONFIG["host"]

    return CONFIG["host"]


def get_base_url(request: Request) -> str:
    host = get_host(request)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{proto}://{host}"


def generate_uuid():
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def now_ir():
    return datetime.now(IRAN_TZ)


def fmt_bytes(b):
    b = b or 0
    if b < 1024:
        return f"{b} B"
    if b < 1024**2:
        return f"{b/1024:.1f} KB"
    if b < 1024**3:
        return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


def format_uptime():
    secs = int(time.time() - stats["start_time"])
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m, _ = divmod(secs, 60)
    parts = []
    if d:
        parts.append(f"{d} ط±ظˆط²")
    if h:
        parts.append(f"{h} ط³ط§ط¹طھ")
    if not d:
        parts.append(f"{m} ط¯ظ‚غŒظ‚ظ‡")
    return " ".join(parts) if parts else "ع©ظ…طھط± ط§ط² غŒع© ط¯ظ‚غŒظ‚ظ‡"


def hour_key(dt=None):
    # ظ‡ظ…â€Œظپط±ظ…طھ ط¨ط§ relay_vless.py ع©ظ‡ ظ…ط³طھظ‚غŒظ…ط§ظ‹ main.hourly_traffic ط±ط§ ط¨ط§
    # ع©ظ„غŒط¯ "HH:00" (ط¨ط¯ظˆظ† طھط§ط±غŒط®) ظ¾ط± ظ…غŒâ€Œع©ظ†ط¯ â€” ط¨ط§غŒط¯ غŒع©ط³ط§ظ† ط¨ظ…ط§ظ†ظ†ط¯.
    dt = dt or now_ir()
    return dt.strftime("%H:00")


def is_link_expired(link):
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False


def is_link_allowed(link):
    if not link:
        return False

    if not link.get("active", True):
        return False

    if is_link_expired(link):
        return False

    limit = link.get("limit_bytes", 0)
    used = link.get("used_bytes", 0)

    if limit and used >= limit:
        return False

    return True


def count_connected_ips(uuid: str) -> int:
    return len({c["ip"] for c in connections.values() if c.get("uuid") == uuid})


def is_ip_allowed(link, uuid: str, ip: str) -> bool:
    """طھظˆط³ط· relay_vless.py طµط¯ط§ ط²ط¯ظ‡ ظ…غŒâ€Œط´ظˆط¯: ط¨ط±ط±ط³غŒ ظ…ط­ط¯ظˆط¯غŒطھ ط¢غŒâ€Œظ¾غŒ ظ‡ظ…â€Œط²ظ…ط§ظ† ظ‡ط± ع©ط§ظ†ظپغŒع¯."""
    if not link:
        return False

    ip_limit = link.get("ip_limit", 0)
    if not ip_limit:
        return True

    current_ips = {c["ip"] for c in connections.values() if c.get("uuid") == uuid}

    if ip in current_ips:
        return True

    return len(current_ips) < ip_limit


def quota_to_bytes(value, unit):
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0
    if v <= 0:
        return 0
    unit = str(unit or "GB").upper()
    mult = {"MB": 1024**2, "GB": 1024**3}.get(unit, 1024**3)
    return int(v * mult)


def speed_to_bytes_per_sec(value, unit):
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0
    if v <= 0:
        return 0
    unit = str(unit or "MBIT").upper()
    if unit == "MBIT":
        return int(v * 1024 * 1024 / 8)
    if unit == "KB":
        return int(v * 1024)
    if unit == "MB":
        return int(v * 1024 * 1024)
    return int(v * 1024 * 1024 / 8)


PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    # طھظˆط¬ظ‡: "xhttp-stream-one" ط¯ط± xhttp_siz10.py ط­ط°ظپ ط´ط¯ظ‡ ظˆ ط¯غŒع¯ط±
    # ط±ظˆطھ ظ†ظ…غŒâ€Œط´ظˆط¯ (ظپظ‚ط· packet-up ظˆ stream-up ظ¾ط´طھغŒط¨ط§ظ†غŒ ظ…غŒâ€Œط´ظˆظ†ط¯).
)

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
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
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp
        }

    else:
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp
        }

    if alpn:
        params["alpn"] = alpn

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())

    return f"vless://{uuid}@{host}:{port}?{query}#{quote(remark)}"


def build_subscription(link_lines: list) -> Response:
    raw = "\n".join(link_lines)
    encoded = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    return Response(content=encoded, media_type="text/plain; charset=utf-8")


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط±ط¯غŒط§ط¨غŒ ط§طھطµط§ظ„ط§طھ ط²ظ†ط¯ظ‡ (ع©ظ…ع©غŒ/ط§ط®طھغŒط§ط±غŒ)
#  طھظˆط¬ظ‡: relay_vless.py ط®ظˆط¯ط´ ظ…ط³طھظ‚غŒظ…ط§ظ‹ main.connections/main.LINKS/
#  main.stats ط±ط§ ظ…ط¯غŒط±غŒطھ ظ…غŒâ€Œع©ظ†ط¯ ظˆ ط§ط² طھظˆط§ط¨ط¹ ط²غŒط± ط§ط³طھظپط§ط¯ظ‡ ظ†ظ…غŒâ€Œع©ظ†ط¯.
#  ط§غŒظ† طھظˆط§ط¨ط¹ ظپظ‚ط· ط¨ط±ط§غŒ غŒع© ظ…ط§عکظˆظ„ XHTTP ط§ط­طھظ…ط§ظ„غŒ ط¯ط± ط¢غŒظ†ط¯ظ‡ ظ†ع¯ظ‡ ط¯ط§ط´طھظ‡
#  ط´ط¯ظ‡â€Œط§ظ†ط¯ طھط§ ط¯ط± طµظˆط±طھ ظ†غŒط§ط² ظ‡ظ…ط§ظ† ط§ظ„ع¯ظˆ ط±ط§ ط¨ط¯ظˆظ† طھع©ط±ط§ط± ع©ط¯ ظ¾غŒط§ط¯ظ‡ ع©ظ†ط¯.
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

async def try_register_connection(uid: str, ip: str, transport: str = "vless-ws"):
    """ظ‚ط¨ظ„ ط§ط² ظ¾ط°غŒط±ط´ ط§طھطµط§ظ„ ط¨ط§غŒط¯ طµط¯ط§ ط²ط¯ظ‡ ط´ظˆط¯.
    ط¯ط± طµظˆط±طھ ظ…ط¬ط§ط² ط¨ظˆط¯ظ† conn_id ط¨ط±ظ…غŒâ€Œع¯ط±ط¯ط§ظ†ط¯طŒ ط¯ط± ط؛غŒط± ط§غŒظ† طµظˆط±طھ None."""

    async with LINKS_LOCK:
        link = LINKS.get(uid)

        if not is_link_allowed(link):
            return None

        ip_limit = link.get("ip_limit", 0)
        if ip_limit:
            current_ips = {c["ip"] for c in connections.values() if c.get("uuid") == uid}
            if ip not in current_ips and len(current_ips) >= ip_limit:
                return None

    conn_id = secrets.token_hex(8)
    connections[conn_id] = {
        "uuid": uid,
        "ip": ip,
        "transport": transport,
        "bytes": 0,
        "connected_at": datetime.now().isoformat(),
    }
    log_activity("connection", f"ط§طھطµط§ظ„ ط¬ط¯غŒط¯: {ip} â†’ {uid[:8]}â€¦", "info")
    return conn_id


def unregister_connection(conn_id: str):
    connections.pop(conn_id, None)


async def add_traffic(conn_id: str, n: int):
    if not n or n <= 0:
        return

    conn = connections.get(conn_id)
    if not conn:
        return

    conn["bytes"] = conn.get("bytes", 0) + n
    stats["total_bytes"] += n
    hourly_traffic[hour_key()] += n

    async with LINKS_LOCK:
        link = LINKS.get(conn.get("uuid"))
        if link:
            link["used_bytes"] = link.get("used_bytes", 0) + n


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط±ظˆطھâ€Œظ‡ط§غŒ ط¹ظ…ظˆظ…غŒ / ط³ظ„ط§ظ…طھ
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/")
async def root():
    return {"service": "X4G", "status": "active", "version": "9.5"}


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections)}


@app.get("/test-ws")
async def test_ws():
    return {"status": "ready"}


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط§ط­ط±ط§ط² ظ‡ظˆغŒطھ
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.post("/api/login")
async def login(request: Request):
    body = await request.json()

    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(401, "wrong password")

    token = await create_session()

    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        max_age=SESSION_TTL,
        samesite="lax"
    )
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)

    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/me")
async def me(request: Request):
    return {
        "authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))
    }


@app.post("/api/change-password")
async def change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()

    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))

    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(400, "ط±ظ…ط² ظپط¹ظ„غŒ ط§ط´طھط¨ط§ظ‡ ط§ط³طھ")

    if len(new) < 4:
        raise HTTPException(400, "ط±ظ…ط² ط¬ط¯غŒط¯ ط¨ط§غŒط¯ ط­ط¯ط§ظ‚ظ„ غ´ ع©ط§ط±ط§ع©طھط± ط¨ط§ط´ط¯")

    AUTH["password_hash"] = hash_password(new)
    await save_state()
    log_activity("auth", "ط±ظ…ط² ط¹ط¨ظˆط± ظ¾ظ†ظ„ طھط؛غŒغŒط± ع©ط±ط¯", "warn")

    return {"ok": True}


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط¢ظ…ط§ط± / ظ„ط§ع¯â€Œظ‡ط§
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/stats")
async def stats_api(_=Depends(require_auth)):

    async with LINKS_LOCK:
        links_count = len(LINKS)
        active_links = sum(1 for l in LINKS.values() if is_link_allowed(l))

    async with SUBS_LOCK:
        subs_count = len(SUBS)

    return {
        "active_connections": len(connections),
        "total_traffic_mb": stats["total_bytes"] / 1024**2,
        "active_links": active_links,
        "links_count": links_count,
        "subs_count": subs_count,
        "total_errors": stats["total_errors"],
        "uptime": format_uptime(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs),
    }


@app.get("/api/activity")
async def activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)}


@app.get("/api/connections")
async def list_connections(_=Depends(require_auth)):
    data = []

    for conn_id, c in connections.items():
        link = LINKS.get(c.get("uuid"))
        data.append({
            "id": conn_id,
            "uuid": c.get("uuid"),
            "ip": c.get("ip", "-"),
            "label": (link.get("label") if link else c.get("uuid", "-")),
            "transport": c.get("transport", "vless-ws"),
            "bytes_fmt": fmt_bytes(c.get("bytes", 0)),
            "connected_at": c.get("connected_at"),
        })

    return {"count": len(data), "connections": data}


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ع©ط§ظ†ظپغŒع¯â€Œظ‡ط§ (ظ„غŒظ†ع©â€Œظ‡ط§)
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):

    host = get_host(request)
    base = get_base_url(request)

    async with LINKS_LOCK:
        data = []

        for uid, link in LINKS.items():
            data.append({
                "uuid": uid,
                **link,
                "expired": is_link_expired(link),
                "connected_ips": count_connected_ips(uid),
                "vless_link": generate_vless_link(
                    uid,
                    host,
                    link.get("label", "X4G"),
                    link.get("protocol", DEFAULT_PROTOCOL),
                    link.get("fingerprint", DEFAULT_FINGERPRINT),
                    link.get("alpn", ""),
                    link.get("port", 443)
                ),
                "sub_url": f"{base}/sub/{uid}",
            })

    return {"links": data}


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):

    body = await request.json()
    uid = generate_uuid()

    protocol = body.get("protocol", DEFAULT_PROTOCOL)
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = body.get("fingerprint", DEFAULT_FINGERPRINT)
    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    try:
        expires_days = int(body.get("expires_days", 0) or 0)
    except (TypeError, ValueError):
        expires_days = 0

    expires_at = None
    if expires_days > 0:
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()

    sub_id = body.get("sub_id") or None
    if sub_id:
        async with SUBS_LOCK:
            if sub_id not in SUBS:
                sub_id = None

    try:
        port = int(body.get("port", 443) or 443)
        port = max(1, min(65535, port))
    except (TypeError, ValueError):
        port = 443

    link = {
        "label": str(body.get("label", "ظ„غŒظ†ع© ط¬ط¯غŒط¯"))[:60] or "ظ„غŒظ†ع© ط¬ط¯غŒط¯",
        "limit_bytes": quota_to_bytes(body.get("limit_value", 0), body.get("limit_unit", "GB")),
        "used_bytes": 0,
        "active": True,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires_at,
        "protocol": protocol,
        "fingerprint": fingerprint,
        "alpn": str(body.get("alpn", "") or "")[:100],
        "port": port,
        "note": str(body.get("note", "") or "")[:200],
        "sub_id": sub_id,
        "ip_limit": max(0, int(body.get("ip_limit", 0) or 0)),
        "speed_limit_bytes": speed_to_bytes_per_sec(
            body.get("speed_limit_value", 0), body.get("speed_limit_unit", "MBIT")
        ),
    }

    async with LINKS_LOCK:
        LINKS[uid] = link

    await save_state()
    log_activity("link", f"ع©ط§ظ†ظپغŒع¯ آ«{link['label']}آ» ط³ط§ط®طھظ‡ ط´ط¯", "ok")

    return {"uuid": uid, **link}


@app.patch("/api/links/{uid}")
async def edit_link(uid: str, request: Request, _=Depends(require_auth)):

    body = await request.json()

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(404, "not found")

        link = LINKS[uid]

        if "label" in body and str(body["label"]).strip():
            link["label"] = str(body["label"])[:60]

        if "note" in body:
            link["note"] = str(body["note"] or "")[:200]

        if "active" in body:
            link["active"] = bool(body["active"])

        if "fingerprint" in body:
            fp = body["fingerprint"]
            if fp in FINGERPRINTS:
                link["fingerprint"] = fp

        if "alpn" in body:
            link["alpn"] = str(body["alpn"] or "")[:100]

        if "port" in body:
            try:
                link["port"] = max(1, min(65535, int(body["port"])))
            except (TypeError, ValueError):
                pass

        if "ip_limit" in body:
            try:
                link["ip_limit"] = max(0, int(body["ip_limit"]))
            except (TypeError, ValueError):
                pass

        if "limit_value" in body:
            link["limit_bytes"] = quota_to_bytes(
                body.get("limit_value", 0), body.get("limit_unit", "GB")
            )

        if "speed_limit_value" in body:
            link["speed_limit_bytes"] = speed_to_bytes_per_sec(
                body.get("speed_limit_value", 0), body.get("speed_limit_unit", "MBIT")
            )

        if body.get("expires_days"):
            try:
                days = int(body["expires_days"])
            except (TypeError, ValueError):
                days = 0
            if days > 0:
                link["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat()

        if body.get("reset_usage"):
            link["used_bytes"] = 0

        if "sub_id" in body:
            sid = body["sub_id"] or None
            if sid and sid not in SUBS:
                sid = None
            link["sub_id"] = sid

    await save_state()
    log_activity("link", f"ع©ط§ظ†ظپغŒع¯ {uid[:8]}â€¦ ظˆغŒط±ط§غŒط´ ط´ط¯", "info")

    return {"ok": True}


@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):

    async with LINKS_LOCK:
        if uid in LINKS:
            del LINKS[uid]
        else:
            raise HTTPException(404, "not found")

    reset_bucket(uid)

    await save_state()
    log_activity("link", f"ع©ط§ظ†ظپغŒع¯ {uid[:8]}â€¦ ط­ط°ظپ ط´ط¯", "warn")

    return {"ok": True}


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ع¯ط±ظˆظ‡â€Œظ‡ط§غŒ ط³ط§ط¨
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/api/subs")
async def list_subs(request: Request, _=Depends(require_auth)):

    base = get_base_url(request)

    async with LINKS_LOCK, SUBS_LOCK:
        data = []

        for sub_id, sub in SUBS.items():
            member_uids = [uid for uid, l in LINKS.items() if l.get("sub_id") == sub_id]
            member_links = [LINKS[u] for u in member_uids]
            active_count = sum(1 for l in member_links if is_link_allowed(l))
            total_used = sum(l.get("used_bytes", 0) for l in member_links)

            data.append({
                "sub_id": sub_id,
                "name": sub.get("name", ""),
                "desc": sub.get("desc", ""),
                "has_password": bool(sub.get("password_hash")),
                "links_count": len(member_links),
                "active_count": active_count,
                "total_used_fmt": fmt_bytes(total_used),
                "link_ids": member_uids,
                "sub_url": f"{base}/sub-group/{sub_id}",
                "public_url": f"{base}/pub/{sub_id}",
                "created_at": sub.get("created_at"),
            })

    return {"subs": data}


@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):

    body = await request.json()
    sub_id = secrets.token_hex(6)

    name = str(body.get("name", "ع¯ط±ظˆظ‡ ط¬ط¯غŒط¯"))[:60] or "ع¯ط±ظˆظ‡ ط¬ط¯غŒط¯"
    desc = str(body.get("desc", "") or "")[:200]
    pw = str(body.get("password", "") or "")

    sub = {
        "name": name,
        "desc": desc,
        "password_hash": hash_password(pw) if pw else None,
        "created_at": datetime.now().isoformat(),
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = sub

    await save_state()
    log_activity("sub", f"ع¯ط±ظˆظ‡ آ«{name}آ» ط³ط§ط®طھظ‡ ط´ط¯", "ok")

    return {"sub_id": sub_id, **sub}


@app.patch("/api/subs/{sub_id}")
async def edit_sub(sub_id: str, request: Request, _=Depends(require_auth)):

    body = await request.json()

    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(404, "not found")

        sub = SUBS[sub_id]

        if "name" in body and str(body["name"]).strip():
            sub["name"] = str(body["name"])[:60]

        if "desc" in body:
            sub["desc"] = str(body["desc"] or "")[:200]

        if "password" in body:
            pw = str(body["password"] or "")
            sub["password_hash"] = hash_password(pw) if pw else None

    if "link_ids" in body:
        wanted = set(body.get("link_ids") or [])

        async with LINKS_LOCK:
            for uid, link in LINKS.items():
                if uid in wanted:
                    link["sub_id"] = sub_id
                elif link.get("sub_id") == sub_id:
                    link["sub_id"] = None

    await save_state()
    log_activity("sub", f"ع¯ط±ظˆظ‡ {sub_id} ظˆغŒط±ط§غŒط´ ط´ط¯", "info")

    return {"ok": True}


@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):

    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(404, "not found")
        del SUBS[sub_id]

    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None

    await save_state()
    log_activity("sub", f"ع¯ط±ظˆظ‡ {sub_id} ط­ط°ظپ ط´ط¯", "warn")

    return {"ok": True}


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ط³ط§ط¨ط³ع©ط±غŒظ¾ط´ظ†â€Œظ‡ط§ (ظ¾ط§ط¨ظ„غŒع© / ط§ط¯ظ…غŒظ†)
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/sub/{uid}")
async def sub_single(uid: str, request: Request):

    host = get_host(request)

    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(404, "not found")

        vless = generate_vless_link(
            uid,
            host,
            link.get("label", "X4G"),
            link.get("protocol", DEFAULT_PROTOCOL),
            link.get("fingerprint", DEFAULT_FINGERPRINT),
            link.get("alpn", ""),
            link.get("port", 443),
        )

    return build_subscription([vless])


@app.get("/sub-group/{sub_id}")
async def sub_group(sub_id: str, request: Request, pw: str = ""):

    async with SUBS_LOCK:
        sub = SUBS.get(sub_id)
        if not sub:
            raise HTTPException(404, "not found")

        if sub.get("password_hash") and hash_password(pw) != sub["password_hash"]:
            raise HTTPException(403, "ط±ظ…ط² ظ†ط§ط¯ط±ط³طھ ط§ط³طھ")

    host = get_host(request)
    lines = []

    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            if link.get("sub_id") != sub_id:
                continue
            if not is_link_allowed(link):
                continue
            lines.append(generate_vless_link(
                uid,
                host,
                link.get("label", "X4G"),
                link.get("protocol", DEFAULT_PROTOCOL),
                link.get("fingerprint", DEFAULT_FINGERPRINT),
                link.get("alpn", ""),
                link.get("port", 443),
            ))

    return build_subscription(lines)


# ط³ط§ط²ع¯ط§ط±غŒ ط¨ط§ ظ†ط§ظ… ظ‚ط¯غŒظ…غŒ/ط¬ط§غŒع¯ط²غŒظ† ط§ط­طھظ…ط§ظ„غŒ ط¨ط±ط§غŒ ظ‡ظ…ط§ظ† ظ…ط³غŒط±
@app.get("/subg/{sub_id}")
async def sub_group_alias(sub_id: str, request: Request, pw: str = ""):
    return await sub_group(sub_id, request, pw)


@app.get("/sub-all")
async def sub_all(request: Request, _=Depends(require_auth)):

    host = get_host(request)
    lines = []

    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            if not is_link_allowed(link):
                continue
            lines.append(generate_vless_link(
                uid,
                host,
                link.get("label", "X4G"),
                link.get("protocol", DEFAULT_PROTOCOL),
                link.get("fingerprint", DEFAULT_FINGERPRINT),
                link.get("alpn", ""),
                link.get("port", 443),
            ))

    return build_subscription(lines)


@app.get("/api/public/sub/{sub_id}")
async def public_sub_info(sub_id: str, request: Request, pw: str = ""):

    async with SUBS_LOCK:
        sub = SUBS.get(sub_id)
        if not sub:
            raise HTTPException(404, "not found")

        name = sub.get("name", "")
        desc = sub.get("desc", "")
        locked = bool(sub.get("password_hash")) and hash_password(pw) != sub.get("password_hash")

        if locked:
            return {"locked": True, "name": name}

    base = get_base_url(request)
    host = get_host(request)

    async with LINKS_LOCK:
        member = [(uid, l) for uid, l in LINKS.items() if l.get("sub_id") == sub_id]
        total_used = sum(l.get("used_bytes", 0) for _, l in member)
        member_uuids = {uid for uid, _ in member}

        links_data = []
        for uid, link in member:
            links_data.append({
                "label": link.get("label", ""),
                "active": is_link_allowed(link),
                "protocol": link.get("protocol", DEFAULT_PROTOCOL),
                "connections": count_connected_ips(uid),
                "used_bytes": link.get("used_bytes", 0),
                "limit_bytes": link.get("limit_bytes", 0),
                "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
                "vless_link": generate_vless_link(
                    uid,
                    host,
                    link.get("label", "X4G"),
                    link.get("protocol", DEFAULT_PROTOCOL),
                    link.get("fingerprint", DEFAULT_FINGERPRINT),
                    link.get("alpn", ""),
                    link.get("port", 443),
                ),
                "sub_url": f"{base}/sub/{uid}",
            })

    active_connections = sum(1 for c in connections.values() if c.get("uuid") in member_uuids)

    return {
        "locked": False,
        "name": name,
        "desc": desc,
        "sub_url": f"{base}/sub-group/{sub_id}",
        "total_used_fmt": fmt_bytes(total_used),
        "active_connections": active_connections,
        "links": links_data,
    }


@app.get("/pub/{sub_id}", response_class=HTMLResponse)
async def public_page(sub_id: str):

    async with SUBS_LOCK:
        exists = sub_id in SUBS

    if not exists:
        raise HTTPException(404, "not found")

    try:
        from pages import get_public_page_html
        return HTMLResponse(get_public_page_html(sub_id))
    except Exception as e:
        return HTMLResponse(f"<h2>Public page unavailable</h2><pre>{e}</pre>")


# ظ†ط§ظ… ط¬ط§غŒع¯ط²غŒظ† ط§ط­طھظ…ط§ظ„غŒ ط¨ط±ط§غŒ ظ‡ظ…ط§ظ† طµظپط­ظ‡â€ŒغŒ ظ¾ط§ط¨ظ„غŒع©
@app.get("/s/{sub_id}", response_class=HTMLResponse)
async def public_page_alias(sub_id: str):
    return await public_page(sub_id)


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  طµظپط­ط§طھ ط¯ط§ط´ط¨ظˆط±ط¯ / ظˆط±ظˆط¯
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):

    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/login")

    try:
        from pages import DASHBOARD_HTML
        return HTMLResponse(DASHBOARD_HTML)
    except Exception as e:
        return HTMLResponse(f"<h2>Dashboard unavailable</h2><pre>{e}</pre>")


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    try:
        from pages import LOGIN_HTML
        return HTMLResponse(LOGIN_HTML)
    except Exception:
        return HTMLResponse("<h2>Login</h2>")


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ظ…ط§عکظˆظ„â€Œظ‡ط§غŒ ط¬ط§ظ†ط¨غŒ ط§ط®طھغŒط§ط±غŒ (طھظˆظ†ظ„ VLESS/WS ظˆ XHTTP)
#  ظ‡ط±ع©ط¯ط§ظ… ظ…ط³طھظ‚ظ„ import ظ…غŒâ€Œط´ظˆظ†ط¯ طھط§ ظ†ط¨ظˆط¯ظگ غŒع©غŒطŒ ط¯غŒع¯ط±غŒ ط±ط§ ط؛غŒط±ظپط¹ط§ظ„ ظ†ع©ظ†ط¯
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

try:
    from speed_limit import reset_bucket
except Exception as e:
    logger.warning(f"speed_limit disabled: {e}")

    def reset_bucket(uid: str):
        pass


try:
    from relay_vless import websocket_tunnel

    app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

except Exception as e:
    logger.warning(f"relay disabled: {e}")


try:
    from xhttp_siz10 import router as xhttp_router

    app.include_router(xhttp_router)

except Exception as e:
    logger.warning(f"xhttp disabled: {e}")


# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ
#  ظ‡ظ†ط¯ظ„ط± ط®ط·ط§ظ‡ط§غŒ ظ¾غŒط´â€Œط¨غŒظ†غŒâ€Œظ†ط´ط¯ظ‡ (ط¨ط±ط§غŒ طµظپط­ظ‡â€ŒغŒ آ«ط®ط·ط§ظ‡ط§آ»)
# â•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گâ•گ

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log_error(str(exc), str(request.url))
    logger.exception(f"unhandled error: {exc}")
    return JSONResponse({"detail": "internal server error"}, status_code=500)


if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        workers=1
    )

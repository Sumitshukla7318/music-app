import hmac, json, os, re, time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
DATA = Path(os.getenv("DATA_DIR", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)
STORE = DATA / "playlist.json"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
fails: dict[str, list[float]] = {}  # very small brute-force guard


def read_id() -> str:
    try:
        return json.loads(STORE.read_text()).get("playlist_id", "")
    except Exception:
        return os.getenv("DEFAULT_PLAYLIST_ID", "")


def parse_id(v: str) -> str | None:
    v = v.strip()
    m = re.search(r"[?&]list=([\w-]+)", v)
    pid = m.group(1) if m else v
    return pid if re.fullmatch(r"[\w-]{10,64}", pid) else None


def check_admin(password: str, ip: str = "x"):
    now = time.time()
    recent = [t for t in fails.get(ip, []) if now - t < 300]
    if len(recent) >= 5:
        raise HTTPException(429, "Too many wrong attempts. Try again in 5 minutes.")
    if not ADMIN_PASSWORD or not hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
        fails[ip] = recent + [now]
        raise HTTPException(401, "Wrong password.")
    fails.pop(ip, None)


class NewPlaylist(BaseModel):
    playlist: str


@app.get("/api/playlist")
def get_playlist():
    return {"playlist_id": read_id()}


@app.post("/api/admin/check")
def admin_check(x_admin_password: str = Header("")):
    check_admin(x_admin_password)
    return {"ok": True, "playlist_id": read_id()}


@app.put("/api/playlist")
def set_playlist(body: NewPlaylist, x_admin_password: str = Header("")):
    check_admin(x_admin_password)
    pid = parse_id(body.playlist)
    if not pid:
        raise HTTPException(400, "That doesn't look like a playlist link. Copy it from the playlist page.")
    STORE.write_text(json.dumps({"playlist_id": pid}))
    return {"playlist_id": pid}


@app.get("/admin")
def admin_page():
    return FileResponse(BASE / "static" / "admin.html", headers={"X-Robots-Tag": "noindex"})


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")

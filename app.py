# app.py
import os
import sys
import base64
import datetime as dt
import json
import random
import string
from typing import Dict, Any

import requests
from flask import Flask, request, jsonify, make_response, redirect
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId

import jwt
# exceptions import compatible across PyJWT versions
try:
    from jwt import InvalidTokenError, ExpiredSignatureError
except Exception:
    from jwt.exceptions import InvalidTokenError, ExpiredSignatureError


# ──────────────────────────────────────────────────────────────────────────────
# Environment
# ──────────────────────────────────────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
DB_NAME = os.environ.get("DB_NAME", "epic_seven_armory").strip()

# Twitch Extension (EBS) secret for verifying Extension JWTs
TWITCH_EXTENSION_SECRET = os.environ.get("TWITCH_EXTENSION_SECRET", "").strip()
TWITCH_EXTENSION_CLIENT_ID = os.environ.get("TWITCH_EXTENSION_CLIENT_ID", "").strip()

# Twitch OAuth (for user-initiated linking in browser)
TWITCH_OAUTH_CLIENT_ID = os.environ.get("TWITCH_OAUTH_CLIENT_ID", "").strip()
TWITCH_OAUTH_CLIENT_SECRET = os.environ.get("TWITCH_OAUTH_CLIENT_SECRET", "").strip()
TWITCH_OAUTH_REDIRECT_URI = os.environ.get("TWITCH_OAUTH_REDIRECT_URI", "").strip()

# Public base URL of this server (for redirects/callbacks), e.g.
# https://epicsevenarmoryserver-87gz.onrender.com
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

# Additional CORS origins (comma-separated)
EXTRA_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
]

DEFAULT_TWITCH_ORIGINS = [
    "https://www.twitch.tv",
    "https://dashboard.twitch.tv",
    "https://extension-files.twitch.tv",
    "http://127.0.0.1:5500",  # Live Server (dev)
    "http://localhost:5500",
]
if TWITCH_EXTENSION_CLIENT_ID:
    DEFAULT_TWITCH_ORIGINS.append(f"https://{TWITCH_EXTENSION_CLIENT_ID}.ext-twitch.tv")

ALLOWED_ORIGINS = set(DEFAULT_TWITCH_ORIGINS + EXTRA_ALLOWED_ORIGINS)


# ──────────────────────────────────────────────────────────────────────────────
# Flask app & CORS (must be defined BEFORE any @app.route)
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# CORS is handled entirely by _reflect_cors / @app.after_request below.
# flask_cors is intentionally NOT used here — its after_request hook runs
# after ours and overwrites the Electron null-origin wildcard we set.

def _is_electron_origin(origin: str) -> bool:
    # Electron renders from file:// which sends a null or empty Origin header.
    return not origin or origin == "null"

def _reflect_cors(resp):
    origin = request.headers.get("Origin")
    if _is_electron_origin(origin):
        # Desktop app (Electron) — allow wildcard so fetch() calls succeed
        resp.headers["Access-Control-Allow-Origin"] = "*"
    elif origin and (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS):
        resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Username, username"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

@app.after_request
def after_request(resp):
    return _reflect_cors(resp)

def _preflight_ok():
    resp = make_response("", 204)
    return _reflect_cors(resp)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _now() -> dt.datetime:
    return dt.datetime.utcnow()

def _now_utc() -> dt.datetime:
    # alias for clarity in code that expects _now_utc
    return _now()

def _b64_to_bytes(s: str) -> bytes:
    s = (s or "").strip()
    missing = (-len(s)) % 4
    if missing:
        s += "=" * missing
    try:
        return base64.b64decode(s)
    except Exception as e:
        print(f"[JWT] Base64 decode failed: {e}", file=sys.stderr)
        return b""

def _rand_code(n=4):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

def _make_link_code() -> str:
    # format: H7QK-29FD
    return f"{_rand_code(4)}-{_rand_code(4)}"

def _in(seconds: int) -> dt.datetime:
    return _now() + dt.timedelta(seconds=seconds)


# ──────────────────────────────────────────────────────────────────────────────
# MongoDB connection (BEFORE any code that uses collections)
# ──────────────────────────────────────────────────────────────────────────────
client = None
db = None
Users = None
TwitchChannels = None
ImageStats = None
LinkCodes = None
PendingLinks = None  # used by /auth/twitch/* flow

try:
    if not MONGO_URI:
        raise RuntimeError("MONGO_URI is missing. Set it in your environment.")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")

    db = client.get_database(DB_NAME) if DB_NAME else client.get_default_database()
    if db is None:
        raise RuntimeError("Mongo connected but database handle is None. Check DB_NAME / URI path.")

    Users = db["Users"]
    TwitchChannels = db["twitch_channels"]
    ImageStats = db["ImageStats"]             # your existing stats collection
    LinkCodes = db["twitch_link_codes"]       # for /link/code/* flow
    PendingLinks = db["pending_links"]        # for /auth/twitch/* flow

    print(f"[Mongo] Connected. DB={db.name}", file=sys.stderr)

except PyMongoError as e:
    print(f"[Mongo] Connection error: {e}", file=sys.stderr)
except Exception as e:
    print(f"[Mongo] Setup error: {e}", file=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# JWT verification for Twitch Extension
# ──────────────────────────────────────────────────────────────────────────────
EXT_SECRET_BYTES = _b64_to_bytes(TWITCH_EXTENSION_SECRET)

def verify_ext_jwt(auth_header: str) -> Dict[str, Any]:
    if not auth_header or " " not in auth_header:
        raise ValueError("Missing or malformed Authorization header")
    scheme, token = auth_header.split(" ", 1)
    if scheme.lower() != "bearer":
        raise ValueError("Expected Bearer token")
    if not EXT_SECRET_BYTES:
        raise ValueError("Server missing/invalid TWITCH_EXTENSION_SECRET")

    # Decode claims without verification so we can log them for debugging
    try:
        unverified = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False},
            algorithms=["HS256"],
        )
        print(f"[JWT] Unverified claims: {unverified}", file=sys.stderr)
    except Exception as ue:
        print(f"[JWT] Could not decode token at all: {ue}", file=sys.stderr)

    print(f"[JWT] Secret bytes length: {len(EXT_SECRET_BYTES)}", file=sys.stderr)
    print(f"[JWT] Token prefix: {token[:20]}...", file=sys.stderr)

    try:
        payload = jwt.decode(
            token,
            EXT_SECRET_BYTES,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except ExpiredSignatureError:
        raise ValueError("Token expired")
    except InvalidTokenError as e:
        print(f"[JWT] Signature verification failed. Secret len={len(EXT_SECRET_BYTES)}, error={e}", file=sys.stderr)
        raise ValueError(f"Invalid token: {e}")
    if "channel_id" not in payload or "role" not in payload:
        raise ValueError("Token missing required claims")
    return payload


# ──────────────────────────────────────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify(
        {
            "ok": True,
            "service": "e7-armory-api",
            "time": _now().isoformat() + "Z",
            "db_connected": bool(db is not None),
            "client_id": TWITCH_EXTENSION_CLIENT_ID or None,
            "secret_loaded": bool(EXT_SECRET_BYTES),
            "secret_bytes_len": len(EXT_SECRET_BYTES),
        }
    )


@app.route("/debug/jwt", methods=["GET", "OPTIONS"])
def debug_jwt():
    """Debug endpoint — decodes the extension JWT without verifying signature.
    Shows claims and secret status so we can diagnose mismatches."""
    if request.method == "OPTIONS":
        return _preflight_ok()
    auth = request.headers.get("Authorization", "")
    if not auth or " " not in auth:
        return jsonify({"error": "No Authorization header"}), 400
    token = auth.split(" ", 1)[1]
    try:
        unverified = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False},
            algorithms=["HS256"],
        )
    except Exception as e:
        return jsonify({"error": f"Could not decode token: {e}"}), 400
    return jsonify({
        "claims": unverified,
        "secret_loaded": bool(EXT_SECRET_BYTES),
        "secret_bytes_len": len(EXT_SECRET_BYTES),
    })


# ──────────────────────────────────────────────────────────────────────────────
# Twitch OAuth (link_code flow for desktop/Electron linking) - /auth/twitch/*
# ──────────────────────────────────────────────────────────────────────────────
def _twitch_auth_url(link_code: str, return_to: str = "close") -> str:
    """
    Build the Twitch OAuth authorization URL. We put the link_code in 'state'.
    """
    from urllib.parse import urlencode
    params = {
        "client_id": TWITCH_OAUTH_CLIENT_ID,
        "redirect_uri": TWITCH_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "user:read:email",
        "state": link_code,
        "force_verify": "true",  # force account selector
    }
    return "https://id.twitch.tv/oauth2/authorize?" + urlencode(params)

def _twitch_exchange_code(code: str) -> dict:
    r = requests.post(
        "https://id.twitch.tv/oauth2/token",
        data={
            "client_id": TWITCH_OAUTH_CLIENT_ID,
            "client_secret": TWITCH_OAUTH_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": TWITCH_OAUTH_REDIRECT_URI,
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()

def _twitch_get_user(access_token: str) -> dict:
    r = requests.get(
        "https://api.twitch.tv/helix/users",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Client-Id": TWITCH_OAUTH_CLIENT_ID,
        },
        timeout=15,
    )
    r.raise_for_status()
    data = r.json() or {}
    d = (data.get("data") or [])
    return d[0] if d else {}

def _html_close_page(title: str, body: str):
    # Tiny helper to close the tab if opened with return_to=close
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:Arial,sans-serif;margin:24px">
  <h2>{title}</h2>
  <p>{body}</p>
  <script>try {{
    if (window.opener) {{ window.opener.postMessage({{"e7_link_done": true}}, "*"); }}
    window.close();
  }} catch (e) {{}}
  </script>
</body></html>"""

@app.route("/auth/twitch/start", methods=["GET", "OPTIONS"])
def auth_twitch_start():
    """
    Desktop app: call this in an external browser with:
      GET /auth/twitch/start?link_code=...&return_to=close
    Provide the Armory username via the 'Username' header (or ?username=...).

    We store a pending record keyed by link_code so the callback knows which
    user to attach the Twitch identity to.
    """
    if request.method == "OPTIONS":
        return _preflight_ok()

    if not (TWITCH_OAUTH_CLIENT_ID and TWITCH_OAUTH_CLIENT_SECRET and TWITCH_OAUTH_REDIRECT_URI):
        return jsonify({"error": "Twitch OAuth app not configured"}), 500

    link_code = (request.args.get("link_code") or "").strip()
    if not link_code or len(link_code) < 8:
        return jsonify({"error": "link_code required"}), 400

    # Who are we linking this Twitch identity to?
    username = request.headers.get("Username") or request.args.get("username") or ""
    username = username.strip()
    if not username:
        return jsonify({"error": "Username header or ?username is required"}), 400

    # Confirm user exists
    user_doc = Users.find_one({"username": username}) if Users else None
    if not user_doc:
        return jsonify({"error": "User not found"}), 404

    # Create/refresh pending link record (TTL ~10 minutes)
    PendingLinks.update_one(
        {"link_code": link_code},
        {"$set": {
            "link_code": link_code,
            "username": username,
            "status": "pending",
            "created_at": _now_utc(),
            "updated_at": _now_utc(),
        }},
        upsert=True
    )

    auth_url = _twitch_auth_url(link_code, request.args.get("return_to", "close"))
    return jsonify({"ok": True, "auth_url": auth_url})

@app.route("/auth/twitch/callback", methods=["GET"])
def auth_twitch_callback():
    """
    Twitch OAuth redirect endpoint.
    - state = link_code we issued
    - code  = Twitch authorization code
    We exchange, fetch Helix user, and attach to the Armory user stored in PendingLinks.
    """
    code = request.args.get("code", "").strip()
    link_code = request.args.get("state", "").strip()  # we set this to link_code
    if not code or not link_code:
        return _html_close_page("Link failed", "Missing code or state (link_code)."), 400

    pending = PendingLinks.find_one({"link_code": link_code}) if PendingLinks else None
    if not pending:
        return _html_close_page("Link failed", "Invalid or expired link_code."), 400

    try:
        token = _twitch_exchange_code(code)
        access_token = token.get("access_token")
        if not access_token:
            raise RuntimeError("Missing access_token")

        tuser = _twitch_get_user(access_token)
        if not tuser:
            raise RuntimeError("No user from Twitch")

        # Normalize what we store
        twitch_user_id = tuser.get("id")
        twitch_login   = (tuser.get("login") or "").lower()
        display_name   = tuser.get("display_name") or tuser.get("login") or ""
        avatar_url     = tuser.get("profile_image_url")

        # Attach to the Armory user — store under links.twitch to match /link/callback schema
        Users.update_one(
            {"username": pending["username"]},
            {"$set": {
                "links.twitch.user_id": twitch_user_id,
                "links.twitch.login": twitch_login,
                "links.twitch.display_name": display_name,
                "links.twitch.avatar_url": avatar_url,
                "links.twitch.linked_at": _now_utc(),
            }}
        )

        PendingLinks.update_one(
            {"_id": pending["_id"]},
            {"$set": {"status": "linked", "updated_at": _now_utc(), "twitch_login": twitch_login}}
        )

        return _html_close_page("Linked!", "Your Twitch account has been linked. You can close this window.")

    except Exception as e:
        PendingLinks.update_one(
            {"_id": pending["_id"]},
            {"$set": {"status": "error", "error": str(e), "updated_at": _now_utc()}}
        )
        return _html_close_page("Link failed", f"{e}"), 400

@app.route("/auth/link/status", methods=["GET", "OPTIONS"])
def auth_link_status():
    """
    Desktop app polls this:
      GET /auth/link/status?link_code=...
    Returns linked:true when callback succeeded.
    """
    if request.method == "OPTIONS":
        return _preflight_ok()

    link_code = (request.args.get("link_code") or "").strip()
    if not link_code:
        return jsonify({"error": "link_code required"}), 400

    row = PendingLinks.find_one({"link_code": link_code}) if PendingLinks else None
    if not row:
        return jsonify({"ok": True, "linked": False, "status": "unknown"}), 200

    status = row.get("status") or "pending"
    return jsonify({
        "ok": True,
        "linked": status == "linked",
        "status": status,
        "twitch_login": row.get("twitch_login"),
        "username": row.get("username"),
    }), 200


# ──────────────────────────────────────────────────────────────────────────────
# Twitch Extension Routes (overlay/config)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/twitch/my_armory", methods=["GET", "OPTIONS"])
def twitch_my_armory():
    """
    Given a broadcaster JWT, return the Armory username linked to that Twitch user_id.
    Used by the config page to auto-detect and pre-fill the username field.
    """
    if request.method == "OPTIONS":
        return _preflight_ok()
    try:
        payload = verify_ext_jwt(request.headers.get("Authorization"))
        twitch_user_id = str(payload.get("user_id") or "")
        if not twitch_user_id:
            return jsonify({"ok": True, "username": None, "reason": "no_user_id_in_jwt"})
        user = Users.find_one({
            "$or": [
                {"links.twitch.user_id": twitch_user_id},
                {"twitch_user_id": twitch_user_id},
            ]
        })
        if user:
            return jsonify({"ok": True, "username": user.get("username")})
        return jsonify({"ok": True, "username": None, "reason": "not_linked"})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/twitch/channel_config", methods=["GET", "OPTIONS"])
def twitch_channel_config():
    """
    GET the current channel mapping for the authenticated broadcaster.
    Called by config.js on load (after onAuthorized) so the input is
    pre-populated from the server rather than only from Twitch CDN storage.
    Returns { ok, channel_id, username } — username is null if not yet mapped.
    """
    if request.method == "OPTIONS":
        return _preflight_ok()
    try:
        payload = verify_ext_jwt(request.headers.get("Authorization"))
        channel_id = payload["channel_id"]
        mapping = TwitchChannels.find_one({"channel_id": channel_id})
        return jsonify({
            "ok": True,
            "channel_id": channel_id,
            "username": mapping.get("username") if mapping else None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@app.route("/twitch/map_channel", methods=["POST", "OPTIONS"])
def twitch_map_channel():
    if request.method == "OPTIONS":
        return _preflight_ok()
    try:
        payload = verify_ext_jwt(request.headers.get("Authorization"))
        if payload.get("role") != "broadcaster":
            return jsonify({"error": "Only broadcaster may map the channel"}), 403

        data = request.get_json(force=True) or {}
        username = (data.get("username") or "").strip()
        if not username:
            return jsonify({"error": "username required"}), 400

        # Verify the caller actually owns this Armory username by comparing the
        # Twitch user_id in the JWT against the one stored when they linked accounts.
        twitch_jwt_uid = str(payload.get("user_id") or "")
        if twitch_jwt_uid:
            user_doc = Users.find_one({"username": username})
            if not user_doc:
                return jsonify({"error": f"Armory username '{username}' not found."}), 404
            stored_uid = str(
                (user_doc.get("links") or {}).get("twitch", {}).get("user_id")
                or user_doc.get("twitch_user_id")
                or ""
            )
            if not stored_uid:
                return jsonify({"error": (
                    "This Armory account has not been linked to a Twitch account yet. "
                    "Open the Armory desktop app \u2192 Profile \u2192 Link Twitch, then try again."
                )}), 403
            if stored_uid != twitch_jwt_uid:
                return jsonify({"error": (
                    "This Twitch account is not linked to that Armory username. "
                    "Make sure you linked your accounts in the Armory desktop app."
                )}), 403

        channel_id = payload["channel_id"]
        doc = {
            "channel_id": channel_id,
            "username": username,
            "updated_at": _now(),
        }
        TwitchChannels.find_one_and_update(
            {"channel_id": channel_id},
            {"$set": doc},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return jsonify({"ok": True, "channel_id": channel_id, "username": username})
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@app.route("/twitch/selected_units", methods=["GET", "OPTIONS"])
def twitch_selected_units():
    if request.method == "OPTIONS":
        return _preflight_ok()
    try:
        payload = verify_ext_jwt(request.headers.get("Authorization"))
        mapping = TwitchChannels.find_one({"channel_id": payload["channel_id"]})
        if not mapping:
            return jsonify([])
        username = mapping.get("username")

        # selected_units is a SEPARATE collection (not a field on the User doc).
        # Look up unit_id1..4, then resolve each to a full ImageStats document.
        sel_doc = db.selected_units.find_one({"username": username}) or {}
        unit_ids = [
            sel_doc.get(f"unit_id{i}")
            for i in range(1, 5)
            if sel_doc.get(f"unit_id{i}")
        ]
        units_data = []
        for uid in unit_ids:
            try:
                unit = ImageStats.find_one({"_id": ObjectId(uid)})
                if unit:
                    unit["_id"] = str(unit["_id"])
                    units_data.append(unit)
            except Exception:
                pass
        return jsonify(units_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 401


# ──────────────────────────────────────────────────────────────────────────────
# Live Viewer / Desktop-compatible routes (your existing behavior)
# ──────────────────────────────────────────────────────────────────────────────
@app.route('/your_units', methods=['GET', 'POST', 'OPTIONS'])
def your_units():
    if request.method == 'OPTIONS':
        return _preflight_ok()

    if request.method == 'GET':
        try:
            username = request.headers.get('Username') or request.headers.get('username') or request.args.get('username')
            if not username:
                return jsonify([]), 200
            units = list(ImageStats.find({"uploaded_by": username}))
            for unit in units:
                unit['_id'] = str(unit['_id'])
            units = sorted(units, key=lambda x: x.get('unit', ''))
            return jsonify(units), 200
        except Exception as e:
            print(f"[HTML] /your_units GET error: {e}", file=sys.stderr)
            return jsonify({"error": f"server error: {e}"}), 500

    # POST: fetch a single unit by name for this user
    try:
        form = request.get_json() or {}
        unit_name = form.get('unit')
        username = request.headers.get('Username') or request.headers.get('username') or request.args.get('username')
        if not username:
            return jsonify({"error": "Username not provided"}), 400
        unit = ImageStats.find_one({"uploaded_by": username, "unit": unit_name})
        if unit:
            unit['_id'] = str(unit['_id'])
            return jsonify(unit), 200
        return jsonify({"error": "Unit not found"}), 404
    except Exception as e:
        print(f"[HTML] /your_units POST error: {e}", file=sys.stderr)
        return jsonify({"error": f"server error: {e}"}), 500

@app.route('/update_unit_stats', methods=['POST'])
def update_unit_stats():
    payload = request.get_json(silent=True) or {}
    unit_id = payload.get('unit_id')
    updates = payload.get('updates') or {}
    username = request.headers.get('Username') or request.headers.get('username') or request.args.get('username')

    if not username:
        return jsonify({"error": "Username not provided"}), 400
    if not unit_id:
        return jsonify({"error": "unit_id is required"}), 400

    allowed = {
        "unit", "name", "unit_name",
        "attack", "defense", "health", "speed",
        "imprint",
        "critical_hit_chance", "critical_hit_damage",
        "effectiveness", "effect_resistance",
        "set1", "set2", "set3",
    }
    clean = {k: v for k, v in updates.items() if k in allowed}
    if not clean:
        return jsonify({"error": "No valid fields to update"}), 400

    for f in ("attack", "defense", "health", "speed"):
        if f in clean:
            try:
                if clean[f] in ("", None):
                    clean[f] = None
                else:
                    clean[f] = int(float(clean[f]))
            except Exception:
                pass

    res = ImageStats.update_one(
        {"_id": ObjectId(unit_id), "uploaded_by": username},
        {"$set": clean}
    )

    if res.matched_count == 0:
        return jsonify({"error": "Unit not found or not authorized to update"}), 404

    updated = ImageStats.find_one({"_id": ObjectId(unit_id)})
    if updated:
        updated["_id"] = str(updated["_id"])
    return jsonify({"ok": True, "unit": updated}), 200

@app.route('/update_selected_units', methods=['POST', 'OPTIONS'])
def update_selected_units():
    if request.method == 'OPTIONS':
        return _preflight_ok()

    username = request.headers.get('Username') or request.headers.get('username') or request.args.get('username')
    if not username:
        return jsonify({"error": "Username not provided"}), 400

    data = request.json or {}
    selected_units = data.get('units', [])
    selected_units = selected_units[:4]
    while len(selected_units) < 4:
        selected_units.append(None)

    result = db.selected_units.update_one(
        {"username": username},
        {"$set": {
            "unit_id1": selected_units[0]['id'] if selected_units[0] else None,
            "unit_id2": selected_units[1]['id'] if selected_units[1] else None,
            "unit_id3": selected_units[2]['id'] if selected_units[2] else None,
            "unit_id4": selected_units[3]['id'] if selected_units[3] else None,
            "updated_at": _now(),
        }},
        upsert=True
    )

    if result.acknowledged:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update selected units'}), 500

@app.route('/get_selected_units_data', methods=['GET', 'OPTIONS'])
def get_selected_units_data():
    if request.method == 'OPTIONS':
        return _preflight_ok()

    username = request.headers.get('Username') or request.headers.get('username') or request.args.get('username')
    if not username:
        return jsonify({"error": "Username not provided"}), 400

    selected_units = db.selected_units.find_one({"username": username})
    if not selected_units:
        return jsonify([]), 200

    unit_ids = [selected_units.get(f'unit_id{i}') for i in range(1, 5) if selected_units.get(f'unit_id{i}')]

    units_data = []
    for unit_id in unit_ids:
        try:
            unit = ImageStats.find_one({"_id": ObjectId(unit_id)})
            if unit:
                unit['_id'] = str(unit['_id'])
                units_data.append(unit)
        except Exception:
            pass

    return jsonify(units_data), 200


# ──────────────────────────────────────────────────────────────────────────────
# NEW: Twitch Linking (Render-hosted) - /link* routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/link/code/start", methods=["POST", "OPTIONS"])
def link_code_start():
    if request.method == "OPTIONS":
        return _preflight_ok()

    username = request.headers.get("Username") or request.headers.get("username")
    if not username:
        return jsonify({"error": "Username header required"}), 400

    code = _make_link_code()
    expires_at = _in(600)  # 10 minutes

    LinkCodes.insert_one({
        "link_code": code,
        "username": username,
        "status": "pending",
        "created_at": _now(),
        "expires_at": expires_at,
        "twitch_user_id": None,
        "twitch_login": None,
    })

    return jsonify({"link_code": code, "expires_in": 600})

@app.route("/link", methods=["GET"])
def link_page():
    code = request.args.get("code", "").strip()
    session_hint = request.args.get("armory_session", "").strip()

    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Link Twitch</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    body {{ font-family: Arial, sans-serif; padding: 24px; background: #0f172a; color: #e2e8f0; }}
    .card {{ max-width: 520px; margin: 0 auto; background: rgba(255,255,255,.04); border: 1px solid rgba(255,255,255,.08);
             border-radius: 10px; padding: 18px; }}
    .btn {{ display:inline-block; padding: 10px 14px; border-radius: 8px; background: #9146FF; color: white; text-decoration: none; }}
    code {{ background: rgba(255,255,255,.08); padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Link your Twitch account</h2>
    <p>This will securely confirm your Twitch identity and link it to your Armory account.</p>
    {"<p>Link code: <code>"+code+"</code></p>" if code else ""}
    <p><a class="btn" href="/link/start?{('code='+code) if code else ('armory_session='+session_hint if session_hint else '')}">Connect with Twitch</a></p>
  </div>
</body>
</html>
"""
    return html

@app.route("/link/start", methods=["GET"])
def link_start():
    code = request.args.get("code", "").strip()
    armory_session = request.args.get("armory_session", "").strip()  # optional future use

    if not TWITCH_OAUTH_CLIENT_ID or not TWITCH_OAUTH_CLIENT_SECRET or not PUBLIC_BASE_URL:
        return "OAuth not configured on server (set TWITCH_OAUTH_CLIENT_ID/SECRET and PUBLIC_BASE_URL).", 500

    state_payload = {"ts": int(_now().timestamp())}
    if code:
        state_payload["link_code"] = code
    if armory_session:
        state_payload["armory_session"] = armory_session

    state = base64.urlsafe_b64encode(json.dumps(state_payload).encode("utf-8")).decode("utf-8").rstrip("=")

    params = {
        "client_id": TWITCH_OAUTH_CLIENT_ID,
        "redirect_uri": f"{PUBLIC_BASE_URL}/link/callback",
        "response_type": "code",
        "scope": "user:read:email",
        "state": state,
        "force_verify": "true",
    }
    from urllib.parse import urlencode
    auth_url = "https://id.twitch.tv/oauth2/authorize?" + urlencode(params)
    return redirect(auth_url, code=302)

@app.route("/link/callback", methods=["GET"])
def link_callback():
    error = request.args.get("error")
    if error:
        return f"OAuth error: {error}", 400

    auth_code = request.args.get("code", "")
    raw_state = request.args.get("state", "")

    def _decode_state(s: str) -> Dict[str, Any]:
        if not s:
            return {}
        padding = "=" * (-len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s + padding).decode("utf-8"))
        except Exception:
            return {}

    state = _decode_state(raw_state)
    link_code = state.get("link_code")

    if not TWITCH_OAUTH_CLIENT_ID or not TWITCH_OAUTH_CLIENT_SECRET or not PUBLIC_BASE_URL:
        return "OAuth not configured on server.", 500

    token_res = requests.post(
        "https://id.twitch.tv/oauth2/token",
        data={
            "client_id": TWITCH_OAUTH_CLIENT_ID,
            "client_secret": TWITCH_OAUTH_CLIENT_SECRET,
            "code": auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": f"{PUBLIC_BASE_URL}/link/callback",
        },
        timeout=10,
    )
    if token_res.status_code != 200:
        return f"Token exchange failed: {token_res.text}", 400

    token_data = token_res.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return "No access token returned.", 400

    user_res = requests.get(
        "https://api.twitch.tv/helix/users",
        headers={
            "Client-Id": TWITCH_OAUTH_CLIENT_ID,
            "Authorization": f"Bearer {access_token}",
        },
        timeout=10,
    )
    if user_res.status_code != 200:
        return f"Helix /users failed: {user_res.text}", 400

    users = user_res.json().get("data", [])
    if not users:
        return "No Twitch user found.", 400

    tw_user = users[0]
    twitch_user_id = tw_user.get("id")
    twitch_login = tw_user.get("login")

    # Complete linking via link_code (desktop-flow)
    if link_code:
        doc = LinkCodes.find_one({"link_code": link_code})
        if not doc:
            return "Link code not found.", 400
        if doc.get("status") != "pending":
            return "Link code already used or invalid.", 400
        if doc.get("expires_at") and doc["expires_at"] < _now():
            return "Link code expired.", 400

        username = doc.get("username")
        if not username:
            return "Link code missing username.", 400

        # Update Users record with twitch link info
        Users.find_one_and_update(
            {"username": username},
            {
                "$set": {
                    "links.twitch": {
                        "user_id": twitch_user_id,
                        "login": twitch_login,
                        "linked_at": _now(),
                    }
                }
            },
            upsert=False,
            return_document=ReturnDocument.AFTER,
        )

        # Mark code as used
        LinkCodes.update_one(
            {"_id": doc["_id"]},
            {"$set": {"status": "linked", "twitch_user_id": twitch_user_id, "twitch_login": twitch_login, "used_at": _now()}}
        )

        return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"/><title>Linked</title></head>
<body style="font-family:Arial;padding:24px;background:#0f172a;color:#e2e8f0">
  <h2>✅ Twitch linked</h2>
  <p>Linked Twitch user: <strong>@{twitch_login}</strong></p>
  <p>You can close this tab and return to the app.</p>
</body>
</html>
"""

    return "Linked, but no link_code flow was used. (Add armory_session handling if needed.)", 200


# ──────────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)

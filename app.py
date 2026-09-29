import os
import secrets
import hashlib
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session, jsonify, send_from_directory

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "").strip()
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "").strip()
REDIRECT_URI = os.environ.get("TIKTOK_REDIRECT_URI", "").strip()

# Keep this to the permissions needed by the current Upload-to-Draft flow.
SCOPES = "user.info.basic,video.upload"

AUTHORIZE_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
UPLOAD_INIT_URL = "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/"
STATUS_URL = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

def config_status():
    return {
        "client_key_set": bool(CLIENT_KEY),
        "client_secret_set": bool(CLIENT_SECRET),
        "redirect_uri_set": bool(REDIRECT_URI),
        "redirect_uri": REDIRECT_URI,
        "client_key_fingerprint": hashlib.sha256(CLIENT_KEY.encode()).hexdigest()[:12] if CLIENT_KEY else None,
    }

@app.get("/")
def index():
    return send_from_directory(".", "index.html")

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "tiktok-uploader", "config": config_status()})

@app.get("/config-check")
def config_check():
    return jsonify(config_status())

@app.get("/oauth/tiktok")
def oauth_tiktok():
    missing = []
    if not CLIENT_KEY:
        missing.append("TIKTOK_CLIENT_KEY")
    if not CLIENT_SECRET:
        missing.append("TIKTOK_CLIENT_SECRET")
    if not REDIRECT_URI:
        missing.append("TIKTOK_REDIRECT_URI")
    if missing:
        return jsonify({
            "ok": False,
            "error": "missing_environment_variables",
            "missing": missing,
            "config": config_status(),
        }), 500

    state = secrets.token_urlsafe(32)
    session["tiktok_oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    return redirect(AUTHORIZE_URL + "?" + urlencode(params))

@app.get("/callback/")
def callback():
    if request.args.get("error"):
        return jsonify({
            "ok": False,
            "stage": "tiktok_authorization",
            "error": request.args.get("error"),
            "error_description": request.args.get("error_description", ""),
            "state": request.args.get("state", ""),
        }), 400

    state = request.args.get("state", "")
    expected = session.pop("tiktok_oauth_state", None)
    if not expected or not secrets.compare_digest(state, expected):
        return jsonify({
            "ok": False,
            "stage": "callback",
            "error": "invalid_state",
            "message": "OAuth state mismatch. Start login again.",
        }), 400

    code = request.args.get("code", "")
    if not code:
        return jsonify({"ok": False, "stage": "callback", "error": "missing_code"}), 400

    data = {
        "client_key": CLIENT_KEY,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }

    try:
        r = requests.post(
            TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        payload = r.json()
    except Exception as exc:
        return jsonify({
            "ok": False,
            "stage": "token_exchange",
            "error": "request_failed",
            "message": str(exc),
        }), 502

    if r.status_code >= 400 or payload.get("error"):
        # Never return the client secret or authorization code.
        return jsonify({
            "ok": False,
            "stage": "token_exchange",
            "http_status": r.status_code,
            "tiktok_error": payload.get("error"),
            "error_description": payload.get("error_description"),
            "log_id": payload.get("log_id"),
            "config": config_status(),
            "message": (
                "TikTok rejected the token exchange. Check that CLIENT KEY/SECRET "
                "belong to the same TikTok app and that the redirect URI is identical."
            ),
        }), 400

    session["tiktok_access_token"] = payload.get("access_token")
    session["tiktok_refresh_token"] = payload.get("refresh_token")
    session["tiktok_open_id"] = payload.get("open_id")
    session["tiktok_scope"] = payload.get("scope", "")

    return redirect("/?login=success")

@app.get("/api/session")
def api_session():
    token = session.get("tiktok_access_token")
    return jsonify({
        "logged_in": bool(token),
        "open_id": session.get("tiktok_open_id"),
        "scope": session.get("tiktok_scope", ""),
    })

@app.post("/api/upload")
def api_upload():
    token = session.get("tiktok_access_token")
    if not token:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401

    uploaded = request.files.get("video")
    if not uploaded or not uploaded.filename:
        return jsonify({"ok": False, "error": "video_file_required"}), 400

    video_bytes = uploaded.read()
    if not video_bytes:
        return jsonify({"ok": False, "error": "empty_file"}), 400

    size = len(video_bytes)
    # TikTok's media-transfer guide requires chunks >=5 MB and <=64 MB,
    # except the final chunk. A single chunk is simplest for normal Shorts.
    chunk_size = size
    total_chunks = 1

    init_body = {
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": size,
            "chunk_size": chunk_size,
            "total_chunk_count": total_chunks,
        }
    }

    try:
        init = requests.post(
            UPLOAD_INIT_URL,
            json=init_body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            timeout=30,
        )
        init_payload = init.json()
    except Exception as exc:
        return jsonify({"ok": False, "stage": "init", "error": str(exc)}), 502

    init_error = init_payload.get("error", {})
    if init.status_code >= 400 or init_error.get("code") not in (None, "", "ok"):
        return jsonify({
            "ok": False,
            "stage": "init",
            "http_status": init.status_code,
            "tiktok": init_payload,
        }), 400

    upload_url = (init_payload.get("data") or {}).get("upload_url")
    publish_id = (init_payload.get("data") or {}).get("publish_id")
    if not upload_url or not publish_id:
        return jsonify({
            "ok": False,
            "stage": "init",
            "error": "TikTok did not return upload_url/publish_id",
            "tiktok": init_payload,
        }), 502

    mime = uploaded.mimetype or "video/mp4"
    try:
        put = requests.put(
            upload_url,
            data=video_bytes,
            headers={
                "Content-Type": mime,
                "Content-Length": str(size),
                "Content-Range": f"bytes 0-{size - 1}/{size}",
            },
            timeout=120,
        )
    except Exception as exc:
        return jsonify({
            "ok": False,
            "stage": "upload",
            "publish_id": publish_id,
            "error": str(exc),
        }), 502

    if put.status_code not in (200, 201, 206):
        return jsonify({
            "ok": False,
            "stage": "upload",
            "publish_id": publish_id,
            "http_status": put.status_code,
            "response": put.text[:2000],
        }), 400

    return jsonify({
        "ok": True,
        "publish_id": publish_id,
        "message": "Video uploaded to TikTok inbox/draft. Open TikTok inbox to continue editing and post.",
    })

@app.get("/api/status/<publish_id>")
def api_status(publish_id):
    token = session.get("tiktok_access_token")
    if not token:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401

    try:
        r = requests.post(
            STATUS_URL,
            json={"publish_id": publish_id},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            timeout=30,
        )
        return jsonify(r.json()), r.status_code
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

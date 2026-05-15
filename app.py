import json
import os
import time
from numpy import floor
from sqlalchemy import update
from urllib.parse import quote_plus
import jwt
from jwt import PyJWKClient
import requests
from flask import Blueprint, Flask, jsonify, redirect, request, session
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Float
from elasticsearch import Elasticsearch
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "keycloak")
DB_HOST = os.getenv("DB_HOST", "keycloak")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "keycloak")
DB_URL = f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

LIBRARY_URL = os.getenv("LIBRARY_API_URL", "http://library:2000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:8000/")
POST_LOGOUT_REDIRECT_URI = os.getenv("POST_LOGOUT_REDIRECT_URI", "http://127.0.0.1:8000/api/")

engine = create_engine(
    DB_URL,
    echo=False,
    pool_size=500,
    pool_pre_ping=True,
    max_overflow=40,
    pool_timeout=3,
    pool_recycle=1800,
)

lobby = Blueprint('lobby', __name__)
gameBP = Blueprint('game', __name__)

Base = declarative_base()
es = Elasticsearch(
    os.getenv("ELASTICSEARCH_URL") or "http://elasticsearch:9200",
    verify_certs=False,
)


class Lobby(Base):
    __tablename__ = 'lobbies'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    username = Column(String, nullable=False)
    active = Column(Integer, default=0, nullable=True)
    songid = Column(Integer, nullable=True)
    timestamp = Column(Integer, nullable=True)


class PlayerInfo(Base):
    __tablename__ = 'players'
    username = Column(String, primary_key=True)
    lobbyId = Column(Integer, nullable=True)
    score = Column(Float, default=0.0, nullable=True)
    status = Column(Integer, default=0, nullable=True)


class SongInfo(Base):
    __tablename__ = 'songs'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    artist = Column(String, nullable=False)
    lyrics = Column(String, nullable=False)
    filename = Column(String, nullable=True)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
PORT = 5000
ADDRESS = os.getenv("ADDRESS", "127.0.0.1")
REDIRECT_URI = f"http://{ADDRESS}:8000/api/callback"

AUTH_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"
SIGNUP_URL = f"{KEYCLOAK_URL}/realms/{REALM}/login-actions/registration"
TOKEN_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/token"
LOGOUT_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
USERINFO_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
JWKS_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/certs"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def role_required(required_role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return jsonify({"error": "unauthorized"}), 401
            roles = session["user"].get("realm_access", {}).get("roles", [])
            if "admin" in roles or required_role in roles:
                return f(*args, **kwargs)
            return jsonify({"error": "forbidden"}), 403
        return decorated
    return wrapper


def serialize_user():
    user = session.get("user")
    if not user:
        return None
    return {
        "username": user.get("preferred_username", "User"),
        "email": user.get("email"),
        "roles": user.get("realm_access", {}).get("roles", []),
    }


@app.route("/me")
def me():
    user = serialize_user()
    if not user:
        return jsonify({"authenticated": False}), 200
    return jsonify({"authenticated": True, "user": user})


@app.route("/login")
def login():
    auth_redirect = (
        f"{AUTH_URL}?client_id={CLIENT_ID}"
        f"&response_type=code&scope=openid profile email"
        f"&redirect_uri={REDIRECT_URI}"
    )
    return redirect(auth_redirect)


@app.route("/callback")
def callback():
    auth_code = request.args.get("code")
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    requests_response = requests.post(TOKEN_URL, data=data)
    access_token = requests_response.json().get("access_token")
    id_token = requests_response.json().get("id_token")

    if not access_token:
        return redirect(f"{FRONTEND_URL}?error=login_failed")

    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)

    decoded_token = jwt.decode(
        access_token,
        signing_key.key,
        algorithms=["RS256"],
        options={"verify_aud": False},
    )

    session["user"] = decoded_token
    session["access_token"] = access_token
    session["id_token"] = id_token

    return redirect(FRONTEND_URL)


@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()

    logout_redirect = (
        f"{LOGOUT_URL}?client_id={CLIENT_ID}"
        f"&post_logout_redirect_uri={POST_LOGOUT_REDIRECT_URI}"
        f"&id_token_hint={id_token}"
    )

    return redirect(logout_redirect)


@app.route("/")
def api_root():
    return redirect(FRONTEND_URL)


@app.route("/lobbies/clear", methods=["POST"])
@login_required
@role_required("admin")
def clear_lobbies():
    db = SessionLocal()
    db.query(Lobby).delete()
    db.commit()
    return jsonify({"ok": True})


@app.route("/players/clear", methods=["POST"])
@login_required
@role_required("admin")
def clear_players():
    db = SessionLocal()
    db.query(PlayerInfo).delete()
    db.commit()
    return jsonify({"ok": True})


@app.route("/lobbies")
@login_required
def lobbies():
    username = session["user"].get("preferred_username")

    db = SessionLocal()
    lobbies_list = db.query(Lobby).all()
    player_record = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()

    current_lobby = None
    players_in_lobby = []
    if player_record and player_record.lobbyId:
        current_lobby = db.query(Lobby).filter(Lobby.id == player_record.lobbyId).first()
        players_in_lobby = (
            db.query(PlayerInfo).filter(PlayerInfo.lobbyId == player_record.lobbyId).all()
        )

    def lobby_dict(l):
        return {
            "id": l.id,
            "name": l.name,
            "username": l.username,
            "active": l.active,
        }

    return jsonify({
        "username": username,
        "lobbies": [lobby_dict(l) for l in lobbies_list],
        "current_lobby": lobby_dict(current_lobby) if current_lobby else None,
        "players_in_lobby": [
            {"username": p.username, "score": p.score} for p in players_in_lobby
        ],
    })


@lobby.route("/create", methods=["POST"])
@login_required
def lobby_create():
    payload = request.get_json(silent=True) or {}
    lobby_name = payload.get("name") or request.form.get("name")
    username = session["user"].get("preferred_username")

    db = SessionLocal()
    new_lobby = Lobby(name=lobby_name, username=username, active=0, timestamp=0)
    db.add(new_lobby)
    db.commit()

    lobby_id = db.query(Lobby).order_by(Lobby.id.desc()).first().id
    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    if player:
        u = update(PlayerInfo).where(PlayerInfo.username == username).values(lobbyId=lobby_id)
        db.execute(u)
    else:
        new_player = PlayerInfo(username=username, lobbyId=lobby_id)
        db.add(new_player)
    db.commit()

    return jsonify({"ok": True, "lobby_id": lobby_id})


@lobby.route("/join/<int:lobby_id>", methods=["POST"])
@login_required
def lobby_join(lobby_id):
    username = session["user"].get("preferred_username")

    db = SessionLocal()

    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    if player:
        u = update(PlayerInfo).where(PlayerInfo.username == username).values(lobbyId=lobby_id)
        db.execute(u)
    else:
        new_player = PlayerInfo(username=username, lobbyId=lobby_id, score=0, status=0)
        db.add(new_player)
    db.commit()
    return jsonify({"ok": True})


@lobby.route("/status/<int:lobby_id>", methods=["GET"])
@login_required
def lobby_status(lobby_id):
    db = SessionLocal()
    lobby_row = db.query(Lobby).filter(Lobby.id == lobby_id).first()
    if not lobby_row:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"active": lobby_row.active})


@lobby.route("/leave", methods=["POST"])
@login_required
def lobby_leave():
    username = session["user"].get("preferred_username")

    db = SessionLocal()
    db.execute(
        update(PlayerInfo)
        .where(PlayerInfo.username == username)
        .values(lobbyId=None, score=0, status=0)
    )
    db.commit()
    return jsonify({"ok": True})


@gameBP.route("/start", methods=["POST"])
@login_required
def game_start():
    username = session["user"].get("preferred_username")
    db = SessionLocal()

    playerInfo = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    if not playerInfo or not playerInfo.lobbyId:
        return jsonify({"error": "no_lobby"}), 400

    lobbyInfo = db.query(Lobby).filter(Lobby.id == playerInfo.lobbyId).first()
    if lobbyInfo.active != 0:
        return jsonify({"ok": True})

    songs_list = db.query(SongInfo).all()
    if not songs_list:
        return jsonify({"error": "no_songs"}), 400

    random_song = songs_list[int(time.time()) % len(songs_list)]

    processed_song = (
        random_song.lyrics.lower()
        .replace("\n", " ")
        .replace(",", "")
        .replace(".", "")
        .replace("!", "")
        .replace("?", "")
        .replace(";", "")
        .replace(":", "")
        .replace("\r", " ")
    )

    indexName = random_song.name.lower().replace(" ", "_")
    for i in range(10, len(processed_song) + 10, 10):
        es.index(index=indexName + str(i), body={"lyric": processed_song[:i]})

    db.execute(update(Lobby).where(Lobby.id == lobbyInfo.id).values(songid=random_song.id))
    db.commit()

    if username != lobbyInfo.username:
        return jsonify({"ok": True})

    db.execute(update(Lobby).where(Lobby.id == lobbyInfo.id).values(active=1))
    db.commit()
    return jsonify({"ok": True})


@gameBP.route("/ready", methods=["POST"])
@login_required
def ready():
    username = session["user"].get("preferred_username")
    db = SessionLocal()
    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    db.execute(update(PlayerInfo).where(PlayerInfo.username == username).values(status=1))
    db.commit()

    players = db.query(PlayerInfo).filter(PlayerInfo.lobbyId == player.lobbyId).all()
    all_ready = all(p.status != 0 for p in players)

    if all_ready:
        lobby_row = db.query(Lobby).filter(Lobby.id == player.lobbyId).first()
        db.execute(update(Lobby).where(Lobby.id == lobby_row.id).values(active=2))

    db.commit()

    return jsonify({"status": 2 if all_ready else 1})


@gameBP.route("/update", methods=["POST"])
@login_required
def game_update():
    solution = request.json.get("lyrics", "")
    db = SessionLocal()

    song = db.query(SongInfo).filter(SongInfo.id == request.json.get("songId")).first()
    if not song:
        return jsonify({"error": "no_song"}), 404

    length = len(solution)
    length = int(floor(length / 10) * 10 + 10)
    indexName = song.name.lower().replace(" ", "_")
    es_res = es.search(index=indexName + str(length), query={"match": {"lyric": solution}})

    username = session["user"].get("preferred_username")
    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    score = 0
    if es_res['hits']['max_score'] is not None:
        score = int(es_res['hits']['max_score'] * 100)
        db.execute(
            update(PlayerInfo)
            .where(PlayerInfo.username == username)
            .values(score=score)
        )

    lobby_row = db.query(Lobby).filter(Lobby.id == player.lobbyId).first()
    players = db.query(PlayerInfo).filter(PlayerInfo.lobbyId == player.lobbyId).all()
    db.commit()

    return jsonify({
        "status": lobby_row.active,
        "score": score,
        "players": [{"username": p.username, "score": p.score} for p in players],
    })


@app.route("/game", methods=["GET"])
@login_required
def game():
    username = session["user"].get("preferred_username")
    db = SessionLocal()

    playerInfo = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    if not playerInfo or not playerInfo.lobbyId:
        return jsonify({"error": "no_lobby"}), 404

    lobbyInfo = db.query(Lobby).filter(Lobby.id == playerInfo.lobbyId).first()
    if not lobbyInfo or lobbyInfo.active == 0:
        return jsonify({"error": "not_started"}), 404

    songInfo = db.query(SongInfo).filter(SongInfo.id == lobbyInfo.songid).first()
    roles = session["user"].get("realm_access", {}).get("roles", [])

    return jsonify({
        "song": {
            "id": songInfo.id,
            "name": songInfo.name,
            "artist": songInfo.artist,
            "lyrics": songInfo.lyrics if "admin" in roles else None,
        },
        "lobby": {
            "id": lobbyInfo.id,
            "name": lobbyInfo.name,
            "active": lobbyInfo.active,
        },
        "is_admin": "admin" in roles,
    })


@app.route("/library")
@login_required
@role_required("admin")
def library():
    db = SessionLocal()
    songs_list = db.query(SongInfo).all()
    return jsonify({
        "songs": [
            {"id": s.id, "name": s.name, "artist": s.artist, "filename": s.filename}
            for s in songs_list
        ]
    })


@app.route("/add_song", methods=["POST"])
@login_required
@role_required("admin")
def add_song():
    song_name = request.form.get("name")
    song_artist = request.form.get("artist")
    song_lyrics = request.form.get("lyrics")
    file = request.files['file']
    filename = file.filename

    response = requests.post(
        f"{LIBRARY_URL}/upload",
        files={"file": (filename, file.stream, file.mimetype)},
    )
    if response.status_code != 200:
        return jsonify({"error": "File upload failed"}), 500

    db = SessionLocal()
    new_song = SongInfo(name=song_name, artist=song_artist, lyrics=song_lyrics, filename=filename)
    db.add(new_song)
    db.commit()

    return jsonify({"ok": True, "id": new_song.id})


@app.route("/get_song/<int:song_id>", methods=["GET"])
@login_required
def get_song(song_id):
    db = SessionLocal()
    song = db.query(SongInfo).filter(SongInfo.id == song_id).first()
    if not song:
        return jsonify({"error": "Song not found"}), 404

    response = requests.get(f"{LIBRARY_URL}/download/{secure_filename(song.filename)}")
    if response.status_code != 200:
        return jsonify({"error": "File download failed"}), 500

    return response.content, 200, {
        'Content-Type': 'audio/mpeg',
        'Content-Disposition': f'attachment; filename="{song.filename}"',
    }


@app.route("/debug")
@login_required
def debug():
    return jsonify(session.get('user', {}))


if __name__ == "__main__":
    max_retries = 30
    retry_count = 0
    print("Initializing database connection...", flush=True)

    app.register_blueprint(lobby, url_prefix="/lobby")
    app.register_blueprint(gameBP, url_prefix="/game")
    while retry_count < max_retries:
        try:
            engine.connect()
            print("Database connected successfully")
            break
        except Exception as e:
            retry_count += 1
            print(f"Database connection failed, retrying... ({retry_count}/{max_retries})")
            time.sleep(1)

    db = SessionLocal()
    db.query(Lobby).delete()
    db.query(PlayerInfo).delete()
    db.commit()

    if es.ping():
        print("Connected to Elasticsearch")
    else:
        print("Connection failed")

    print(f"Starting app on http://{ADDRESS}:{PORT}")
    app.run(host='0.0.0.0', port=int(PORT), debug=True)

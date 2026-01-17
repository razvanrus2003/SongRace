import json
import os
from time import time
from numpy import floor
from sqlalchemy import text
from sqlalchemy import update
from urllib.parse import quote_plus
from xml.dom.minidom import Text
import jwt
from jwt import PyJWKClient
import requests
from flask import Blueprint, Flask, redirect, request, session, url_for, render_template
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Float
from elasticsearch import Elasticsearch
from werkzeug.utils import secure_filename

# ---------------- Load Configuration ----------------
# Do not change these (except for REDIRECT_URI, you can choose another port)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Database setup
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "keycloak")
DB_HOST = os.getenv("DB_HOST", "keycloak")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "keycloak")
DB_URL = f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

LIBRARY_URL = os.getenv("LIBRARY_API_URL", "http://library:2000")

engine = create_engine(DB_URL, echo=False, 
                        pool_size=500,
                        max_overflow=40,
                        pool_timeout=3,
                        pool_recycle=1800
                        )

lobby = Blueprint('lobby', __name__)
gameBP = Blueprint('game', __name__)

Base = declarative_base()
es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://127.0.0.1:9200"), verify_certs=False)

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

# Environment variables
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
PORT =5000
ADDRESS = os.getenv("ADDRESS", "127.0.0.1")
REDIRECT_URI = f"http://{ADDRESS}:{PORT}/callback"

# Keycloak endpoints
AUTH_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"
SIGNUP_URL = f"{KEYCLOAK_URL}/realms/{REALM}/login-actions/registration"
TOKEN_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/token"
LOGOUT_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
USERINFO_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
JWKS_URL = f"http://keycloak:8080/realms/{REALM}/protocol/openid-connect/certs"

# ---------------- Helper Methods ----------------
# Do not change these

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            print(url_for("login"))
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(required_role):
    """Allow access if user has the required role OR is an admin."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            roles = session["user"].get("realm_access", {}).get("roles", [])
            if "admin" in roles or required_role in roles:
                return f(*args, **kwargs)
            return render_template("access_denied.html")
        return decorated
    return wrapper

# ---------------- Routes ----------------

@app.route("/")
def home():
    if "user" in session:
        username = session["user"].get("preferred_username", "User")
        roles = session["user"].get("realm_access", {}).get("roles", [])
        role_info = ", ".join(roles) if roles else "No roles"

        return render_template("home.html", user=session["user"], username=username, role_info=role_info)
    return render_template("home.html", user=None)


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
    print("Callback called", flush=True)
    # TODO: Extract the authorization code from the URL query parameters sent by Keycloak
    auth_code = request.args.get("code")
    # TODO: Prepare the data for the token exchange request
    #   We should add grant type, authorization code, redirect URI (we already have it defined) and client id
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID
    }
    # TODO: Make a POST request to Keycloak's token endpoint to exchange the authorization code for token
    requests_response = requests.post(TOKEN_URL, data=data)
    # TODO: Parse the token and extract: access token and identity token
    access_token = requests_response.json().get("access_token")
    id_token = requests_response.json().get("id_token")

    # TODO: Render "login_failed.html" template if no access token was found
    if not access_token:
        return render_template("login_failed.html")

    # Decode JWT
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)

    decoded_token = jwt.decode(
        access_token,
        signing_key.key,
        algorithms=["RS256"],
        options={"verify_aud": False}  # Ignore audience for this demo
    )

    # TODO: Store the decoded token, the access token and the identity token in the current session

    session["user"] = decoded_token
    session["access_token"] = access_token
    session["id_token"] = id_token
    # login_user(decoded_token)

    return redirect(url_for("home"))

@app.route("/lobbies/clear")
@login_required
@role_required("admin")
def clear_lobbies():
    
    db = SessionLocal()
    db.query(Lobby).delete()
    db.commit()

    return redirect(url_for("lobbies"))

@app.route("/players/clear")
@login_required
@role_required("admin")
def clear_players():
    
    db = SessionLocal()
    db.query(PlayerInfo).delete()
    db.commit()

    return redirect(url_for("lobbies"))

@app.route("/lobbies")
@login_required
def lobbies():
    username = session["user"].get("preferred_username")
    
    db = SessionLocal()
    lobbies_list = db.query(Lobby).all()
    current_lobby = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    players_in_lobby = None
    if current_lobby:
        players_in_lobby = db.query(PlayerInfo).filter(PlayerInfo.lobbyId == current_lobby.lobbyId).all()
        current_lobby = db.query(Lobby).filter(Lobby.id == current_lobby.lobbyId).first()
    print(lobbies_list, flush=True)
    return render_template("lobbies.html", username=username, lobbies=lobbies_list, current_lobby=current_lobby, players_in_lobby=players_in_lobby)

@lobby.route("/create", methods=["POST"])
@login_required
def lobby_create():
    lobby_name = request.form.get("name")
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

    return redirect(url_for("lobbies"))

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
    return redirect(url_for("lobbies"))

@lobby.route("/status/<int:lobby_id>", methods=["GET"])
@login_required
def lobby_status(lobby_id):
    db = SessionLocal()
    lobby = db.query(Lobby).filter(Lobby.id == lobby_id).first()
    response = {"active": lobby.active}
    return json.dumps(response)

@lobby.route("/leave", methods=["POST", "GET"])
@login_required
def lobby_leave():
    username = session["user"].get("preferred_username")

    db = SessionLocal()

    u = update(PlayerInfo).where(PlayerInfo.username == username).values(lobbyId=None)

    db.execute(u)
    u = update(PlayerInfo).where(PlayerInfo.username == username).values(score=0)
    db.execute(u)

    u = update(PlayerInfo).where(PlayerInfo.username == username).values(status=0)
    db.execute(u)
    db.commit()
    return redirect(url_for("home"))

@gameBP.route("/start", methods=["POST"])
@login_required
def game_start():
    username = session["user"].get("preferred_username")
    db = SessionLocal()

    playerInfo = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    lobbyInfo = db.query(Lobby).filter(Lobby.id == playerInfo.lobbyId).first()
    if (lobbyInfo.active != 0):
        return redirect(url_for("game"))
    
    songs_list = db.query(SongInfo).all()

    random_song = songs_list[int(time()) % len(songs_list)]

    proccesd_song = random_song.lyrics.lower().replace("\n", " ").replace(",", "").replace(".", "").replace("!", "").replace("?", "").replace(";", "").replace(":", "").replace("\r", " ")
    words = proccesd_song.split(" ")
    words = list(set(words))
    body = {}
    indexName = random_song.name.lower().replace(" ", "_")
    for i in range(10, len(proccesd_song)+10, 10):
        es.index(index=indexName+str(i), body={"lyric": proccesd_song[:i]})

    u = update(Lobby).where(Lobby.id == lobbyInfo.id).values(songid=random_song.id)
    db.execute(u)
    db.commit()
    
    if (username != lobbyInfo.username):
        return redirect(url_for("lobbies"))
    u = update(Lobby).where(Lobby.id == lobbyInfo.id).values(active=1)
    db.execute(u)
    db.commit()
    return redirect(url_for("game"))

@gameBP.route("/ready", methods=["POST"])
@login_required
def ready():
    username = session["user"].get("preferred_username")
    db = SessionLocal()
    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    u = update(PlayerInfo).where(PlayerInfo.username == username).values(status=1)
    db.execute(u)

    db.commit()
    players = db.query(PlayerInfo).filter(PlayerInfo.lobbyId == player.lobbyId).all()
    all_ready = True
    for p in players:
        if p.status == 0:
            all_ready = False
            break
    if all_ready:
        lobby = db.query(Lobby).filter(Lobby.id == player.lobbyId).first()
        u = update(Lobby).where(Lobby.id == lobby.id).values(active=2)
        db.execute(u)
        
    db.commit()

    return json.dumps({"status": 2 if all_ready else 1})

@gameBP.route("/update", methods=["POST"])
@login_required
def game_update():
    print("Game update route called", flush=True)
    solution = request.json.get("lyrics")
    db = SessionLocal()

    song = db.query(SongInfo).filter(SongInfo.id == request.json.get("songId")).first()
    length = len(solution)
    length = int(floor(length / 10) * 10 + 10)
    print("Searching for:", str(length), solution, flush=True)
    indexName = song.name.lower().replace(" ", "_")
    es_res = es.search(index=indexName+str(length), query={"match": {"lyric": solution}})
    print(es_res, flush=True)

    db = SessionLocal()
    username = session["user"].get("preferred_username")
    player = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    print("Max score:", es_res['hits']['max_score'], flush=True)
    score = 0
    if (es_res['hits']['max_score'] is not None):
        score = int(es_res['hits']['max_score'] * 100)
        u = update(PlayerInfo).where(PlayerInfo.username == username).values(score=int(es_res['hits']['max_score'] * 100))
        db.execute(u)
        
    lobby = db.query(Lobby).filter(Lobby.id == player.lobbyId).first()

    players = db.query(PlayerInfo).filter(PlayerInfo.lobbyId == player.lobbyId).all()
    list = []
    for p in players:
        list.append({"username": p.username, "score": p.score})
    db.commit()

    response = {"status": lobby.active, "score": score, "players": list}
    return json.dumps(response)

@app.route("/game", methods=["POST", "GET"])
@login_required
def game():
    print("Game route called", flush=True)
    username = session["user"].get("preferred_username")
    db = SessionLocal()

    playerInfo = db.query(PlayerInfo).filter(PlayerInfo.username == username).first()
    lobbyInfo = db.query(Lobby).filter(Lobby.id == playerInfo.lobbyId).first()
    songInfo = db.query(SongInfo).filter(SongInfo.id == lobbyInfo.songid).first()
    if (lobbyInfo.active != 0):
        print(session["user"].get("realm_access", {}).get("roles", []), flush=True)
        return render_template("game.html", song=songInfo, lobby=lobbyInfo, role=session["user"].get("realm_access", {}).get("roles", [])[0])
    
    return redirect(url_for("lobbies"))



@app.route("/user")
@login_required
@role_required("user")
def user_dashboard():
    username = session["user"].get("preferred_username")
    return render_template("user_dashboard.html", username=username)

@app.route("/library")
@login_required
@role_required("admin")
def library():
    username = session["user"].get("preferred_username")
    
    db = SessionLocal()
    songs_list = db.query(SongInfo).all()
    # print(songs_list, flush=True)
    return render_template("library.html", songs=songs_list)

@app.route("/add_song", methods=["POST"])
@login_required
@role_required("admin")
def add_song():
    song_name = request.form.get("name")
    song_artist = request.form.get("artist")
    song_lyrics = request.form.get("lyrics")
    file = request.files['file']
    filename = file.filename

    response = requests.post(f"{LIBRARY_URL}/upload", files={"file": (filename, file.stream, file.mimetype)})
    if response.status_code != 200:
        return {"error": "File upload failed"}, 500

    db = SessionLocal()
    new_song = SongInfo(name=song_name, artist=song_artist, lyrics=song_lyrics, filename=filename)
    db.add(new_song)
    db.commit()

    return redirect(url_for("library"))

@app.route("/get_song/<int:song_id>", methods=["GET"])
@login_required
def get_song(song_id):
    db = SessionLocal()
    song = db.query(SongInfo).filter(SongInfo.id == song_id).first()
    if not song:
        return {"error": "Song not found"}, 404

    response = requests.get(f"{LIBRARY_URL}/download/{secure_filename(song.filename)}")
    if response.status_code != 200:
        return {"error": "File download failed"}, 500

    return response.content, 200, {
        'Content-Type': 'audio/mpeg',
        'Content-Disposition': f'attachment; filename="{song.filename}"'
    }

@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    username = session["user"].get("preferred_username")
    return render_template("admin_dashboard.html", username=username)

@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()

    logout_redirect = (
        f"{LOGOUT_URL}?client_id={CLIENT_ID}"
        f"&post_logout_redirect_uri={url_for('home', _external=True)}"
    )

    if id_token:
        logout_redirect += f"&id_token_hint={id_token}"

    return redirect(logout_redirect)

# Additional: Debug view to see decoded token content
@app.route("/debug")
def debug():
    import json
    user_data = json.dumps(session.get('user', {}), indent=2)
    return render_template("debug.html", user_data=user_data)

# ---------------- Run App ----------------
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
    # db.query(SongInfo).delete()
    # db.execute(text("ALTER TABLE songs ADD COLUMN IF NOT EXISTS lyrics VARCHAR"))

    # db.execute(text("ALTER TABLE lobbies ADD COLUMN IF NOT EXISTS songId INTEGER"))
    # db.execute(text("ALTER TABLE songs ADD COLUMN IF NOT EXISTS filename VARCHAR"))
    # db.execute(text("ALTER TABLE lobbies ADD COLUMN IF NOT EXISTS timestamp INTEGER"))
    # db.delete(text("DELETE FROM songs WHERE filename IS NULL"))
    # db.execute(text("ALTER TABLE players DROP COLUMN IF EXISTS score INTEGER"))
    # db.execute(text("ALTER TABLE players DROP COLUMN IF EXISTS status FLOAT"))
    # db.commit()
    # db.execute(text("ALTER TABLE players ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0"))
    # db.execute(text("ALTER TABLE players ADD COLUMN IF NOT EXISTS status FLOAT DEFAULT 0"))
    # db.execute(text("ALTER TABLE players ADD COLUMN IF NOT EXISTS score FLOAT DEFAULT 0.0"))
    # db.execute(text("ALTER TABLE players ADD COLUMN IF NOT EXISTS status INTEGER DEFAULT 0"))
    db.commit()

    if es.ping():
        print("Connected to Elasticsearch")
    else:
        print("Connection failed")
    
    print(f"Starting app on http://{ADDRESS}:{PORT}")
    app.run(host='0.0.0.0', port=int(PORT), debug=True)

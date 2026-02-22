from datetime import datetime, timezone, timedelta
import ipaddress
import json
import os
import re
import select
import shutil
import socket as socket_lib
import threading
import time
import uuid

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from flask import Flask, render_template, request, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
socketio = SocketIO(app, cors_allowed_origins='*')

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
PROJECTS_DIR  = os.path.join(BASE_DIR, 'projects')
CONFIG_FILE   = os.path.join(BASE_DIR, 'config.json')
CERT_FILE     = os.path.join(BASE_DIR, 'cert.pem')
KEY_FILE      = os.path.join(BASE_DIR, 'key.pem')
MAX_HISTORY   = 200

DEFAULT_CHANNELS = ['algemeen', 'foh', 'podium', 'licht']

PROJECT_DIR:  str = ''
DATA_FILE:    str = ''
USERS_FILE:   str = ''
UPLOADS_DIR:  str = ''
SETTINGS_FILE:str = ''

APP_CONFIG:     dict = {}
PROJECT_CONFIG: dict = {}
ACTIVE_PROJECT: str  = 'default'

CHANNELS: list        = list(DEFAULT_CHANNELS)
message_history: dict = {ch: [] for ch in CHANNELS}
connected_users: dict = {}
USERS: dict           = {}           # username → {password, is_admin}
SESSIONS: dict        = {}           # token → username
call_participants: dict = {}
CHANNEL_TOPICS: dict  = {}
START_TIME: float = time.time()

_countdown_timer: threading.Timer = None
_countdown_end_time: float = 0.0


# ── Config ──

def _project_config_defaults() -> dict:
    return {
        'language':               'nl',
        'timezone':               '',
        'max_file_size_mb':       50,
        'allowed_extensions':     [],
        'allow_all_channel_edit': False,
        'allow_registration':     True,
        'allow_all_countdown':    False,
    }


def _legacy_project_config() -> dict:
    defaults = _project_config_defaults()
    return {k: APP_CONFIG.get(k, defaults[k]) for k in defaults}


def _coerce_project_config(data: dict) -> dict:
    cfg = {**_project_config_defaults(), **(data or {})}
    try:
        cfg['max_file_size_mb'] = max(1, min(2000, int(cfg.get('max_file_size_mb', 50))))
    except Exception:
        cfg['max_file_size_mb'] = 50
    allowed = cfg.get('allowed_extensions', [])
    if not isinstance(allowed, list):
        allowed = []
    cfg['allowed_extensions'] = [str(ext).strip().lower() for ext in allowed if str(ext).strip()]
    cfg['language'] = str(cfg.get('language', 'nl') or 'nl')
    cfg['timezone'] = str(cfg.get('timezone', '') or '')
    cfg['allow_all_channel_edit'] = bool(cfg.get('allow_all_channel_edit', False))
    cfg['allow_registration'] = bool(cfg.get('allow_registration', True))
    cfg['allow_all_countdown'] = bool(cfg.get('allow_all_countdown', False))
    return cfg


def _project_settings_path(project_name: str) -> str:
    return os.path.join(PROJECTS_DIR, project_name, 'settings.json')


def load_project_settings(project_name: str):
    global PROJECT_CONFIG
    path = _project_settings_path(project_name)
    fallback = _coerce_project_config(_legacy_project_config())
    if os.path.exists(path):
        try:
            with open(path) as f:
                loaded = json.load(f)
            PROJECT_CONFIG = _coerce_project_config(loaded)
        except Exception as e:
            print(f'[settings] Laden mislukt ({project_name}): {e}')
            PROJECT_CONFIG = fallback
    else:
        PROJECT_CONFIG = fallback
    save_project_settings(project_name)


def save_project_settings(project_name: str = None):
    target = project_name or ACTIVE_PROJECT or 'default'
    path = _project_settings_path(target)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(_coerce_project_config(PROJECT_CONFIG), f, indent=2)
    except Exception as e:
        print(f'[settings] Opslaan mislukt ({target}): {e}')


def migrate_project_settings():
    source_cfg = _coerce_project_config(_legacy_project_config())
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    for proj in [d for d in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, d))]:
        path = _project_settings_path(proj)
        if os.path.exists(path):
            try:
                with open(path) as f:
                    raw = json.load(f)
                normalized = _coerce_project_config(raw)
                if raw != normalized:
                    with open(path, 'w') as f:
                        json.dump(normalized, f, indent=2)
            except Exception as e:
                print(f'[migrate] settings herstellen voor {proj}: {e}')
                with open(path, 'w') as f:
                    json.dump(source_cfg, f, indent=2)
            continue
        with open(path, 'w') as f:
            json.dump(source_cfg, f, indent=2)
        print(f'[migrate] settings.json aangemaakt voor project "{proj}"')


def _coerce_port(value, default: int = 5001) -> int:
    try:
        port = int(value)
    except Exception:
        return default
    return port if 1 <= port <= 65535 else default


def load_config():
    global APP_CONFIG, ACTIVE_PROJECT
    defaults = {
        'active_project':        'default',
        'port':                  5001,
        'username_case_sensitive': False,
        'language':              'nl',
        'timezone':              '',
        'max_file_size_mb':      50,
        'allowed_extensions':    [],
        'allow_all_channel_edit': False,
        'allow_registration':    True,
        'allow_all_countdown':   False,
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                APP_CONFIG = {**defaults, **json.load(f)}
        except Exception as e:
            print(f'[config] Laden mislukt: {e}')
            APP_CONFIG = defaults
    else:
        APP_CONFIG = defaults
    APP_CONFIG['port'] = _coerce_port(APP_CONFIG.get('port', 5001))
    APP_CONFIG['username_case_sensitive'] = bool(APP_CONFIG.get('username_case_sensitive', False))
    ACTIVE_PROJECT = APP_CONFIG.get('active_project', 'default')


def save_config():
    try:
        payload = {
            'active_project': APP_CONFIG.get('active_project', 'default'),
            'port': _coerce_port(APP_CONFIG.get('port', 5001)),
            'username_case_sensitive': bool(APP_CONFIG.get('username_case_sensitive', False)),
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        print(f'[config] Opslaan mislukt: {e}')


def _client_config() -> dict:
    """Subset of active project config that clients need to know."""
    return {
        'language':               PROJECT_CONFIG.get('language', 'nl'),
        'allow_all_channel_edit': PROJECT_CONFIG.get('allow_all_channel_edit', False),
        'allow_registration':     PROJECT_CONFIG.get('allow_registration', True),
        'allow_all_countdown':    PROJECT_CONFIG.get('allow_all_countdown', False),
    }


def set_project_paths(project_name: str):
    global PROJECT_DIR, DATA_FILE, USERS_FILE, UPLOADS_DIR, SETTINGS_FILE
    PROJECT_DIR = os.path.join(PROJECTS_DIR, project_name)
    DATA_FILE   = os.path.join(PROJECT_DIR, 'data.json')
    USERS_FILE  = os.path.join(PROJECT_DIR, 'users.json')
    UPLOADS_DIR = os.path.join(PROJECT_DIR, 'uploads')
    SETTINGS_FILE = os.path.join(PROJECT_DIR, 'settings.json')
    os.makedirs(UPLOADS_DIR, exist_ok=True)


def load_project(project_name: str):
    global ACTIVE_PROJECT
    ACTIVE_PROJECT = project_name
    set_project_paths(project_name)
    load_project_settings(project_name)
    CHANNELS.clear(); CHANNELS.extend(DEFAULT_CHANNELS)
    message_history.clear()
    for ch in CHANNELS:
        message_history[ch] = []
    USERS.clear(); CHANNEL_TOPICS.clear()
    load_data(); load_users()


def migrate_legacy_data():
    default_dir = os.path.join(PROJECTS_DIR, 'default')
    os.makedirs(default_dir, exist_ok=True)
    for fname in ('data.json', 'users.json'):
        src = os.path.join(BASE_DIR, fname)
        dst = os.path.join(default_dir, fname)
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copy2(src, dst)
            print(f'[migrate] {fname} → projects/default/{fname}')


# ── SSL ──

def _get_local_ips() -> list:
    ips = {'127.0.0.1'}
    try:
        s = socket_lib.socket(socket_lib.AF_INET, socket_lib.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); ips.add(s.getsockname()[0]); s.close()
    except Exception: pass
    try:
        for info in socket_lib.getaddrinfo(socket_lib.gethostname(), None, socket_lib.AF_INET):
            ips.add(info[4][0])
    except Exception: pass
    return list(ips)


def generate_ssl_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    print('[ssl] Zelfondertekend certificaat aanmaken…')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    local_ips = _get_local_ips()
    san = [x509.DNSName('localhost')] + [x509.IPAddress(ipaddress.IPv4Address(ip)) for ip in local_ips]
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'stagechat')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(CERT_FILE, 'wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_FILE, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    print(f'[ssl] Certificaat opgeslagen — {", ".join(local_ips)}')


# ── Persistence ──

def load_data():
    if not os.path.exists(DATA_FILE): return
    try:
        with open(DATA_FILE) as f: data = json.load(f)
        saved = data.get('channels', [])
        if saved:
            CHANNELS.clear(); CHANNELS.extend(saved)
            message_history.clear()
            for ch in CHANNELS: message_history[ch] = data.get('history', {}).get(ch, [])
        CHANNEL_TOPICS.clear(); CHANNEL_TOPICS.update(data.get('topics', {}))
    except Exception as e: print(f'[data] Laden mislukt: {e}')


def save_data():
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump({'channels': CHANNELS, 'topics': CHANNEL_TOPICS, 'history': message_history}, f)
    except Exception as e: print(f'[data] Opslaan mislukt: {e}')


def load_users():
    if not os.path.exists(USERS_FILE): return
    try:
        with open(USERS_FILE) as f: raw = json.load(f)
        first = True
        for username, value in raw.items():
            if isinstance(value, str):
                USERS[username] = {'password': value, 'is_admin': first}; first = False
            else:
                USERS[username] = value
    except Exception as e: print(f'[users] Laden mislukt: {e}')


def save_users():
    try:
        with open(USERS_FILE, 'w') as f: json.dump(USERS, f)
    except Exception as e: print(f'[users] Opslaan mislukt: {e}')


migrate_legacy_data()
load_config()
migrate_project_settings()
save_config()
load_project(ACTIVE_PROJECT)


# ── Helpers ──

def _now() -> str:
    tz_name = PROJECT_CONFIG.get('timezone', '')
    if tz_name and ZoneInfo:
        try:
            return datetime.now(ZoneInfo(tz_name)).strftime('%H:%M')
        except Exception:
            pass
    return datetime.now().astimezone().strftime('%H:%M')


def _add_message(channel, sender, text, msg_type='user') -> dict:
    msg = {'channel': channel, 'sender': sender, 'text': text, 'timestamp': _now(), 'type': msg_type}
    history = message_history.setdefault(channel, [])
    history.append(msg)
    if len(history) > MAX_HISTORY: history.pop(0)
    return msg


def _user_list() -> list:
    seen, users = set(), []
    for info in connected_users.values():
        if info['name'] not in seen: seen.add(info['name']); users.append(info['name'])
    return sorted(users)


def _remove_from_call(sid):
    for channel, participants in list(call_participants.items()):
        if sid in participants:
            participants.pop(sid); _broadcast_call_state(channel); break


def _broadcast_call_state(channel):
    participants = [{'sid': s, 'name': n} for s, n in call_participants.get(channel, {}).items()]
    emit('call_state', {'channel': channel, 'participants': participants}, to=channel)


def require_admin(token: str) -> bool:
    username = SESSIONS.get(token)
    user = USERS.get(username or '')
    return bool(user and isinstance(user, dict) and user.get('is_admin'))


def can_edit_channels(token: str) -> bool:
    if PROJECT_CONFIG.get('allow_all_channel_edit', False):
        return bool(SESSIONS.get(token))
    return require_admin(token)


def can_control_countdown(token: str) -> bool:
    if PROJECT_CONFIG.get('allow_all_countdown', False):
        return bool(SESSIONS.get(token))
    return require_admin(token)


def _get_server_ip() -> str:
    try:
        s = socket_lib.socket(socket_lib.AF_INET, socket_lib.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception: return '127.0.0.1'


def _project_names() -> list:
    if not os.path.exists(PROJECTS_DIR): return ['default']
    return sorted([d for d in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, d))])


def _dir_size(path: str) -> int:
    total = 0
    if not os.path.exists(path): return 0
    for dp, _, fnames in os.walk(path):
        for fname in fnames:
            try: total += os.path.getsize(os.path.join(dp, fname))
            except OSError: pass
    return total


def _file_size(path: str) -> int:
    try: return os.path.getsize(path) if os.path.exists(path) else 0
    except OSError: return 0


def _build_storage_list() -> list:
    storage = []
    for proj in _project_names():
        pdir = os.path.join(PROJECTS_DIR, proj)
        data_sz    = _file_size(os.path.join(pdir, 'data.json'))
        uploads_sz = _dir_size(os.path.join(pdir, 'uploads'))
        storage.append({'project': proj, 'data_size': data_sz, 'uploads_size': uploads_sz, 'total_size': data_sz + uploads_sz})
    return storage


def _is_tls_client_hello(prefix: bytes) -> bool:
    return len(prefix) >= 2 and prefix[0] == 0x16 and prefix[1] == 0x03


def _strip_host_port(host_header: str) -> str:
    host = (host_header or '').strip()
    if not host:
        return 'localhost'
    if host.startswith('['):
        end = host.find(']')
        return host[:end + 1] if end != -1 else host
    if ':' in host:
        return host.split(':', 1)[0]
    return host


def _redirect_response_for_request(raw_request: bytes, https_port: int) -> bytes:
    text = raw_request.decode('iso-8859-1', errors='ignore')
    lines = text.split('\r\n')
    path = '/'
    if lines:
        match = re.match(r'^[A-Z]+\s+(\S+)\s+HTTP/\d\.\d$', lines[0])
        if match:
            path = match.group(1)
    host = ''
    for line in lines[1:]:
        if line.lower().startswith('host:'):
            host = line.split(':', 1)[1].strip()
            break
    host_only = _strip_host_port(host)
    location = f'https://{host_only}:{https_port}{path}'
    payload = (
        'HTTP/1.1 308 Permanent Redirect\r\n'
        f'Location: {location}\r\n'
        'Connection: close\r\n'
        'Content-Length: 0\r\n'
        '\r\n'
    )
    return payload.encode('ascii', errors='ignore')


def _proxy_tcp_bidirectional(client_sock, upstream_sock):
    sockets = [client_sock, upstream_sock]
    while True:
        readable, _, _ = select.select(sockets, [], [], 30)
        if not readable:
            continue
        for src in readable:
            data = src.recv(65536)
            if not data:
                return
            dst = upstream_sock if src is client_sock else client_sock
            dst.sendall(data)


def _handle_mux_connection(client_sock, https_target_port: int, public_https_port: int):
    upstream_sock = None
    try:
        client_sock.settimeout(5)
        prefix = client_sock.recv(2, socket_lib.MSG_PEEK)
        if _is_tls_client_hello(prefix):
            upstream_sock = socket_lib.create_connection(('127.0.0.1', https_target_port), timeout=5)
            client_sock.settimeout(None)
            upstream_sock.settimeout(None)
            _proxy_tcp_bidirectional(client_sock, upstream_sock)
            return
        request_head = client_sock.recv(4096)
        client_sock.sendall(_redirect_response_for_request(request_head, public_https_port))
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        if upstream_sock is not None:
            try:
                upstream_sock.close()
            except Exception:
                pass


def _serve_http_https_mux(listen_host: str, public_port: int, https_target_port: int):
    srv = socket_lib.socket(socket_lib.AF_INET, socket_lib.SOCK_STREAM)
    srv.setsockopt(socket_lib.SOL_SOCKET, socket_lib.SO_REUSEADDR, 1)
    srv.bind((listen_host, public_port))
    srv.listen(128)
    print(f'[mux] HTTP->HTTPS redirect + TLS passthrough op poort {public_port}')
    while True:
        client_sock, _ = srv.accept()
        t = threading.Thread(
            target=_handle_mux_connection,
            args=(client_sock, https_target_port, public_port),
            daemon=True,
        )
        t.start()


def _username_case_sensitive() -> bool:
    return bool(APP_CONFIG.get('username_case_sensitive', False))


def _resolve_username_key(name: str):
    candidate = (name or '').strip()
    if not candidate:
        return None
    if _username_case_sensitive():
        return candidate if candidate in USERS else None
    norm = candidate.casefold()
    for stored in USERS.keys():
        if stored.casefold() == norm:
            return stored
    return None


# ── Routes ──

@app.route('/')
def index():
    return render_template('index.html', channels=CHANNELS)


@app.route('/upload', methods=['POST'])
def upload_file():
    token    = request.form.get('token', '')
    username = SESSIONS.get(token)
    if not username: return {'error': 'Niet geautoriseerd'}, 401
    if 'file' not in request.files: return {'error': 'Geen bestand'}, 400
    file = request.files['file']
    if not file.filename: return {'error': 'Geen bestandsnaam'}, 400
    allowed = PROJECT_CONFIG.get('allowed_extensions', [])
    if allowed:
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in allowed: return {'error': f'Bestandstype .{ext} niet toegestaan'}, 400
    max_mb = PROJECT_CONFIG.get('max_file_size_mb', 50)
    file.seek(0, 2); size = file.tell(); file.seek(0)
    if size > max_mb * 1024 * 1024: return {'error': f'Bestand te groot (max {max_mb} MB)'}, 400
    filename    = secure_filename(file.filename)
    unique_name = f'{int(time.time() * 1000)}_{filename}'
    file.save(os.path.join(UPLOADS_DIR, unique_name))
    return {'url': f'/uploads/{unique_name}', 'filename': filename, 'size': size}


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(UPLOADS_DIR, filename)


# ── Auth ──

@socketio.on('auth')
def on_auth(data):
    token = data.get('token')
    if token:
        username = SESSIONS.get(token)
        if username and username in USERS:
            is_admin = USERS[username].get('is_admin', False) if isinstance(USERS[username], dict) else False
            emit('auth_ok', {'token': token, 'username': username, 'is_admin': is_admin,
                             'project': ACTIVE_PROJECT, 'config': _client_config()})
        else:
            emit('auth_error', {'message': 'Sessie verlopen, log opnieuw in'})
        return

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    action   = data.get('action', 'login')

    if not username or not password:
        emit('auth_error', {'message': 'Vul gebruikersnaam en wachtwoord in'}); return

    if action == 'register':
        if not PROJECT_CONFIG.get('allow_registration', True) and len(USERS) > 0:
            emit('auth_error', {'message': 'Registratie is uitgeschakeld door de beheerder'}); return
        if len(username) < 2 or len(username) > 30:
            emit('auth_error', {'message': 'Gebruikersnaam moet 2–30 tekens zijn'}); return
        if len(password) < 4:
            emit('auth_error', {'message': 'Wachtwoord moet minimaal 4 tekens zijn'}); return
        if _resolve_username_key(username):
            emit('auth_error', {'message': 'Gebruikersnaam al in gebruik'}); return
        is_admin = len(USERS) == 0
        USERS[username] = {'password': generate_password_hash(password), 'is_admin': is_admin}
        save_users()
        user_key = username
    else:
        user_key = _resolve_username_key(username)
        user_data = USERS.get(user_key or '')
        if not user_data:
            emit('auth_error', {'message': 'Ongeldige gebruikersnaam of wachtwoord'}); return
        stored_pw = user_data['password'] if isinstance(user_data, dict) else user_data
        if not check_password_hash(stored_pw, password):
            emit('auth_error', {'message': 'Ongeldige gebruikersnaam of wachtwoord'}); return

    token    = str(uuid.uuid4())
    SESSIONS[token] = user_key
    is_admin = USERS[user_key].get('is_admin', False) if isinstance(USERS[user_key], dict) else False
    emit('auth_ok', {'token': token, 'username': user_key, 'is_admin': is_admin,
                     'project': ACTIVE_PROJECT, 'config': _client_config()})


# ── Chat events ──

@socketio.on('connect')
def on_connect(): pass


@socketio.on('join')
def on_join(data):
    sid   = request.sid
    token = data.get('token')
    if not token or token not in SESSIONS:
        emit('auth_error', {'message': 'Authenticatie vereist'}); return
    name    = SESSIONS[token]
    channel = data.get('channel', 'algemeen')
    if channel not in CHANNELS: channel = CHANNELS[0] if CHANNELS else 'algemeen'
    if sid in connected_users: leave_room(connected_users[sid]['channel'])
    connected_users[sid] = {'name': name, 'channel': channel}
    join_room(channel)
    emit('channel_list', {'channels': CHANNELS, 'topics': CHANNEL_TOPICS,
                          'project': ACTIVE_PROJECT, 'config': _client_config()})
    emit('channel_history', {'channel': channel, 'messages': message_history.get(channel, []),
                             'topic': CHANNEL_TOPICS.get(channel, '')})
    emit('new_message', _add_message(channel, 'systeem', f'{name} is de chat binnengetreden', 'system'), to=channel)
    emit('user_list', {'users': _user_list()}, broadcast=True)
    if call_participants.get(channel):
        participants = [{'sid': s, 'name': n} for s, n in call_participants[channel].items()]
        emit('call_state', {'channel': channel, 'participants': participants})
    if _countdown_end_time > time.time():
        emit('countdown_started', {'end_time': _countdown_end_time,
                                   'seconds': int(_countdown_end_time - time.time()), 'label': ''})


@socketio.on('switch_channel')
def on_switch_channel(data):
    sid = request.sid
    if sid not in connected_users: return
    new_channel = data.get('channel', 'algemeen')
    if new_channel not in CHANNELS: return
    user = connected_users[sid]; old_channel = user['channel']; name = user['name']
    if old_channel == new_channel: return
    _remove_from_call(sid)
    leave_room(old_channel)
    emit('new_message', _add_message(old_channel, 'systeem', f'{name} heeft #{old_channel} verlaten', 'system'), to=old_channel)
    connected_users[sid]['channel'] = new_channel
    join_room(new_channel)
    emit('channel_history', {'channel': new_channel, 'messages': message_history.get(new_channel, []),
                             'topic': CHANNEL_TOPICS.get(new_channel, '')})
    emit('new_message', _add_message(new_channel, 'systeem', f'{name} heeft #{new_channel} betreden', 'system'), to=new_channel)
    emit('user_list', {'users': _user_list()}, broadcast=True)
    if call_participants.get(new_channel):
        participants = [{'sid': s, 'name': n} for s, n in call_participants[new_channel].items()]
        emit('call_state', {'channel': new_channel, 'participants': participants})


@socketio.on('send_message')
def on_send_message(data):
    sid = request.sid
    if sid not in connected_users: return
    user = connected_users[sid]; channel = data.get('channel', user['channel'])
    if channel not in CHANNELS: return
    text = (data.get('text') or '').strip()
    if not text: return
    emit('new_message', _add_message(channel, user['name'], text, 'user'), broadcast=True)
    save_data()


@socketio.on('send_file_message')
def on_send_file_message(data):
    sid = request.sid
    if sid not in connected_users: return
    user = connected_users[sid]; channel = data.get('channel', user['channel'])
    if channel not in CHANNELS: return
    filename = data.get('filename', ''); url = data.get('url', ''); size = data.get('size', 0)
    if not filename or not url: return
    msg = {'channel': channel, 'sender': user['name'], 'type': 'file',
           'filename': filename, 'url': url, 'size': size, 'timestamp': _now()}
    history = message_history.setdefault(channel, [])
    history.append(msg)
    if len(history) > MAX_HISTORY: history.pop(0)
    emit('new_message', msg, broadcast=True); save_data()


@socketio.on('clear_channel')
def on_clear_channel(data):
    sid = request.sid
    if sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    channel = data.get('channel')
    if channel not in CHANNELS: return
    message_history[channel].clear()
    emit('channel_cleared', {'channel': channel}, to=channel)
    emit('new_message', _add_message(channel, 'systeem', f'Berichten gewist door {connected_users[sid]["name"]}', 'system'), to=channel)
    save_data()


@socketio.on('create_channel')
def on_create_channel(data):
    if request.sid not in connected_users: return
    if not can_edit_channels(data.get('token', '')):
        emit('error', {'message': 'Geen rechten om kanalen aan te maken'}); return
    name = (data.get('name') or '').strip().lower()
    if not re.match(r'^[a-z0-9\-]{2,20}$', name) or name in CHANNELS: return
    CHANNELS.append(name); message_history[name] = []; save_data()
    emit('channel_list', {'channels': CHANNELS, 'topics': CHANNEL_TOPICS,
                          'project': ACTIVE_PROJECT, 'config': _client_config()}, broadcast=True)


@socketio.on('rename_channel')
def on_rename_channel(data):
    if request.sid not in connected_users: return
    if not can_edit_channels(data.get('token', '')):
        emit('error', {'message': 'Geen rechten om kanalen te hernoemen'}); return
    old = data.get('old', ''); new = (data.get('new') or '').strip().lower()
    if not re.match(r'^[a-z0-9\-]{2,20}$', new): return
    if old not in CHANNELS or old == 'algemeen' or old == new or new in CHANNELS: return
    idx = CHANNELS.index(old); CHANNELS[idx] = new
    message_history[new] = message_history.pop(old)
    if old in CHANNEL_TOPICS: CHANNEL_TOPICS[new] = CHANNEL_TOPICS.pop(old)
    if old in call_participants: call_participants[new] = call_participants.pop(old)
    for user in connected_users.values():
        if user['channel'] == old: user['channel'] = new
    save_data()
    emit('channel_renamed', {'old': old, 'new': new}, broadcast=True)
    emit('channel_list', {'channels': CHANNELS, 'topics': CHANNEL_TOPICS,
                          'project': ACTIVE_PROJECT, 'config': _client_config()}, broadcast=True)


@socketio.on('delete_channel')
def on_delete_channel(data):
    if request.sid not in connected_users: return
    if not can_edit_channels(data.get('token', '')):
        emit('error', {'message': 'Geen rechten om kanalen te verwijderen'}); return
    channel = data.get('channel')
    if channel not in CHANNELS or channel == 'algemeen' or len(CHANNELS) <= 1: return
    call_participants.pop(channel, None); CHANNEL_TOPICS.pop(channel, None)
    for user in connected_users.values():
        if user['channel'] == channel: user['channel'] = 'algemeen'
    CHANNELS.remove(channel); del message_history[channel]; save_data()
    emit('channel_deleted', {'channel': channel, 'fallback': 'algemeen'}, broadcast=True)
    emit('channel_list', {'channels': CHANNELS, 'topics': CHANNEL_TOPICS,
                          'project': ACTIVE_PROJECT, 'config': _client_config()}, broadcast=True)


@socketio.on('set_channel_topic')
def on_set_channel_topic(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    channel = data.get('channel', ''); topic = (data.get('topic') or '').strip()
    if channel not in CHANNELS: return
    CHANNEL_TOPICS[channel] = topic; save_data()
    emit('channel_topic_updated', {'channel': channel, 'topic': topic}, broadcast=True)


@socketio.on('rename')
def on_rename(data):
    sid = request.sid
    if sid not in connected_users: return
    new_name = (data.get('name') or '').strip()
    if not new_name: return
    old_name = connected_users[sid]['name']
    if old_name == new_name: return
    existing = _resolve_username_key(new_name)
    if existing and existing != old_name:
        emit('error', {'message': 'Die naam is al in gebruik door een geregistreerde gebruiker'}); return
    connected_users[sid]['name'] = new_name
    channel = connected_users[sid]['channel']
    if channel in call_participants and sid in call_participants[channel]:
        call_participants[channel][sid] = new_name; _broadcast_call_state(channel)
    emit('new_message', _add_message(channel, 'systeem', f'{old_name} heet nu {new_name}', 'system'), to=channel)
    emit('user_list', {'users': _user_list()}, broadcast=True)


@socketio.on('get_users')
def on_get_users(data):
    if request.sid not in connected_users: return
    online = set(_user_list())
    emit('users_list', {'users': [
        {'username': u, 'online': u in online,
         'is_admin': d.get('is_admin', False) if isinstance(d, dict) else False}
        for u, d in USERS.items()
    ]})


@socketio.on('delete_user')
def on_delete_user(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    requested = data.get('username', '')
    username = _resolve_username_key(requested)
    if not username or username not in USERS: return
    admins = [u for u, d in USERS.items() if isinstance(d, dict) and d.get('is_admin')]
    if username in admins and len(admins) == 1:
        emit('error', {'message': 'Kan de laatste beheerder niet verwijderen'}); return
    del USERS[username]; save_users()
    for tok in [t for t, u in SESSIONS.items() if u == username]: del SESSIONS[tok]
    for sid, user in list(connected_users.items()):
        if user['name'] == username:
            emit('kicked', {'message': 'Je account is verwijderd door een beheerder'}, to=sid)
            _remove_from_call(sid); connected_users.pop(sid, None)
    emit('user_deleted', {'username': username}, broadcast=True)
    emit('user_list', {'users': _user_list()}, broadcast=True)


@socketio.on('set_user_admin')
def on_set_user_admin(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    username = _resolve_username_key(data.get('username', ''))
    make_admin = bool(data.get('is_admin', False))
    if username not in USERS: return
    if not make_admin:
        admins = [u for u, d in USERS.items() if isinstance(d, dict) and d.get('is_admin')]
        if username in admins and len(admins) == 1:
            emit('error', {'message': 'Kan de laatste beheerder niet degraderen'}); return
    if isinstance(USERS[username], dict): USERS[username]['is_admin'] = make_admin
    save_users()
    emit('user_admin_updated', {'username': username, 'is_admin': make_admin}, broadcast=True)


@socketio.on('reset_app')
def on_reset_app(data):
    sid = request.sid
    if sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    CHANNELS.clear(); CHANNELS.extend(DEFAULT_CHANNELS)
    message_history.clear()
    for ch in DEFAULT_CHANNELS: message_history[ch] = []
    CHANNEL_TOPICS.clear(); save_data()
    USERS.clear(); save_users(); SESSIONS.clear(); call_participants.clear()
    emit('app_reset', {'channels': DEFAULT_CHANNELS}, broadcast=True)


@socketio.on('logout')
def on_logout(data):
    sid = request.sid; token = data.get('token')
    if token in SESSIONS: del SESSIONS[token]
    _remove_from_call(sid)
    if sid in connected_users:
        user = connected_users.pop(sid); channel = user['channel']
        emit('new_message', _add_message(channel, 'systeem', f'{user["name"]} heeft de chat verlaten', 'system'), to=channel)
        emit('user_list', {'users': _user_list()}, broadcast=True)


@socketio.on('request_history')
def on_request_history(data):
    channel = data.get('channel')
    if channel not in CHANNELS: return
    emit('channel_history', {'channel': channel, 'messages': message_history.get(channel, []),
                             'topic': CHANNEL_TOPICS.get(channel, '')})


@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid; _remove_from_call(sid)
    if sid not in connected_users: return
    user = connected_users.pop(sid); channel = user['channel']
    emit('new_message', _add_message(channel, 'systeem', f'{user["name"]} heeft de chat verlaten', 'system'), to=channel)
    emit('user_list', {'users': _user_list()}, broadcast=True)


# ── Admin data ──

@socketio.on('get_admin_data')
def on_get_admin_data(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    online = set(_user_list())
    emit('admin_data', {
        'projects': _project_names(), 'active_project': ACTIVE_PROJECT,
        'users': [{'username': u, 'online': u in online,
                   'is_admin': d.get('is_admin', False) if isinstance(d, dict) else False}
                  for u, d in USERS.items()],
        'channels': CHANNELS, 'topics': CHANNEL_TOPICS,
        'uptime': int(time.time() - START_TIME), 'server_ip': _get_server_ip(),
        'config': PROJECT_CONFIG, 'storage': _build_storage_list()
    })


@socketio.on('update_settings')
def on_update_settings(data):
    global PROJECT_CONFIG
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    next_cfg = dict(PROJECT_CONFIG)
    if 'max_file_size_mb'       in data: next_cfg['max_file_size_mb']       = data['max_file_size_mb']
    if 'allowed_extensions'     in data: next_cfg['allowed_extensions']     = data['allowed_extensions']
    if 'language'               in data: next_cfg['language']               = data['language']
    if 'timezone'               in data: next_cfg['timezone']               = data['timezone']
    if 'allow_all_channel_edit' in data: next_cfg['allow_all_channel_edit'] = data['allow_all_channel_edit']
    if 'allow_registration'     in data: next_cfg['allow_registration']     = data['allow_registration']
    if 'allow_all_countdown'    in data: next_cfg['allow_all_countdown']    = data['allow_all_countdown']
    PROJECT_CONFIG = _coerce_project_config(next_cfg)
    save_project_settings(ACTIVE_PROJECT)
    emit('settings_updated', {'config': PROJECT_CONFIG, 'client_config': _client_config()}, broadcast=True)


# ── Projects ──

@socketio.on('create_project')
def on_create_project(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = (data.get('name') or '').strip().lower()
    if not re.match(r'^[a-z0-9_\-]{2,40}$', name):
        emit('error', {'message': 'Ongeldige projectnaam (a-z, 0-9, _, -)'}); return
    pdir = os.path.join(PROJECTS_DIR, name)
    if os.path.exists(pdir): emit('error', {'message': 'Project bestaat al'}); return
    os.makedirs(os.path.join(pdir, 'uploads'), exist_ok=True)
    with open(os.path.join(pdir, 'data.json'), 'w') as f:
        json.dump({'channels': list(DEFAULT_CHANNELS), 'topics': {}, 'history': {}}, f)
    with open(os.path.join(pdir, 'users.json'), 'w') as f: json.dump({}, f)
    with open(os.path.join(pdir, 'settings.json'), 'w') as f:
        json.dump(_coerce_project_config(PROJECT_CONFIG), f, indent=2)
    emit('project_created', {'name': name, 'projects': _project_names()}, broadcast=True)


@socketio.on('duplicate_project')
def on_duplicate_project(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    source = data.get('source', ''); dest = (data.get('dest') or '').strip().lower()
    if not re.match(r'^[a-z0-9_\-]{2,40}$', dest):
        emit('error', {'message': 'Ongeldige projectnaam'}); return
    src_path = os.path.join(PROJECTS_DIR, source); dest_path = os.path.join(PROJECTS_DIR, dest)
    if not os.path.exists(src_path): emit('error', {'message': 'Bronproject niet gevonden'}); return
    if os.path.exists(dest_path): emit('error', {'message': 'Doelproject bestaat al'}); return
    shutil.copytree(src_path, dest_path)
    settings_path = os.path.join(dest_path, 'settings.json')
    if not os.path.exists(settings_path):
        with open(settings_path, 'w') as f:
            json.dump(_coerce_project_config(PROJECT_CONFIG), f, indent=2)
    emit('project_created', {'name': dest, 'projects': _project_names()}, broadcast=True)


@socketio.on('delete_project')
def on_delete_project(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = data.get('name', '')
    if name == ACTIVE_PROJECT: emit('error', {'message': 'Actief project kan niet worden verwijderd'}); return
    if name == 'default': emit('error', {'message': 'Standaardproject kan niet worden verwijderd'}); return
    pdir = os.path.join(PROJECTS_DIR, name)
    if not os.path.exists(pdir): emit('error', {'message': 'Project niet gevonden'}); return
    shutil.rmtree(pdir)
    emit('project_deleted', {'name': name, 'projects': _project_names()}, broadcast=True)


@socketio.on('switch_project')
def on_switch_project(data):
    global ACTIVE_PROJECT
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = data.get('name', '')
    if name == ACTIVE_PROJECT: return
    if not os.path.exists(os.path.join(PROJECTS_DIR, name)):
        emit('error', {'message': 'Project niet gevonden'}); return
    save_data(); save_users()
    ACTIVE_PROJECT = name; APP_CONFIG['active_project'] = name; save_config()
    load_project(name)
    emit('project_switched', {'name': name}, broadcast=True)


# ── Storage ──

@socketio.on('get_storage_info')
def on_get_storage_info(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    emit('storage_info', {'storage': _build_storage_list()})


@socketio.on('clear_project_history')
def on_clear_project_history(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = data.get('project', ACTIVE_PROJECT)
    pdir = os.path.join(PROJECTS_DIR, name)
    if not os.path.exists(pdir): emit('error', {'message': 'Project niet gevonden'}); return
    data_path = os.path.join(pdir, 'data.json')
    if os.path.exists(data_path):
        try:
            with open(data_path) as f: pdata = json.load(f)
            pdata['history'] = {}
            with open(data_path, 'w') as f: json.dump(pdata, f)
        except Exception as e: emit('error', {'message': str(e)}); return
    if name == ACTIVE_PROJECT:
        for ch in CHANNELS: message_history[ch] = []
        emit('channel_cleared', {'channel': '__all__'}, broadcast=True)
    emit('storage_info', {'storage': _build_storage_list()})


@socketio.on('clear_project_uploads')
def on_clear_project_uploads(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = data.get('project', ACTIVE_PROJECT)
    uploads_path = os.path.join(PROJECTS_DIR, name, 'uploads')
    if not os.path.exists(os.path.join(PROJECTS_DIR, name)):
        emit('error', {'message': 'Project niet gevonden'}); return
    if os.path.exists(uploads_path): shutil.rmtree(uploads_path)
    os.makedirs(uploads_path, exist_ok=True)
    emit('storage_info', {'storage': _build_storage_list()})


@socketio.on('clear_project_all')
def on_clear_project_all(data):
    if request.sid not in connected_users: return
    if not require_admin(data.get('token', '')):
        emit('error', {'message': 'Geen beheerdersrechten'}); return
    name = data.get('project', ACTIVE_PROJECT)
    pdir = os.path.join(PROJECTS_DIR, name)
    if not os.path.exists(pdir): emit('error', {'message': 'Project niet gevonden'}); return
    # Clear chat
    data_path = os.path.join(pdir, 'data.json')
    if os.path.exists(data_path):
        try:
            with open(data_path) as f: pdata = json.load(f)
            pdata['history'] = {}
            with open(data_path, 'w') as f: json.dump(pdata, f)
        except Exception as e: emit('error', {'message': str(e)}); return
    # Clear uploads
    uploads_path = os.path.join(pdir, 'uploads')
    if os.path.exists(uploads_path): shutil.rmtree(uploads_path)
    os.makedirs(uploads_path, exist_ok=True)
    if name == ACTIVE_PROJECT:
        for ch in CHANNELS: message_history[ch] = []
        emit('channel_cleared', {'channel': '__all__'}, broadcast=True)
    emit('storage_info', {'storage': _build_storage_list()})


# ── Countdown ──

@socketio.on('start_countdown')
def on_start_countdown(data):
    global _countdown_timer, _countdown_end_time
    if request.sid not in connected_users: return
    if not can_control_countdown(data.get('token', '')):
        emit('error', {'message': 'Geen rechten om timer te starten'}); return
    seconds = int(data.get('seconds', 60)); label = str(data.get('label', ''))
    if seconds <= 0 or seconds > 86400:
        emit('error', {'message': 'Ongeldige tijdsduur'}); return
    if _countdown_timer: _countdown_timer.cancel()
    _countdown_end_time = time.time() + seconds

    def on_expire():
        global _countdown_end_time
        _countdown_end_time = 0.0
        socketio.emit('countdown_expired', {})

    _countdown_timer = threading.Timer(seconds, on_expire)
    _countdown_timer.daemon = True
    _countdown_timer.start()
    emit('countdown_started', {'end_time': _countdown_end_time, 'seconds': seconds, 'label': label}, broadcast=True)


@socketio.on('stop_countdown')
def on_stop_countdown(data):
    global _countdown_timer, _countdown_end_time
    if request.sid not in connected_users: return
    if not can_control_countdown(data.get('token', '')):
        emit('error', {'message': 'Geen rechten om timer te stoppen'}); return
    if _countdown_timer: _countdown_timer.cancel(); _countdown_timer = None
    _countdown_end_time = 0.0
    emit('countdown_stopped', {}, broadcast=True)


# ── WebRTC ──

@socketio.on('call_join')
def on_call_join(data):
    sid = request.sid
    if sid not in connected_users: return
    channel = connected_users[sid]['channel']
    if channel not in call_participants: call_participants[channel] = {}
    existing = [{'sid': s, 'name': n} for s, n in call_participants[channel].items()]
    call_participants[channel][sid] = connected_users[sid]['name']
    emit('call_joined', {'peers': existing}); _broadcast_call_state(channel)

@socketio.on('call_leave')
def on_call_leave(data): _remove_from_call(request.sid)

@socketio.on('call_offer')
def on_call_offer(data): emit('call_offer', {'from': request.sid, 'sdp': data.get('sdp')}, to=data.get('target'))

@socketio.on('call_answer')
def on_call_answer(data): emit('call_answer', {'from': request.sid, 'sdp': data.get('sdp')}, to=data.get('target'))

@socketio.on('call_ice')
def on_call_ice(data): emit('call_ice', {'from': request.sid, 'candidate': data.get('candidate')}, to=data.get('target'))


if __name__ == '__main__':
    generate_ssl_cert()
    PUBLIC_PORT = _coerce_port(APP_CONFIG.get('port', 5001))
    HTTPS_BACKEND_PORT = PUBLIC_PORT + 1 if PUBLIC_PORT < 65535 else 65534
    if HTTPS_BACKEND_PORT == PUBLIC_PORT:
        HTTPS_BACKEND_PORT = 5443
    mux_thread = threading.Thread(
        target=_serve_http_https_mux,
        args=('0.0.0.0', PUBLIC_PORT, HTTPS_BACKEND_PORT),
        daemon=True,
    )
    mux_thread.start()
    socketio.run(app, host='127.0.0.1', port=HTTPS_BACKEND_PORT, debug=False,
                 allow_unsafe_werkzeug=True, ssl_context=(CERT_FILE, KEY_FILE))

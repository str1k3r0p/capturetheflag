import os
import sqlite3
import base64
import multiprocessing
import time
import jwt
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template, send_from_directory, Blueprint, make_response, Response, redirect, url_for, abort
from scapy.all import IP, TCP, Raw, wrpcap
from werkzeug.serving import run_simple

# --- Configuration ---
ADMIN_PASSWORD = "teacher_password"
JWT_SECRET = "a_very_secret_key_for_jwt" # Change this for a real event

# --- Challenge Definitions (Central Truth) ---
# UPDATED: Total of 10 challenges with creative names.
CHALLENGES_CONFIG = {
    'web1': {'name': 'The Snack Cabinet', 'points': 100, 'port': 5001, 'flag': 'flag{c00k1e_m0nst3r_!s_h3r3}'},
    'web2': {'name': 'Restricted Area', 'points': 200, 'port': 5002, 'flag': 'flag{r0b0ts_c4nt_k33p_s3cr3ts}'},
    'net1': {'name': 'The Messenger', 'points': 300, 'flag': 'flag{ftp_!s_s0_!ns3cur3}'},
    'web3': {'name': 'The VIP Lounge', 'points': 400, 'port': 5003, 'flag': 'flag{w3lc0m3_adm1n_y0u_h4v3_b33n_pwn3d}'},
    'net2': {'name': 'Whispers in the Wire', 'points': 500, 'flag': 'flag{t3ln3t_chatt3r_b0x}'},
    # 5 NEW Intermediate Web Challenges
    'web4': {'name': 'Local Traffic Only', 'points': 250, 'port': 5004, 'flag': 'flag{x_f0rw4rd3d_f0r_th3_w1n}'},
    'web5': {'name': 'The Golden Ticket', 'points': 350, 'port': 5005, 'flag': 'flag{jwt_t0k3n_c4n_b3_tr1cky}'},
    'web6': {'name': 'Forgotten Files', 'points': 450, 'port': 5006, 'flag': 'flag{n0t_4ll_f1l3s_4r3_l1nk3d}'},
    'web7': {'name': 'The Reading Room', 'points': 550, 'port': 5007, 'flag': 'flag{lfi_m4k3s_th3_s3rv3r_s4d}'},
    'web8': {'name': 'The Ping Test', 'points': 600, 'port': 5008, 'flag': 'flag{c0mm4nd_!nj3ct!0n_!s_p0w3rfu1}'},
}

# --- Challenge Server Functions ---
def run_challenge_1(port):
    app = Flask(__name__)
    @app.route('/')
    def challenge():
        response = make_response("<h1>OM NOM NOM</h1><p>I love cookies! This one tastes... weird.</p>")
        response.set_cookie('secret_recipe', base64.b64encode(CHALLENGES_CONFIG['web1']['flag'].encode()).decode())
        return response
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_2(port):
    app = Flask(__name__)
    @app.route('/')
    def index(): return "<h1>Welcome!</h1><p>Our brand new, ultra-secure corporate website.</p>"
    @app.route('/robots.txt')
    def robots(): return Response("User-agent: *\nDisallow: /secret-area/", mimetype='text/plain')
    @app.route('/secret-area/flag.txt')
    def secret(): return Response(f"Congratulations: {CHALLENGES_CONFIG['web2']['flag']}", mimetype='text/plain')
    run_simple('0.0.0.0', port, app, use_reloader=False)
    
def run_challenge_3(port):
    app = Flask(__name__, template_folder='templates')
    db_path = f'challenge3_{port}.db'
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecretpassword123')")
        conn.commit()
        conn.close()
    @app.route('/', methods=['GET', 'POST'])
    def login():
        error=None
        if request.method == 'POST':
            query = f"SELECT * FROM users WHERE username = '{request.form['username']}' AND password = '{request.form['password']}'"
            conn = sqlite3.connect(db_path)
            user = conn.cursor().execute(query).fetchone()
            conn.close()
            if user: return redirect(url_for('dashboard'))
            else: error = 'Invalid Credentials.'
        return render_template('login.html', error=error)
    @app.route('/dashboard')
    def dashboard(): return render_template('dashboard.html', flag=CHALLENGES_CONFIG['web3']['flag'])
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_4(port):
    app = Flask(__name__)
    @app.route('/')
    def index():
        if request.headers.get('X-Forwarded-For') == '127.0.0.1':
            return f"<h1>Welcome, Local Admin!</h1><p>Here is your flag: {CHALLENGES_CONFIG['web4']['flag']}</p>"
        return "<h1>Access Denied</h1><p>Only local admins can see this page.</p>"
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_5(port):
    app = Flask(__name__)
    @app.route('/')
    def index():
        token = request.cookies.get('session')
        if token:
            try:
                decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                if decoded.get('user') == 'admin':
                    return f"<h1>Welcome Admin!</h1><p>Your flag is: {CHALLENGES_CONFIG['web5']['flag']}</p>"
                return f"<h1>Welcome {decoded.get('user')}!</h1><p>You are not an admin.</p>"
            except jwt.InvalidTokenError:
                return "<h1>Invalid Token!</h1>"
        
        user_token = jwt.encode({"user": "guest", "iat": datetime.now(timezone.utc)}, JWT_SECRET, algorithm="HS256")
        response = make_response("<h1>Welcome Guest!</h1><p>Only admins can see the flag. Here is your session token.</p>")
        response.set_cookie('session', user_token)
        return response
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_6(port):
    app = Flask(__name__)
    @app.route('/')
    def index(): return '<a href="/main.js">Check out our main script!</a>'
    @app.route('/main.js')
    def main_js(): return "console.log('Main application logic.');"
    @app.route('/main.js.bak')
    def backup_js(): return f"// This is a backup. Flag is {CHALLENGES_CONFIG['web6']['flag']}"
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_7(port):
    app = Flask(__name__)
    @app.route('/')
    def index():
        page = request.args.get('page', 'index.html')
        try:
            safe_path = os.path.join('challenge7_files', os.path.basename(page))
            with open(safe_path, 'r') as f:
                return f.read()
        except (IOError, FileNotFoundError):
            return "File not found."
    run_simple('0.0.0.0', port, app, use_reloader=False)

def run_challenge_8(port):
    app = Flask(__name__)
    @app.route('/', methods=['GET', 'POST'])
    def index():
        output = ""
        if request.method == 'POST':
            ip = request.form.get('ip')
            cmd = f"ping -c 1 {ip}"
            output = os.popen(cmd).read()
        return render_template('ping_test.html', output=output)
    run_simple('0.0.0.0', port, app, use_reloader=False)


# --- Main Application ---
app = Flask(__name__, static_folder='static', template_folder='templates')
challenge_processes = {}

def get_db():
    db = sqlite3.connect('ctf.db', detect_types=sqlite3.PARSE_DECLTYPES)
    db.row_factory = sqlite3.Row
    return db

# --- API Endpoints ---
@app.route('/')
def index_page(): return send_from_directory('static', 'index.html')

@app.route('/api/player', methods=['POST'])
def add_player():
    name = request.json.get('name')
    if not name:
        return jsonify({'success': False, 'message': 'Player name cannot be empty.'}), 400
    db = get_db()
    if db.execute('SELECT * FROM players WHERE name = ?', (name,)).fetchone() is None:
        db.execute('INSERT INTO players (name, score, wrong_submissions_count) VALUES (?, 0, 0)', (name,))
        db.commit()
    db.close()
    return jsonify({'success': True, 'name': name})

@app.route('/api/challenges')
def get_challenges():
    db = get_db()
    states = {row['id']: row['is_unlocked'] for row in db.execute('SELECT id, is_unlocked FROM challenge_states').fetchall()}
    all_challenges_with_state = {}
    for cid, data in CHALLENGES_CONFIG.items():
        all_challenges_with_state[cid] = {
            'title': data['name'],
            'category': 'Web' if 'web' in cid else 'Net',
            'points': data['points'],
            'port': data.get('port'),
            'file': f"/static/{cid.replace('net', 'capture')}.pcapng" if 'net' in cid else None,
            'is_unlocked': states.get(cid, False)
        }
    db.close()
    return jsonify(all_challenges_with_state)

@app.route('/api/submit', methods=['POST'])
def submit_flag():
    data = request.json
    name, cid, flag = data.get('player'), data.get('challenge_id'), data.get('flag')
    
    db = get_db()
    if flag == CHALLENGES_CONFIG[cid]['flag']:
        if db.execute('SELECT * FROM submissions WHERE player_name = ? AND challenge_id = ?', (name, cid)).fetchone():
            return jsonify({'success': True, 'message': 'Already solved!'})
        points = CHALLENGES_CONFIG[cid]['points']
        timestamp = datetime.now(timezone.utc).isoformat()
        db.execute('UPDATE players SET score = score + ? WHERE name = ?', (points, name))
        db.execute('INSERT INTO submissions (player_name, challenge_id, submission_time) VALUES (?, ?, ?)', (name, cid, timestamp))
        db.commit()
        return jsonify({'success': True, 'message': 'Correct Flag!', 'points': points})
    else:
        db.execute('UPDATE players SET wrong_submissions_count = wrong_submissions_count + 1 WHERE name = ?', (name,))
        db.execute('INSERT INTO wrong_submissions (player_name, challenge_id, submitted_flag) VALUES (?, ?, ?)', (name, cid, flag))
        db.commit()
        return jsonify({'success': False, 'message': 'Incorrect Flag.'})

@app.route('/api/solves/<challenge_id>')
def get_solves(challenge_id):
    db = get_db()
    solves = db.execute('SELECT player_name, submission_time FROM submissions WHERE challenge_id = ? ORDER BY submission_time ASC', (challenge_id,)).fetchall()
    db.close()
    return jsonify([{'player': s['player_name'], 'time': s['submission_time']} for s in solves])

@app.route('/api/scoreboard')
def get_scoreboard_data():
    db = get_db()
    query = """
        SELECT
            p.name, p.score, p.wrong_submissions_count,
            (SELECT MAX(s.submission_time) FROM submissions s WHERE s.player_name = p.name) as last_submission_time
        FROM players p ORDER BY p.score DESC, p.wrong_submissions_count ASC, last_submission_time ASC
    """
    players = db.execute(query).fetchall()
    
    all_solves = db.execute('SELECT player_name, challenge_id FROM submissions').fetchall()
    solved_map = {}
    for solve in all_solves:
        if solve['player_name'] not in solved_map:
            solved_map[solve['player_name']] = []
        solved_map[solve['player_name']].append(solve['challenge_id'])

    submissions_for_chart = db.execute('SELECT player_name, challenge_id, submission_time FROM submissions ORDER BY submission_time ASC').fetchall()
    chart_data = {}
    player_scores_at_time = {p['name']: 0 for p in players}

    start_time_iso = datetime.now(timezone.utc).isoformat()
    if submissions_for_chart:
        start_time_iso = submissions_for_chart[0]['submission_time']

    for sub in submissions_for_chart:
        player = sub['player_name']
        points = CHALLENGES_CONFIG[sub['challenge_id']]['points']
        if player not in chart_data:
            chart_data[player] = [{'x': start_time_iso, 'y': 0}]
        player_scores_at_time[player] += points
        chart_data[player].append({'x': sub['submission_time'], 'y': player_scores_at_time[player]})

    for p_row in players:
        p_name = p_row['name']
        if p_name not in chart_data:
            chart_data[p_name] = [{'x': start_time_iso, 'y': 0}]
    
    db.close()
    return jsonify({
        'players': [dict(p) for p in players],
        'solved_map': solved_map,
        'chart_data': chart_data,
        'challenge_info': {cid: {'name': data['name']} for cid, data in CHALLENGES_CONFIG.items()}
    })
    
# --- Admin and Setup ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST' and request.form.get('password') == ADMIN_PASSWORD:
        return render_template('admin.html', challenges=get_db().execute('SELECT * FROM challenge_states').fetchall())
    return '<form method="post"><label>Password: <input type="password" name="password"></label><button>Enter</button></form>'

@app.route('/api/admin/toggle', methods=['POST'])
def toggle_challenge():
    if request.headers.get('Authorization') != ADMIN_PASSWORD: abort(403)
    cid = request.json.get('challenge_id')
    db = get_db()
    state = db.execute('SELECT is_unlocked FROM challenge_states WHERE id = ?', (cid,)).fetchone()
    if state:
        new_state = not state['is_unlocked']
        db.execute('UPDATE challenge_states SET is_unlocked = ? WHERE id = ?', (new_state, cid)).commit()
        db.close()
        if 'web' in cid:
            port = CHALLENGES_CONFIG[cid]['port']
            if new_state and cid not in challenge_processes:
                # FIX: Correctly look up the function to run for the new challenges
                target_func_name = f"run_challenge_{cid.replace('web', '')}"
                target_func = globals().get(target_func_name)
                if target_func:
                    p = multiprocessing.Process(target=target_func, args=(port,))
                    p.start()
                    challenge_processes[cid] = p
                    print(f"[Admin] Started {cid} on port {port}")
            elif not new_state and cid in challenge_processes:
                challenge_processes[cid].terminate()
                challenge_processes.pop(cid)
                print(f"[Admin] Stopped {cid}")
        return jsonify({'success': True, 'is_unlocked': new_state})
    db.close()
    return jsonify({'success': False})

def initial_setup():
    print("[INFO] Performing initial setup...")
    os.makedirs('static', exist_ok=True)
    os.makedirs('challenge7_files', exist_ok=True)
    with open('challenge7_files/index.html', 'w') as f: f.write('<h1>Homepage</h1><p>Check out our <a href="?page=news.txt">news</a>!</p>')
    with open('challenge7_files/news.txt', 'w') as f: f.write('No news today.')
    with open('challenge7_files/config.ini.bak', 'w') as f: f.write(f"[secrets]\nflag = {CHALLENGES_CONFIG['web7']['flag']}")
    os.makedirs('templates', exist_ok=True)
    with open(os.path.join('templates', 'ping_test.html'), 'w') as f: f.write('<!DOCTYPE html><html><body><form method="post">IP to ping: <input type="text" name="ip"><button>Ping</button></form><pre>{{ output }}</pre></body></html>')
    with open(os.path.join('templates', 'login.html'), 'w') as f: f.write('<!DOCTYPE html><html><body><form method="post">Username:<input name="username"><br>Password:<input name="password" type="password"><button>Login</button></form><p style="color:red;">{{error}}</p></body></html>')
    with open(os.path.join('templates', 'dashboard.html'), 'w') as f: f.write('<!DOCTYPE html><html><body><h1>Welcome Admin!</h1><p>Flag: {{flag}}</p></body></html>')
    with open(os.path.join('templates', 'admin.html'), 'w') as f: f.write('<!DOCTYPE html><html><head><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-gray-800 text-white p-10"><h1 class="text-3xl font-bold mb-6">Admin Controls</h1><div id="challenge-controls" class="space-y-4">{% for challenge in challenges %}<div class="bg-gray-700 p-4 rounded-lg flex justify-between items-center"><span class="text-xl">{{ challenge.id }}</span><button onclick="toggleChallenge(\'{{ challenge.id }}\')" id="btn-{{ challenge.id }}" class="px-4 py-2 rounded font-semibold {{ \'bg-red-600 hover:bg-red-700\' if challenge.is_unlocked else \'bg-green-600 hover:bg-green-700\' }}">{{ \'Lock\' if challenge.is_unlocked else \'Unlock\' }}</button></div>{% endfor %}</div><script>async function toggleChallenge(id){const res=await fetch("/api/admin/toggle",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"teacher_password"},body:JSON.stringify({challenge_id:id})});const data=await res.json();if(data.success){const btn=document.getElementById(`btn-${id}`);btn.textContent=data.is_unlocked?"Lock":"Unlock";btn.className=`px-4 py-2 rounded font-semibold ${data.is_unlocked?"bg-red-600 hover:bg-red-700":"bg-green-600 hover:bg-green-700"}`}}</script></body></html>')

    db = sqlite3.connect('ctf.db')
    db.execute('CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY, name TEXT UNIQUE, score INTEGER, wrong_submissions_count INTEGER DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, player_name TEXT, challenge_id TEXT, submission_time TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS wrong_submissions (id INTEGER PRIMARY KEY, player_name TEXT, challenge_id TEXT, submitted_flag TEXT, submission_time TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS challenge_states (id TEXT PRIMARY KEY, is_unlocked BOOLEAN)')
    
    try:
        db.execute('ALTER TABLE players ADD COLUMN wrong_submissions_count INTEGER DEFAULT 0')
    except sqlite3.OperationalError: pass
    for cid in CHALLENGES_CONFIG:
        db.execute('INSERT OR IGNORE INTO challenge_states (id, is_unlocked) VALUES (?, ?)', (cid, False))
    db.execute('UPDATE challenge_states SET is_unlocked = ? WHERE id = ?', (True, 'web1'))
    db.commit()
    db.close()
    wrpcap('static/capture1.pcapng', [IP()/TCP(dport=21)/Raw(load=f"PASS {CHALLENGES_CONFIG['net1']['flag']}\r\n")])
    wrpcap('static/capture2.pcapng', [IP()/TCP()/Raw(load=p) for p in ["flag{t3l", "n3t_cha", "tt3r_b0x}"]])
    print("[INFO] Setup complete.")

if __name__ == '__main__':
    multiprocessing.freeze_support()
    initial_setup()
    p = multiprocessing.Process(target=run_challenge_1, args=(CHALLENGES_CONFIG['web1']['port'],))
    p.start()
    challenge_processes['web1'] = p
    print("\n[INFO] CTF Platform is running!")
    print(f"  Admin Panel: http://127.0.0.1:5000/admin (PW: {ADMIN_PASSWORD})")
    print("  Student Dashboard: http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

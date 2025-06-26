import os
import sqlite3
import base64
import multiprocessing
import time
from flask import Flask, jsonify, request, render_template, send_from_directory, Blueprint, make_response, Response, redirect, url_for, abort
from scapy.all import IP, TCP, Raw, wrpcap
from werkzeug.serving import run_simple

# --- Configuration ---
ADMIN_PASSWORD = "teacher_password" 

# --- Challenge Definitions (Central Truth) ---
CHALLENGES_CONFIG = {
    'web1': {'name': 'Cookie Monster', 'points': 100, 'port': 5001, 'flag': 'flag{c00k1e_m0nst3r_!s_h3r3}'},
    'web2': {'name': 'Robots on Parade', 'points': 200, 'port': 5002, 'flag': 'flag{r0b0ts_c4nt_k33p_s3cr3ts}'},
    'net1': {'name': 'Plain Sight', 'points': 300, 'flag': 'flag{ftp_!s_s0_!ns3cur3}'},
    'web3': {'name': 'Login Bypass', 'points': 400, 'port': 5003, 'flag': 'flag{w3lc0m3_adm1n_y0u_h4v3_b33n_pwn3d}'},
    'net2': {'name': 'Hidden Conversation', 'points': 500, 'flag': 'flag{t3ln3t_chatt3r_b0x}'},
}
# --- Challenge Server Functions (to be run in separate processes) ---

def run_challenge_1(port):
    app = Flask(__name__)
    @app.route('/')
    def challenge():
        flag = CHALLENGES_CONFIG['web1']['flag']
        encoded_flag = base64.b64encode(flag.encode()).decode()
        html_content = """<!DOCTYPE html><html lang="en"><head><title>Cookie Monster</title><link href="https://fonts.googleapis.com/css2?family=VT323&display=swap" rel="stylesheet"><style>body{background-color:#1a202c;color:#a0aec0;font-family:'VT323',monospace;text-align:center;padding:100px;}h1{color:#48bb78;font-size:4rem;}</style></head><body><h1>OM NOM NOM</h1><p>I love cookies! This one tastes... weird.</p></body></html>"""
        response = make_response(html_content)
        response.set_cookie('secret_recipe', encoded_flag)
        return response
    run_simple('0.0.0.0', port, app)

def run_challenge_2(port):
    app = Flask(__name__)
    @app.route('/')
    def index(): return """<!DOCTYPE html><html lang="en"><head><title>Corporate Site</title><link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet"><style>body{background-color:#f7fafc;color:#2d3748;font-family:'Roboto',sans-serif;text-align:center;padding:100px;}h1{font-size:3rem;}</style></head><body><h1>Welcome!</h1><p>Our brand new, ultra-secure corporate website.</p></body></html>"""
    @app.route('/robots.txt')
    def robots(): return Response("User-agent: *\nDisallow: /secret-area/", mimetype='text/plain')
    @app.route('/secret-area/flag.txt')
    def secret(): return Response(f"Congratulations: {CHALLENGES_CONFIG['web2']['flag']}", mimetype='text/plain')
    run_simple('0.0.0.0', port, app)
    
def run_challenge_3(port):
    # This function contains the corrected code for the SQL Injection challenge.
    app = Flask(__name__, template_folder='templates')
    db_path = f'challenge3_{port}.db'
    
    # Setup its own db on first run to avoid conflicts
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
        conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecretpassword123')")
        conn.commit()
        conn.close()
    
    @app.route('/', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            username = request.form['username']
            # Note: password is intentionally not used in the vulnerable query
            
            conn = sqlite3.connect(db_path)
            
            # THE CORRECTED VULNERABLE QUERY
            # This query is simplified to make the injection reliable.
            # It only checks the username field, making the bypass more direct.
            query = f"SELECT * FROM users WHERE username = '{username}'"
            
            try:
                # The injection here can force the query to return a user regardless of the WHERE clause.
                user = conn.cursor().execute(query).fetchone()
            except sqlite3.Error as e:
                print(f"SQL Error on challenge 3: {e}") 
                user = None

            conn.close()
            
            # If the injected query successfully returns ANY user, login succeeds.
            if user: 
                return redirect(url_for('dashboard'))
            else: 
                error = 'Invalid Credentials.'
        return render_template('login.html', error=error)

    @app.route('/dashboard')
    def dashboard(): return render_template('dashboard.html', flag=CHALLENGES_CONFIG['web3']['flag'])
    
    run_simple('0.0.0.0', port, app)

# --- Main Flask App (Dashboard & APIs) ---
app = Flask(__name__, static_folder='static', template_folder='templates')
challenge_processes = {}

# --- Database Helpers ---
def get_db():
    db = sqlite3.connect('ctf.db')
    db.row_factory = sqlite3.Row
    return db

# --- Admin Routes ---
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            db = get_db()
            challenges = db.execute('SELECT * FROM challenge_states').fetchall()
            return render_template('admin.html', challenges=challenges)
    return '<form method="post"><label>Password: <input type="password" name="password"></label><button>Enter</button></form>'

@app.route('/api/admin/toggle', methods=['POST'])
def toggle_challenge():
    if request.headers.get('Authorization') != ADMIN_PASSWORD:
        abort(403)
        
    challenge_id = request.json.get('challenge_id')
    db = get_db()
    current_state = db.execute('SELECT is_unlocked FROM challenge_states WHERE id = ?', (challenge_id,)).fetchone()
    if current_state:
        new_state = not current_state['is_unlocked']
        db.execute('UPDATE challenge_states SET is_unlocked = ? WHERE id = ?', (new_state, challenge_id))
        db.commit()
        
        if 'web' in challenge_id:
            port = CHALLENGES_CONFIG[challenge_id]['port']
            if new_state and challenge_id not in challenge_processes:
                target_func = globals()[f"run_challenge_{challenge_id.replace('web', '')}"]
                p = multiprocessing.Process(target=target_func, args=(port,))
                p.start()
                challenge_processes[challenge_id] = p
                print(f"[Admin] Started challenge '{challenge_id}' on port {port}")
            elif not new_state and challenge_id in challenge_processes:
                challenge_processes[challenge_id].terminate()
                challenge_processes.pop(challenge_id)
                print(f"[Admin] Stopped challenge '{challenge_id}'")

        return jsonify({'success': True, 'is_unlocked': new_state})
    return jsonify({'success': False})


# --- Student-Facing API Routes ---
@app.route('/')
def index(): return send_from_directory('static', 'index.html')

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
        
    return jsonify(all_challenges_with_state)


@app.route('/api/player', methods=['POST'])
def add_player():
    name = request.json.get('name')
    if not name: return jsonify({'success': False}), 400
    db = get_db()
    if db.execute('SELECT * FROM players WHERE name = ?', (name,)).fetchone() is None:
        db.execute('INSERT INTO players (name, score) VALUES (?, 0)', (name,))
        db.commit()
    return jsonify({'success': True, 'name': name})

@app.route('/api/submit', methods=['POST'])
def submit_flag():
    data = request.json
    name, cid, flag = data.get('player'), data.get('challenge_id'), data.get('flag')
    
    if not all([name, cid, flag]) or cid not in CHALLENGES_CONFIG or flag != CHALLENGES_CONFIG[cid]['flag']:
        return jsonify({'success': False, 'message': 'Incorrect Flag.'})
    
    db = get_db()
    if db.execute('SELECT * FROM submissions WHERE player_name = ? AND challenge_id = ?', (name, cid)).fetchone():
        return jsonify({'success': True, 'message': 'Already solved!'})
    
    points = CHALLENGES_CONFIG[cid]['points']
    db.execute('UPDATE players SET score = score + ? WHERE name = ?', (points, name))
    db.execute('INSERT INTO submissions (player_name, challenge_id) VALUES (?, ?)', (name, cid))
    db.commit()
    return jsonify({'success': True, 'message': 'Correct Flag!', 'points': points})

@app.route('/api/scoreboard')
def get_scoreboard():
    db = get_db()
    players = db.execute('SELECT name, score FROM players ORDER BY score DESC').fetchall()
    player_name = request.args.get('player')
    solved = [r['challenge_id'] for r in db.execute('SELECT challenge_id FROM submissions WHERE player_name = ?', (player_name or '',)).fetchall()]
    return jsonify({
        'players': [dict(p) for p in players],
        'solved_challenges': solved
    })

# --- Initial Setup ---
def initial_setup():
    print("[INFO] Performing initial setup...")
    os.makedirs('static', exist_ok=True)

    db = sqlite3.connect('ctf.db')
    db.execute('CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY, name TEXT UNIQUE, score INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, player_name TEXT, challenge_id TEXT, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    db.execute('CREATE TABLE IF NOT EXISTS challenge_states (id TEXT PRIMARY KEY, is_unlocked BOOLEAN)')
    
    for cid in CHALLENGES_CONFIG:
        db.execute('INSERT OR IGNORE INTO challenge_states (id, is_unlocked) VALUES (?, ?)', (cid, False))
    
    db.execute('UPDATE challenge_states SET is_unlocked = ? WHERE id = ?', (True, 'web1'))
    db.commit()
    db.close()
    
    wrpcap('static/capture1.pcapng', [IP(dst="10.0.0.2")/TCP(sport=1025, dport=21)/Raw(load=f"PASS {CHALLENGES_CONFIG['net1']['flag']}\r\n")])
    wrpcap('static/capture2.pcapng', [IP()/TCP()/Raw(load=p) for p in ["flag{t3l", "n3t_cha", "tt3r_b0x}"]])
    print("[INFO] Setup complete. The first challenge 'web1' is unlocked by default.")


if __name__ == '__main__':
    initial_setup()
    
    p = multiprocessing.Process(target=run_challenge_1, args=(CHALLENGES_CONFIG['web1']['port'],))
    p.start()
    challenge_processes['web1'] = p
    
    print("\n============================================================")
    print("  CTF Platform is running!")
    print(f"  Admin Panel: http://127.0.0.1:5000/admin (PW: {ADMIN_PASSWORD})")
    print("  Student Dashboard: http://127.0.0.1:5000")
    print("============================================================\n")
    
    app.run(host='0.0.0.0', port=5000)

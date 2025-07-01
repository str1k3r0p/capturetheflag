# database.py
import os
import sqlite3
from scapy.all import IP, TCP, Raw, wrpcap

# This configuration must match the one in app.py
CHALLENGES_CONFIG = {
    'web1': {'name': 'The Snack Cabinet', 'points': 100, 'port': 5001, 'flag': 'flag{c00k1e_m0nst3r_!s_h3r3}'},
    'web2': {'name': 'Restricted Area', 'points': 200, 'port': 5002, 'flag': 'flag{r0b0ts_c4nt_k33p_s3cr3ts}'},
    'net1': {'name': 'The Messenger', 'points': 300, 'flag': 'flag{ftp_!s_s0_!ns3cur3}'},
    'web3': {'name': 'The VIP Lounge', 'points': 400, 'port': 5003, 'flag': 'flag{w3lc0m3_adm1n_y0u_h4v3_b33n_pwn3d}'},
    'net2': {'name': 'Whispers in the Wire', 'points': 500, 'flag': 'flag{t3ln3t_chatt3r_b0x}'},
    'web4': {'name': 'Local Traffic Only', 'points': 250, 'port': 5004, 'flag': 'flag{x_f0rw4rd3d_f0r_th3_w1n}'},
    'web5': {'name': 'The Golden Ticket', 'points': 350, 'port': 5005, 'flag': 'flag{jwt_t0k3n_c4n_b3_tr1cky}'},
    'web6': {'name': 'Forgotten Files', 'points': 450, 'port': 5006, 'flag': 'flag{n0t_4ll_f1l3s_4r3_l1nk3d}'},
    'web7': {'name': 'The Reading Room', 'points': 550, 'port': 5007, 'flag': 'flag{lfi_m4k3s_th3_s3rv3r_s4d}'},
    'web8': {'name': 'The Ping Test', 'points': 600, 'port': 5008, 'flag': 'flag{c0mm4nd_!nj3ct!0n_!s_p0w3rfu1}'},
}

def initial_setup():
    print("[INFO] Performing initial setup...")
    os.makedirs('static', exist_ok=True)
    
    # --- Main CTF Database ---
    db = sqlite3.connect('ctf.db')
    db.execute('DROP TABLE IF EXISTS players')
    db.execute('DROP TABLE IF EXISTS submissions')
    db.execute('DROP TABLE IF EXISTS wrong_submissions')
    db.execute('DROP TABLE IF EXISTS challenge_states')
    
    db.execute('CREATE TABLE players (id INTEGER PRIMARY KEY, name TEXT UNIQUE, score INTEGER, wrong_submissions_count INTEGER DEFAULT 0)')
    db.execute('CREATE TABLE submissions (id INTEGER PRIMARY KEY, player_name TEXT, challenge_id TEXT, submission_time TEXT)')
    db.execute('CREATE TABLE wrong_submissions (id INTEGER PRIMARY KEY, player_name TEXT, challenge_id TEXT, submitted_flag TEXT, submission_time TEXT)')
    db.execute('CREATE TABLE challenge_states (id TEXT PRIMARY KEY, is_unlocked BOOLEAN)')
    
    for cid in CHALLENGES_CONFIG:
        db.execute('INSERT INTO challenge_states (id, is_unlocked) VALUES (?, ?)', (cid, False))
    
    db.commit()
    db.close()
    
    # --- Challenge-specific Files ---
    os.makedirs('challenge7_files', exist_ok=True)
    with open('challenge7_files/challenge7_index.html', 'w') as f: f.write('<h1>Homepage</h1><p>Check out our <a href="?page=news.txt">news</a>!</p>')
    with open('challenge7_files/news.txt', 'w') as f: f.write('No news today.')
    with open('challenge7_files/config.ini.bak', 'w') as f: f.write(f"[secrets]\nflag = {CHALLENGES_CONFIG['web7']['flag']}")

    # --- Network Capture Files ---
    wrpcap('static/capture1.pcapng', [IP()/TCP(dport=21)/Raw(load=f"PASS {CHALLENGES_CONFIG['net1']['flag']}\r\n")])
    wrpcap('static/capture2.pcapng', [IP()/TCP()/Raw(load=p) for p in ["flag{t3l", "n3t_cha", "tt3r_b0x}"]])

    print("[INFO] Setup complete. All challenges are now LOCKED. Use the admin panel to unlock them.")

if __name__ == '__main__':
    initial_setup()

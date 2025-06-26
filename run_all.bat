@echo off
REM run_all.bat - Starts the main CTF server and all challenge servers.
REM Make sure you are in a Python virtual environment with Flask and Scapy installed.

echo =========================================
echo  Starting CTF Platform Servers
echo =========================================

REM Initialize the database if it's the first time
echo.
echo [INFO] Initializing database...
python database.py

REM Generate the pcap files for wireshark challenges
echo.
echo [INFO] Generating Wireshark challenge files...
python challenges/generate_net1.py
python challenges/generate_net2.py

REM Start each challenge server in a new command prompt window
echo.
echo [INFO] Starting Challenge Servers in separate windows...
start "Challenge 1: Cookie Monster" cmd /k "python challenges/web_challenge_1.py"
start "Challenge 2: Robots on Parade" cmd /k "python challenges/web_challenge_2.py"
start "Challenge 3: Login Bypass" cmd /k "python challenges/web_challenge_3.py"

REM Start the main application in the current window
echo.
echo [INFO] Starting Main CTF Server on http://127.0.0.1:5000
python app.py

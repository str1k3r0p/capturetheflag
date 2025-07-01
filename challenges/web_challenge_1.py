# challenges/web_challenge_1.py
from flask import Flask, make_response, render_template_string
import base64

app = Flask(__name__)

@app.route('/')
def challenge():
    # The flag is base64 encoded to obscure it.
    flag = "flag{c00k1e_m0nst3r_!s_h3r3}"
    encoded_flag = base64.b64encode(flag.encode()).decode()

    # HTML content for the challenge page.
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Cookie Monster</title>
        <link href="https://fonts.googleapis.com/css2?family=VT323&display=swap" rel="stylesheet">
        <style>
            body { background-color: #1a202c; color: #a0aec0; font-family: 'VT323', monospace; text-align: center; padding-top: 100px; }
            h1 { color: #48bb78; font-size: 4rem; }
            p { font-size: 1.5rem; }
        </style>
    </head>
    <body>
        <h1>OM NOM NOM</h1>
        <p>I love cookies! But this one tastes... weird.</p>
    </body>
    </html>
    """
    
    # Create a response and set the cookie.
    response = make_response(render_template_string(html_content))
    response.set_cookie('secret_recipe', encoded_flag)
    
    return response

if __name__ == '__main__':
    # Runs on a different port than the main app.
    app.run(host='0.0.0.0', port=5001)


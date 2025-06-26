# challenges/web_challenge_2.py
from flask import Flask, Response, render_template_string

app = Flask(__name__)

# The flag is hidden in a "secret" text file.
FLAG = "flag{r0b0ts_c4nt_k33p_s3cr3ts}"

@app.route('/')
def index():
    # A simple homepage for the challenge.
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Our New Corporate Site</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
        <style>
            body { background-color: #f7fafc; color: #2d3748; font-family: 'Roboto', sans-serif; text-align: center; padding-top: 100px; }
            h1 { font-size: 3rem; }
            p { font-size: 1.2rem; }
        </style>
    </head>
    <body>
        <h1>Welcome!</h1>
        <p>This is our brand new, ultra-secure corporate website. Nothing to see here!</p>
    </body>
    </html>
    """

@app.route('/robots.txt')
def robots():
    # This file tells search engines what not to crawl. A classic hiding spot.
    robots_content = """
User-agent: *
Disallow: /secret-area/
    """
    return Response(robots_content, mimetype='text/plain')

@app.route('/secret-area/flag.txt')
def secret_flag():
    # The flag is located at the disallowed path.
    return Response(f"Congratulations! You found the flag: {FLAG}", mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)

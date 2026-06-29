from flask import Flask, request, make_response, render_template_string
import gzip
import io

app = Flask(__name__)

# Intentionally vulnerable HTML template
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App</title>
</head>
<body>
    <h1>VulcanX Test Range</h1>
    
    <p>Search Results for: <span id="query">{{ query|safe }}</span></p>

    <!-- DOM Sink for testing -->
    <script>
        var q = document.getElementById('query').innerText;
        if (q) {
            document.write("You searched for: " + q);
        }
    </script>
    
    <!-- Test Vulnerable Components -->
    <script src="https://code.jquery.com/jquery-3.4.0.min.js"></script>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css">
    <meta name="generator" content="WordPress 5.8.1">
    
    <h2>Links to Scan</h2>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/search?q=test">Search</a></li>
    </ul>

    <h2>Forms to Fill</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <!-- Missing CSRF token -->
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    query = request.args.get('q', '')
    
    html_content = render_template_string(HTML, query=query).encode('utf-8')
    
    # Compress the response (BREACH/CRIME vulnerability test)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(html_content)
    compressed_content = out.getvalue()
    
    response = make_response(compressed_content)
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Type'] = 'text/html'
    
    # Insecure Cookies (Missing HttpOnly, Secure, SameSite)
    response.headers.add('Set-Cookie', 'session_id=123456789; Path=/')
    response.headers.add('Set-Cookie', 'tracking_id=abcxyz; Path=/')
    
    # Misconfigured CORS
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    # Note: Intentionally missing CSP, HSTS, X-Frame-Options
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    return "Login page - Check POST requests for missing CSRF!"

@app.route('/admin')
def admin():
    return "Admin page"

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f"Search results for: {q}"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8081, debug=False)

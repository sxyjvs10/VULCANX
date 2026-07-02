import urllib.request
import urllib.parse
from http.cookiejar import CookieJar

cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
resp = opener.open('http://zero.webappsecurity.com/')
print("Home page cookies:", [c.name for c in cj])

data = urllib.parse.urlencode({'user_login': 'username', 'user_password': 'password', 'submit': 'Sign in'}).encode()
resp = opener.open('http://zero.webappsecurity.com/login.html', data=data)
print("Login page cookies:", [c.name for c in cj])

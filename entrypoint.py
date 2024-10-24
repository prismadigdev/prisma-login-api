import os
import sys
import uuid
from flask import g, request

from app import create_app
from app import prefix

settings_module = os.getenv('APP_SETTINGS_MODULE')
if not settings_module:
    print("Error: Environment variable APP_SETTINGS_MODULE not set in linux service")
    sys.exit()

app = create_app(settings_module)



def generate_nonce():
    return uuid.uuid4().hex

@app.before_request
def set_nonce():
    g.nonce = generate_nonce()
@app.after_request
def add_security_headers(response):
    nonce = g.get('nonce')
    #gunicorn.SERVER_SOFTWARE = 'intentionally-undisclosed-gensym384763'
    if 'Server' in response.headers:
        del response.headers['Server']
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    #response.headers['Content-Security-Policy'] = csp
    if request.path.startswith('/apidocs'):
        pass
    else:
        response.headers['Content-Security-Policy'] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self';"
        )
    response.headers['server'] = 'MySecureServer'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), fullscreen=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=(), autoplay=()'

    return response

@app.route('/healthcheck', methods=['GET'])
def ping():
    """
        Check if server is alive
        :return: "pong"
    """
    return "pong 3"


@app.route('/', methods=['GET'])
def ok():
    """
        Check if server is alive
        :return: "ok"
    """
    return settings_module

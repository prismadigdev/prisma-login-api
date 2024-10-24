import entrypoint
import os
from flask import Flask, redirect, request, session, url_for, Blueprint, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from urllib.parse import urlparse

from app.auth.service.user import sso_create_token

sso_bp = Blueprint('sso_bp', __name__)

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path = 
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'saml', entrypoint.app.config['SAML_CONFIGURATION']))
    return auth

def prepare_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'https': 'on',
        'http_host': request.host,
        'script_name': request.path,
        'server_port': url_data.port,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


@sso_bp.route('saml', methods=['GET'])
def index():
    if 'samlUserdata' in session:
        email = session["samlUserdata"]["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"][0]
        logout_url = url_for('sso_bp.logout', _external=True)
        return f'Hello {email}! <a href="{logout_url}">Logout</a>.'
    else:
        login_url = url_for('sso_bp.login', _external=True)
        return f'You are not logged in. <a href="{login_url}">Login here</a>.'

"Path dónde redirecciona Azure cuando se cierra la sesion"
@sso_bp.route('', methods=['GET'])
def soo():
    login_url = url_for('sso_bp.login', _external=True)
    return f'You are not logged in. <a href="{login_url}">Login here</a>.'


@sso_bp.route('login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@sso_bp.route('acs', methods=['POST'])
def acs():
    
    print("----------- Inicio ACS")
    try:
        req = prepare_flask_request(request)    
        auth = init_saml_auth(req)
        
        print("----------- ACS 2")
        auth.process_response()
        errors = auth.get_errors()
        if not errors:
            session['samlUserdata'] = auth.get_attributes()

            print("----------- ACS Attributes")
            print("----------- " + str(session['samlUserdata']))

            email = session["samlUserdata"]["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"][0]

            print("----------- ACS email")
            print("----------- " + email)

            jwt_response, status_code = sso_create_token(request.remote_addr, email.lower())

            print("----------- ACS Status Code")
            print("----------- " + str(status_code))

            if status_code == 200:

                data = jwt_response.get_json()
                jwt_token = data['access_token']

                print("----------- ACS Access Token")
                print("----------- " + jwt_token)

                response = make_response(redirect(entrypoint.app.config['FRONT_SITE_HOST'] + "saml?token=" + jwt_token))

                print("----------- ACS Respose")
                print("----------- " + str(response))
                return response

            # Error asociado a que el usuario de Azure no se encuentra registrado en la BD de Login
            response = make_response(redirect(entrypoint.app.config['FRONT_SITE_HOST'] + "saml/error/404"))
            return response
        else: 
            # Error asociado a la respuesta que es enviada desde Azure al servicio ACS 
            response = make_response(redirect(entrypoint.app.config['FRONT_SITE_HOST'] + "saml/error/502"))
            print("----------- Errors ACS")
            print("----------- " + str(errors))
            return response
    except Exception as e:
        # Error general del servidor
        print("----------- Error en ACS Principal:", str(e))
        response = make_response(redirect(entrypoint.app.config['FRONT_SITE_HOST'] + "saml/error/500"))
        return response

@sso_bp.route('logout')
def logout():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(url_for('sso_bp.logout'))

@sso_bp.route('sls', methods=['GET', 'POST'])
def sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo()
    errors = auth.get_errors()
    if not errors:
        session.clear()
        return redirect(url)
    return 'Error: ' + ', '.join(errors)

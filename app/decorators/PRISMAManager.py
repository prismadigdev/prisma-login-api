import json
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps
from typing import Any
from urllib import request as request2

import entrypoint
import ssl


def jwt_required() -> Any:
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):

            try:

                ssl._create_default_https_context = ssl._create_unverified_context
                headers = request.headers
                auth = headers.get("Authorization")

                # Valida si es un token Bearer (Bearer para consumo de servicio desde la misma aplicación)
                if "Bearer" in auth: 
                    verify_jwt_in_request()
                    return fn(*args, **kwargs)
                
                # Si no es Bearer se asume que el servicio está siendo consultado desde otra aplicación
                else:

                    JSON_object, response = validate_suscription_token(auth)
                    if JSON_object == 200:
                        return fn(*args, **kwargs)
                    else:
                        return jsonify(msg="Not valid!"), 403
                    
            except Exception as e:
                return jsonify(msg=str(e)), 403
        return decorator
    return wrapper


"""
    Valida que el token de suscripción enviado en el consumo del servicio es un token válido 
    Obtiene la url de la aplicación de suscripción a través de la varable SUSCRIPTION_URL
    Y pasa el token que es obtenido desde los headers del request
"""
def validate_suscription_token(auth):
    token = auth.split(' ')[1]
    url = entrypoint.app.config['SUSCRIPTION_URL'] + token
    req =  request2.Request(url, method="GET")
    req.add_header('Content-Type', 'application/json')
    resp = request2.urlopen(req)
    with resp as response:
        status_code = response.getcode()
        response_body = response.read()
        response_json = json.loads(response_body)
    print(status_code,response_json["permissions"])
    return resp.getcode(), response_json

from functools import wraps

import requests
from flask import request, jsonify
from urllib.parse import urlparse



def any_of_decorators(*decorators):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            for decorator in decorators:
                response = decorator(f)(*args, **kwargs)
                # Verificar si la respuesta no es un fallo (status code 403)
                if isinstance(response, tuple) and len(response) == 2 and response[1] == 403:
                    continue
                return response
            return jsonify({'error': 'No tienes permisos para realizar esta acción'}), 403
        return decorated
    return wrapper

def validate_request(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        headers = dict(request.headers)
        auth = headers.get("Authorization")
        if "Bearer" in auth: 
            verify_jwt_in_request()
            return func(*args, **kwargs)
        elif "JWT" in auth:
            
            validation_data, headers = prepare_validation(request)
            validation_response = send_validation_request(validation_data, headers)

            #validation_response = requests.post(validation_service_url, headers=headers, json=validation_data)

            if validation_response.status_code != 200:
                return jsonify({'error': 'No tienes permisos para realizar esta acción'}), 403
            return func(*args, **kwargs)

    return decorated_function





def prepare_validation(request):
    headers_json = dict(request.headers)
    token_jwt = headers_json.get("Authorization")

    if token_jwt is None or not token_jwt.startswith("JWT "):
        raise Exception("Invalid Token")

    token = token_jwt.split(" ")[1]

    headers = {
        'Authorization': f'JWT {token}',
        'Accept': 'application/json'
    }

    parsed_url = urlparse(request.url)
    url = parsed_url.netloc + parsed_url.path

    validation_data = {
        'method': request.method,
        'url': url
    }

    return validation_data, headers


def send_validation_request(validation_data, headers):
    validation_service_url = entrypoint.app.config['SUSCRIPTIONNEW_URL']#'https://integrationnew-api.prismaqa.com/api/v1/auth/validate'
    validation_response = requests.post(validation_service_url, headers=headers, json=validation_data)
    #validation_response.raise_for_status()

    return validation_response
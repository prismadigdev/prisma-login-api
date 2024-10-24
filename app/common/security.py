import jwt
import os
from flask import request, jsonify
from flask_jwt_extended import get_jwt
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps

# Here is a custom decorator that verifies the JWT is present in the request,
# as well as insuring that the JWT has a claim indicating that this user is
# an administrator
from app.common.audit import init_audit
from app.decorators.PRISMAManager import validate_suscription_token


def has_role(role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if os.environ['SECURITY'] == "NO":
                return fn(*args, **kwargs)
            init_audit()
            verify_jwt_in_request()
            claims = get_jwt()
            roles = claims["roles"]

            if role in roles:
                return fn(*args, **kwargs)

            if set(roles) & set(role):
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Not roles!"), 403

        return decorator

    return wrapper


def has_permission(permission):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):

            headers = request.headers
            auth = headers.get("Authorization")
            calledroute = str(request.url_rule)

            if "Bearer" in auth:
                if os.environ['SECURITY'] == "NO":
                    return fn(*args, **kwargs)
                init_audit()
                verify_jwt_in_request()
                claims = get_jwt()
                permissions = claims["permissions"]

                if permission in permissions:
                    return fn(*args, **kwargs)

                if set(permissions) & set(permission):
                    return fn(*args, **kwargs)
                else:
                    return jsonify(msg="Not permissions!"), 403
            else:
                return jsonify(msg="Not permissions!"), 403

        return decorator

    return wrapper


def is_valid(apikey):
    #device = DeviceModel.find_by_device_key(api_key)
    #if device and compare_digest(device.device_key, api_key):
    #    return True
    if apikey == "ef229daa-d058-4dd4-9c93-24761842aec5":
        return True
    return False


def api_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        print(request.headers)
        if request.headers.get("Apikey"):
            apikey = request.headers.get("Apikey")
        else:
            return {"message": "Please provide an API key"}, 400
        # Check if API key is correct and valid
        if request.method == "POST" and is_valid(apikey):
            return func(*args, **kwargs)
        else:
            return {"message": "The provided API key is not valid"}, 403
    return decorator







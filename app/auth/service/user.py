import boto3
import datetime
import jwt
from flask import jsonify, abort
from flask import request, Blueprint
from flask_jwt_extended import create_access_token, JWTManager
from json import dumps

from app.auth.models.user import User
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.system_schema_single import SystemSchemaSingle

auth_bp = Blueprint('auth_bp', __name__)



OLClient = boto3.client('cognito-idp', region_name="us-east-1")

OL = "1qip37c38k0v9io2t86u1jat43"
userpool = "us-east-1_zoId0epNt"

system_schema = SystemSchema()
system_schema_single = SystemSchemaSingle()


def create_token (response, username=None):

    ipaddress = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

    #ipaddress = request.environ['HTTP_X_FORWARDED_FOR']

    if(username is None):
        jwt_token = response['AuthenticationResult']['IdToken']
        token = jwt.decode(jwt_token, options={"verify_signature": False})

        username = token['email']

    user = User.simple_filter_unique(email=username)

    if user is None:
        return jsonify({"msg": "User not exist in database"}), 401

    user_role_users = user.user_role_users

    systems = list()

    for user_role_user in user_role_users:
        systems.append(user_role_user.system)

    systems = system_schema.dump(systems, many=True)
    systems_jwt = system_schema_single.dump(systems, many=True)

    expires = datetime.timedelta(minutes=300)
    additional_claims_jwt = {"system": systems_jwt, "ip": ipaddress}
    token_jwt = create_access_token(identity=username, additional_claims=additional_claims_jwt,
                                    expires_delta=expires)

    additional_claims = {"token": response, "system": systems, "token_jwt": token_jwt}

    access_token = create_access_token(identity=username, additional_claims=additional_claims,
                                       expires_delta=expires)

    return jsonify(access_token=access_token)


def sso_create_token(ipaddress=None, username=None):

    if username is None:
        return jsonify({"msg": "Username is mandatory"}), 503

    user = User.simple_filter_unique(email = username)

    if user is None:
        return jsonify({"msg": "User not exist in database"}), 401

    user_role_users = user.user_role_users
    systems = list()

    for user_role_user in user_role_users:
        systems.append(user_role_user.system)

    systems = system_schema.dump(systems, many=True)
    systems_jwt = system_schema_single.dump(systems, many=True)

    expires = datetime.timedelta(minutes = 300)
    additional_claims_jwt = {"system": systems_jwt, "ip": ipaddress}
    token_jwt = create_access_token(identity=username, additional_claims=additional_claims_jwt,
                                    expires_delta=expires)

    additional_claims = {"token": {"AuthenticationResult": {"AccessToken": token_jwt}},"azure": True, "system": systems, "token_jwt": token_jwt}

    access_token = create_access_token(identity=username, additional_claims=additional_claims,
                                       expires_delta=expires)

    return jsonify(access_token=access_token), 200
###############################################
# File name: auth.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################

import boto3
import datetime
import jwt
import os
import requests
from flask import request, Blueprint, Flask, current_app
from flask import request, jsonify, abort
from flask_jwt_extended import create_access_token, JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import verify_jwt_in_request
from json import dumps
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from app.auth.models.option import Option
# from app.auth.models.role_permission import RolePermission
from app.auth.models.permission import Permission
from app.auth.models.role import Role
from app.auth.models.role_user import RoleUser
from app.auth.models.system import System
from app.auth.models.user import User
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.system_schema_single import SystemSchemaSingle
from app.auth.service.user import create_token
from app.common.audit import init_audit, jsonify_audit, login_init_audit, audit_response_login, end_audit
from app.common.secret_manager import get_secret, get_jwt_key
from app.common.security import has_role

#from app.common.jwt_management import generate_access_token_new


auth_bp = Blueprint('auth_bp', __name__)


def olclient():
    region_named = os.environ['AWS_DEFAULT_REGION']
    OLClient = boto3.client('cognito-idp', region_name=region_named)
    return OLClient


def variable_OL():
    OL = os.environ['OL']
    return OL

def variable_Userpool():
    userpool = os.environ['USERPOOL']
    return userpool

system_schema = SystemSchema()
system_schema_single = SystemSchemaSingle()

@auth_bp.route("/login", methods=['POST'])
def login():
    """  Example login API
    This is using docstrings for specifications.
    ---
    tags:
      - login
    parameters:
      - name: body
        in: body
        required: true
    responses:
      200:
        description: We get the authentication result and access tokens
        examples:
          application/json:
            {
                "email": "string",
                "password": "string",
                "recaptcha":"string"
            }
    """
    print("----------- 1")
    OL = variable_OL()
    print("----------- 2")
    OLClient = olclient()
    jsondata = request.get_json()
    recaptcha = jsondata["recaptcha"]
    verification = recapatcha_verification(recaptcha=recaptcha)
    print("----------- 3")
    if verification:
        login_init_audit()
        print("----------- 4")
        try:
            jsondata = request.get_json()
            username = jsondata["email"]
            password = jsondata["password"]
            print("----------- 5")
            response = OLClient.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password},
                ClientId=OL,
            )
            print("----------- 6")
            # Now we recive a 'NEW_PASSWORD_REQUIRED' challenge
            if 'ChallengeName' in response:
                if response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
                    end_audit({"msg": "Select NEW PASSWORD REQUIRED"}, 401)
                    # Redirect to first login view (change temp password)
                    return (response)
                elif response['ChallengeName'] == "SOFTWARE_TOKEN_MFA":
                    end_audit({"msg": "Select SOFTWARE TOKEN MFA"}, 401)
                    # Guardar la SesiÃ³n y el ChallengeName
                    return response
                elif response['ChallengeName'] == "SMS_MFA":
                    end_audit({"msg": "Select SMS MFA"}, 401)
                    return response
                elif response['ChallengeName'] == "MFA_SETUP":
                    end_audit({"msg": "Select MFA SETUP"}, 401)
                    return response
                elif response['ChallengeName'] == "SELECT_MFA_TYPE":
                    end_audit({"msg": "Select MFA TYPE"}, 401)
                    return response
            end_audit({"msg": "User correct"}, 200)

            print("----------- 7")
            return create_token(response, username=username)

        except Exception as e:
            if 'User is disabled' in str(e):
                end_audit({"msg": "User Disabled"}, 403)
                return jsonify({"msg": "User Disabled"}), 403
            else:
                end_audit({"msg": "Incorrect username or password"}, 401)
                return jsonify({"msg": "Incorrect username or password"}), 401
    else:
        end_audit({"msg": "Recaptcha invalid"}, 401)
        return jsonify({"msg": "Recaptcha invalid"}), 401


@auth_bp.route("/refresh_token", methods=['POST'])
def refresh_token():
    """  Example refresh token API
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: Refresh Token
        in: path
        type: string
        required: true
      - name: email
        in: path
        type: string
        required: true
    responses:
      200:
        description: We update access token and authentication info
        examples:
          application/json:
            {
                "refresh_token": "string",
                "email":"string"
            }
    """
    OL = variable_OL()
    try:
        jsondata = request.get_json()
        
        OLClient = olclient()
        refresh_token = jsondata["refresh_token"]
        username=jsondata["email"]
        response = OLClient.initiate_auth(
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token
            },
            ClientId=OL,
        )
        return create_token(response, username=username)
    except OLClient.exceptions.UserNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UserNotFoundException"), 400
    except OLClient.exceptions.NotAuthorizedException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="NotAuthorizedException"), 400


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@auth_bp.route("/init/<acronym>/<token>", methods=["GET"])
def init(acronym, token):
    """Login
        ---
        tags:
          - login
        parameters:
          - name: acronym
            in: path
            type: string
            required: true
          - name: token
            in: path
            type: string
            required: true
        responses:
          200:
            description: Bearer token
        """
    # audit()
    login_init_audit()
    payload = None
    jwt_key = get_jwt_key()['JWT_SECRET_KEY'] # get_secret('jwt-'+acronym)
    print(token)
    print(jwt_key)
    try:
        payload = jwt.decode(token, key=jwt_key, algorithms=['HS256', ])
    except:
        end_audit({"msg": "Incorrect token"}, 401)
        return jsonify({"msg": "Incorrect token"}), 401

    ipaddress = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    ipaddress_token = payload['ip']

    if ipaddress != ipaddress_token and os.environ['SECURITY_IP'] == "YES":
        end_audit({"msg": "Incorrect location of token"}, 401)
        return jsonify({"msg": "Incorrect location of token"}), 401

    username = payload['sub']
    # password = request.json.get("password", None)
    systems = payload['system']
    user_temp = User.simple_filter_unique(email=username)
    user_role_users = user_temp.user_role_users

    systems2 = list()

    for user_role_user in user_role_users:
        systems2.append(user_role_user.system)
    systems_jwt = system_schema_single.dump(systems2, many=True)
    validate = False

    for s in systems:
        if s['acronym'] == acronym:
            validate = True

    for s in systems_jwt:
        if s['acronym'] == acronym:
            print("dentro del systems_jwt")
            validate = True
            
            

    if not validate:
        end_audit({"msg": "User not validate in system"}, 401)
        return jsonify({"msg": "User not validate in system"}), 401

    user = User.simple_filter_unique(email=username)
    if user is None:
        end_audit({"msg": "Bad username or password"}, 401)
        return jsonify({"msg": "Bad username or password"}), 401

    system = System.simple_filter_unique(acronym=acronym)
    
    if system is None:
        end_audit({"msg": "Bad system not exist"}, 401)
        return jsonify({"msg": "Bad system not exist"}), 401
    if system.status ==False:
        end_audit({"msg": "System Disable"}, 503)
        return jsonify({"msg": "The service is currently under maintenance. Please try again later."}), 503
    # resp = customer_schema.dump(customer)

    # role_user = RoleUser.simple_filter_unique(RoleUser.user_id==user.id and RoleUser.system_id==system.id)
    role_user = RoleUser.simple_filter_unique(user_id=user.id, system_id=system.id)
    if role_user is None:
        end_audit({"msg": "Role not exist for this user"}, 401)
        return jsonify({"msg": "Role not exist for this user"}), 401

    #role_user_permissions = [x for x in role_user.role.permissions if (x.system_id == system.id)]

    array_permissions = list()
    array_roles = list()
    array_options = list()

    array_roles.append(role_user.role.description)

    for permission in role_user.role.permissions:
        if permission.system_id == system.id:
            array_permissions.append(permission.description)
            option = Option.get_by_id(permission.option_id)
            if not search(array_options, option.description):
                array_options.append(option.description)

    additional_claims = {"roles": array_roles, "permissions": array_permissions,
                         "options": array_options, "name_user": user.name}

    expires = datetime.timedelta(minutes=300)

    app_jwt_key = get_secret('jwt-' + acronym)

    onelogin_jwt_key = current_app.config["JWT_SECRET_KEY"]
    current_app.config["JWT_SECRET_KEY"] = app_jwt_key["JWT_SECRET_KEY"]
    access_token = create_access_token(identity=username, additional_claims=additional_claims,
                                       expires_delta=expires)

    current_app.config["JWT_SECRET_KEY"] = onelogin_jwt_key
    end_audit({"msg": "Init correct"}, 200)
    return jsonify(access_token=access_token)

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@auth_bp.route("/init_login", methods=["POST"])
def login_init():
    """Login
        ---
        tags:
          - user
        parameters:
          - name: body
            in: body
            required: true
            schema:
              $ref: '{"username": "","password": ""}'
        responses:
          200:
            description: Bearer token
        """
    # audit()
    username = request.json.get("username", None)
    # password = request.json.get("password", None)
    systemname = request.json.get("system", None)

    user = User.simple_filter_unique(username=username)

    if user is None:
        return jsonify({"msg": "Bad username or password"}), 401

    system = System.simple_filter_unique(name=systemname)

    if system is None:
        return jsonify({"msg": "Bad system not exist"}), 401
    # resp = customer_schema.dump(customer)

    # role_user = RoleUser.simple_filter_unique(RoleUser.user_id==user.id and RoleUser.system_id==system.id)
    role_user = RoleUser.simple_filter_unique(user_id=user.id, system_id=system.id)
    if role_user is None:
        return jsonify({"msg": "Role not exist for this user"}), 401

    role_user_permissions = [x for x in role_user.role.permissions if (x.system_id == system.id)]

    array_permissions = list()
    array_roles = list()
    array_options = list()

    array_roles.append(role_user.role.description)

    for permission in role_user_permissions:
        array_permissions.append(permission.description)
        option = Option.get_by_id(permission.option_id)
        if not search(array_options, option.description):
            array_options.append(option.description)

    additional_claims = {"roles": array_roles, "permissions": array_permissions,
                         "options": array_options, "system": system.name}
    expires = datetime.timedelta(minutes=300)

    access_token = create_access_token(identity=username, additional_claims=additional_claims, expires_delta=expires)
    return jsonify(access_token=access_token)



def search(list, platform):
    for i in range(len(list)):
        if list[i] == platform:
            return True
    return False


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@auth_bp.route("/protectedtest", methods=["GET"])
@has_role(["admin"])
def protectedadmin():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


def recapatcha_verification(recaptcha, *args, **kwargs):
        recaptcha_is_valid = None
        recaptchakey = os.environ['RECAPTCHA']
        data = {
            'secret': recaptchakey,#GOOGLE_RECAPTCHA_SECRET_KEY,

            'response': recaptcha,
            'remoteip': "" #request.access_route[0]
        }
        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data=data
        )
        result = r.json()
        if result['success']==True:
            recaptcha_is_valid = True
        else:
            recaptcha_is_valid = False

        return recaptcha_is_valid

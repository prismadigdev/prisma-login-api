###############################################
# File name: user.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
import boto3
import io
import os
import pandas as pd
import safe
import uuid
from flask import jsonify
from flask import request, Blueprint
from flask import send_file
from flask_jwt_extended import get_jwt_identity, jwt_required, verify_jwt_in_request, get_jwt
from werkzeug.security import check_password_hash, generate_password_hash

from app.common.error_handling import ObjectNotFound
from app.auth.controller.auth import olclient
from app.auth.controller.user_management import create_user_cognito, create_user_cognito2
from app.auth.controller.user_management import variable_Userpool
from app.auth.models.role import Role
from app.auth.models.role_user import RoleUser
from app.auth.models.system import System
from app.auth.models.user import User
from app.auth.schemas.role_user_schema import RoleUserSchema
from app.auth.schemas.role_user_user_schema import RoleUserUserSchema
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.system_user_schema import UserRoleSystem
from app.auth.schemas.user_schema import UserSchema
from app.auth.schemas.user_schema_download import UserSchemaDownload
from app.auth.schemas.user_schema_post import UserSchemaPost
from app.auth.utils.function_object import get_user, get_system, get_role, get_role_user, validate_admin
from app.common.audit import jsonify_audit
from app.common.security import has_permission
from app.decorators.PRISMAManager import validate_request, any_of_decorators

users_bp = Blueprint('users_bp', __name__)
admins_bp = Blueprint('admins_bp', __name__)

user_schema = UserSchema()
system_schema = SystemSchema()
user_schema_post = UserSchemaPost()
role_user_schema = RoleUserSchema()
user_role_system_schema = UserRoleSystem()
role_user_user_schema = RoleUserUserSchema()
user_schema_down = UserSchemaDownload()

@users_bp.route('', methods=['GET'])
@has_permission(["USER_ADM", "USER_LIST"])
def get_all_users():
    """Returning list all users
    ---
    tags:
      - user
    definitions:
      User:
        type: object
        properties:
          id:
            type: integer
          name:
            type: string
          username:
            type: string
          status:
            type: string
          email:
            type: string
          phone:
            type: string
          uuid:
            type: string
          user_created:
            type: string
          date_created:
            type: string
            format: date
          azure:
            type: string
    responses:
      200:
        description: A list of users
        schema:
          $ref: '#/definitions/Driver'
    """

    users = User.get_all()
    result = user_schema.dump(users, many=True)
    return jsonify_audit(result)


@users_bp.route('/<user_id>', methods=['GET'])
#@has_permission(["USER_ADM", "USER_LIST"])
def get_user_by_id(user_id):
    """Return user identified by id
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    description: Get user
    responses:
      200:
        description: A user identified by id
        schema:
          $ref: '#/definitions/User'
    """

    user = get_user(user_id)
    resp = user_schema.dump(user)
    #add response from admin_get_user from cognito
    #use user.email to send the request

    try:
      userpool = variable_Userpool()
      username = user.email    
      OLClient = olclient()
      response = OLClient.admin_get_user(
          UserPoolId=userpool,
          Username=username,
      )
      extract_dict = {}
      extract_dict["MFAOptions"] = response["MFAOptions"] if "MFAOptions" in response  else ""
      extract_dict["PreferredMfaSetting"] = response["PreferredMfaSetting"] if "PreferredMfaSetting" in response  else ""
      extract_dict["UserMFASettingList"] = response["UserMFASettingList"] if "UserMFASettingList" in response  else ""
      if response["Enabled"] ==True:
          extract_dict["StatusCognito"]="Enable"
      else:
          extract_dict["StatusCognito"]="Disable"
      extract_dict["StatusAccount"]=response["UserStatus"]
      resp["mfa_config"] = extract_dict
    except Exception as e:
        print("Error get user " + user.email + " in cognito: " + str(e))

    return jsonify_audit(resp)
    


@users_bp.route('/email/<user_email>', methods=['GET'])
@has_permission(["USER_ADM"])
def get_user_by_email(user_email):
    """Return user identified by email
    ---
    tags:
      - user
    parameters:
      - name: user_email
        in: path
        type: string
        required: true
    description: Get user for email
    responses:
      200:
        description: A user identified by email
        schema:
          $ref: '#/definitions/User'
    """

    user = User.simple_filter_unique(email=user_email)

    if user is None:
        raise ObjectNotFound('User not exist')

    resp = user_schema.dump(user)
    return jsonify_audit(resp)

@users_bp.route('/user_systems', methods=['GET'])
def get_systems_of_user_by_email():
    """Return user identified by email
    ---
    tags:
      - user
    parameters:
      - name: user_email
        in: path
        type: string
        required: true
    description: Get user for email
    responses:
      200:
        description: A user identified by email
        schema:
          $ref: '#/definitions/User'
    """

    verify_jwt_in_request()
    claims = get_jwt()
    username = claims["sub"]
    user = User.simple_filter_unique(email=username)

    if user is None:
        return jsonify({"msg": "User not exist"}), 401

    user_role_users = user.user_role_users

    systems = list()

    for user_role_user in user_role_users:
        systems.append(user_role_user.system)

    systems = system_schema.dump(systems, many=True)

    return jsonify_audit(systems)


@users_bp.route('', methods=['POST'])
@has_permission(["USER_ADM"])
def create_user():
    """Add new user
    ---
    tags:
      - user
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/User'
    responses:
      200:
        description: User add
        schema:
          $ref: '#/definitions/User'
    """
    data = request.get_json()
    user_dict = user_schema_post.load(data)
    name = None
    if 'name' in user_dict:
        name = user_dict['name']
    username = None
    if 'username' in user_dict:
        username = user_dict['username']
    status = None
    if 'status' in user_dict:
        status = user_dict['status']
        status = 'A'
    phone = None
    if 'phone' in user_dict:
        phone = user_dict['phone']
    email = None
    if 'email' in user_dict:
        email = user_dict['email']
    user_created = None
    if 'user_created' in user_dict:
        user_created = user_dict['user_created']

    azure = "false"  
    if 'azure' in user_dict:
        azure = user_dict['azure']
    
    if (email != None):
      user=None
      try: 
        
        user_temp = User(name=name, username=username, status=status, phone=phone,
                  email=email, user_created=user_created)
        user_temp.save()
        user = user_temp
        resp = user_schema.dump(user)

        # If Azure is false (!= true), it means the user must be created in Cognito.
        if azure != "true":

          if(phone == ""):
            resp2 = create_user_cognito2(username=email)
            if("err" in resp2[0].json):
                user.delete()
                return jsonify_audit({"msg":resp2[0].json["err"]}), resp2[1]
            else:
                status_code = resp2[1]
                return jsonify_audit(resp), 201
          elif (phone != ""):
            resp2 = create_user_cognito(username=email, phone_number=phone)
            if("err" in resp2[0].json):
                user.delete()
                return jsonify_audit({"msg":resp2[0].json["err"]}), resp2[1]
            else:
                status_code = resp2[1]
                return jsonify_audit(resp),201
          else:
              return jsonify_audit({"msg":resp2[0].json["err"]}), 403
        
        # If it is an Azure user, it does not go through the Cognito creation process and 
        # returns the user created only in the database. 
        else: 
            return jsonify_audit(resp), 201
      except Exception as e:
          if user!=None:
              try:
                  user.delete()
              except Exception as err:
                  raise err
                  #return jsonify({"msg":"Bad Request: An error occur, please retry"}), 400
          #import traceback
          #traceback.print_exception(e)
          print(e)
          return jsonify_audit({"msg":"Bad Request: An error occur, please retry"}), 400
    else:
      return jsonify_audit({"msg":"Email None"}),401
    return jsonify_audit(resp), 201


@users_bp.route('/<user_id>', methods=['PUT'])
@has_permission(["USER_ADM"])
def update_user(user_id):
    """Update user
    ---
    tags:
      - user
    parameters:
      - name: user
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/User'
    responses:
      200:
        description: User update
        schema:
          $ref: '#/definitions/User'
    """
    data = request.get_json()
    user = get_user(user_id)
    user_dict = user_schema_post.load(data)
    username = user_dict['email']
    lista_attributes = []
    if 'name' in user_dict:
        user.name = user_dict['name']
    if 'username' in user_dict:
        user.username = user_dict['username']
    if 'status' in user_dict:
        user.status = user_dict['status']
    if 'phone' in user_dict:
        user.phone = user_dict['phone']
        phone_number = user_dict['phone']
        dictionario = {
            "Name": "phone_number",
            "Value": phone_number
        }
        lista_attributes.append(dictionario)
    if 'email' in user_dict:
        user.email = user_dict['email']
        dictionario = {
            "Name": "email",
            "Value": user.email
        }
        lista_attributes.append(dictionario)
    try:
        userpool = variable_Userpool()
        OLClient = olclient()

        try: 
          response = OLClient.admin_update_user_attributes(
              UserPoolId=userpool,
              Username=username,
              UserAttributes=lista_attributes
          )
        except Exception as e:
          # Este try se debe quitar cuando se tenga forma de saber si el usuario no es de coginito 
          # Y es un usuario Azure. Se agrega try para evitar romper al intetar actualizar un 
          # usuario Azure que no existe en cognito. 
          print("User no found")

        user.save()
        resp = user_schema.dump(user)
        return jsonify_audit(resp), 201
    except OLClient.exceptions.UserNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UserNotFoundException"), 400
    except OLClient.exceptions.UnexpectedLambdaException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UnexpectedLambdaException"), 400
    except OLClient.exceptions.InvalidParameterException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="InvalidParameterException"), 400
    


@users_bp.route('/<user_id>', methods=['DELETE'])
@has_permission(["USER_ADM"])
def delete_user(user_id):
    """Delete user
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: User deleted
        schema:
          $ref: '#/definitions/User'
    """

    user = get_user(user_id)

    resp = {
        'msg': 'User ' + user.name + ' is deleted'
    }
    user.delete()

    return jsonify_audit(resp)


@users_bp.route("/changepwd", methods=["POST"])
#@jwt_required()
@any_of_decorators(jwt_required(), validate_request)
def change():
    """Change user password
        ---
        tags:
          - user
        parameters:
          - name: body
            in: body
            required: true
        responses:
          200:
            description: Password is changed correctly
        """

    username = get_jwt_identity()
    if username is None:
        return jsonify({"msg": "Bad username"}), 401
    password = request.json.get("password", None)

    user = User.simple_filter_unique(username=username)
    if user is None:
        return jsonify({"msg": "Bad username"}), 401

    if check_password_hash(user.passw, password):
        return jsonify({"msg": "password equal to the previous one"}), 401

    check = safe.check(password)
    if check.strength not in ['medium', 'strong']:
        return jsonify({"msg": 'Password is not strong enough'}), 401

    user.passw = str(generate_password_hash(password))
    user.save()

    return jsonify_audit({"msg": 'Password is changed correctly'}), 200


@users_bp.route("/reset_pass/<user_id>", methods=["GET"])
@has_permission(["USER_ADM"])
def reset(user_id):
    """Reset user password
        ---
        tags:
          - user
        parameters:
          - name: user_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: Password is reset correctly
        """

    user = get_user(user_id)
    password = "Hensall.*"
    user.passw = str(generate_password_hash(password))
    user.save()

    return jsonify_audit({"msg": 'Password is reseted correctly'}), 200


@users_bp.route("/recovery", methods=["POST"])
def recovery():
    return


@users_bp.route('/<user_id>/roles', methods=['GET'])
@has_permission(["USER_ADM"])
def get_roles_user_by_id(user_id):
    """Return user identified by id
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    description: Get roler of use
    responses:
      200:
        description: A roles list of user
        schema:
          $ref: '#/definitions/Role'
    """
    user = get_user(user_id)

    resp = role_user_schema.dump(user.user_role_users, many=True)
    return jsonify_audit(resp)


@users_bp.route('/<role_user_id>/role', methods=['DELETE'])
@has_permission(["USER_ADM"])
def delete_role_of_user(role_user_id):
    """Delete user of system
    ---
    tags:
      - user
    parameters:
      - name: role_user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: system
        schema:
          $ref: '#/definitions/System'
    """

    roleuser = get_role_user(role_user_id)

    resp = {
        'msg': 'role ' + roleuser.role.description + ' of system ' +
               roleuser.system.name + ' for user ' + roleuser.user.name + ' is deleted'
    }

    roleuser.delete()

    return jsonify_audit(resp)


@users_bp.route('/<user_id>/system/<system_id>/role/<role_id>', methods=['POST'])
@has_permission(["USER_ADM"])
def add_role_of_user(user_id, system_id, role_id):
    """Add user of system
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
      - name: system_id
        in: path
        type: string
        required: true
      - name: role_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: system
        schema:
          $ref: '#/definitions/System'
    """

    user = get_user(user_id)

    system = get_system(system_id)

    role = get_role(role_id)

    role_user = RoleUser(role_id=role.id, user_id=user.id, system_id=system.id)

    role_user.save()

    resp = role_user_schema.dump(role_user)

    return jsonify_audit(resp)


@users_bp.route('/<user_id>/system/<system_id>', methods=['GET'])
@has_permission(["USER_ADM"])
def get_roles_user_o_system_by_id(user_id, system_id):
    """Return rol of user in a system
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
      - name: system_id
        in: path
        type: string
        required: true
    description: Get role of use in a system
    responses:
      200:
        description: A roles list of user in system
        schema:
          $ref: '#/definitions/Role'
    """
    user = get_user(user_id)
    system = get_system(system_id)
    for user_role_user in user.user_role_users:
        if user_role_user.system.uuid == system.uuid:
            resp = role_user_schema.dump(user_role_user)
            return jsonify(resp)

    return jsonify_audit({"msg": "No role for user"})


@admins_bp.route('/<user_id>/systems/<system_id>/admin', methods=['GET'])
@has_permission(["USER_ADM"])
def get_system_user_is_admin(user_id, system_id):
    """Return True if user is Admin of system
    ---
    tags:
      - admin
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
      - name: system_id
        in: path
        type: string
        required: true
    description: Define so user is admin
    responses:
      200:
        description: A system list of user
        schema:
          $ref: '#/definitions/System'
    """
    user = get_user(user_id)

    system = get_system(system_id)

    for user_system in user.systems:
        if user_system.uuid == system.uuid:
            resp = system_schema.dump(user_system)
            return jsonify(resp)

    return jsonify_audit({"msg": "No admin in system"})


@admins_bp.route('/<user_id>/systems', methods=['GET'])
@has_permission(["USER_ADM"])
def get_system_admin_by_id(user_id):
    """Return systems of user identified by id
    ---
    tags:
      - admin
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    description: Get systems of user
    responses:
      200:
        description: A system list of user
        schema:
          $ref: '#/definitions/System'
    """
    user = get_user(user_id)
    if validate_admin(user_id):
        resp = system_schema.dump(System.get_all(), many=True)
    else:
        resp = system_schema.dump(user.systems, many=True)
    return jsonify_audit(resp)


@admins_bp.route('/<user_id>/systems/<system_id>', methods=['POST'])
@has_permission(["USER_ADM"])
def add_user_system(user_id, system_id):
    """Add user to system as administrator in onelogin
        ---
        tags:
          - admin
        description: Add user as administrator
        parameters:
          - name: user_id
            in: path
            type: string
            required: true
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A system add to user
            schema:
              $ref: '#/definitions/System'
        """

    user = get_user(user_id)
    system = get_system(system_id)

    user.systems.append(system)
    user.save()

    result = system_schema.dump(system)
    return jsonify_audit(result)


@admins_bp.route('/<user_id>/systems/<system_id>', methods=['DELETE'])
@has_permission(["USER_ADM"])
def remove_user_system(user_id, system_id):
    """Delete system to user
        ---
        tags:
          - admin
        description: Remove system of user
        parameters:
          - name: user_id
            in: path
            type: string
            required: true
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A system deleted of user
            schema:
              $ref: '#/definitions/System'
        """

    user = get_user(user_id)
    system = get_system(system_id)

    user.systems.remove(system)
    user.save()

    result = system_schema.dump(system)
    return jsonify_audit(result)


@admins_bp.route('/current/systems', methods=['GET'])
@has_permission(["USER_ADM"])
def get_system_admin_current_user():
    """Return systems of user identified by id
    ---
    tags:
      - admin
    description: Get systems of current user
    responses:
      200:
        description: A system list of user
        schema:
          $ref: '#/definitions/System'
    """

    verify_jwt_in_request()
    claims = get_jwt()
    username = claims["sub"]

    user = User.simple_filter_unique(email=username)

    if validate_admin(user.uuid):
        resp = system_schema.dump(System.get_all(), many=True)
    else:
        resp = system_schema.dump(user.systems, many=True)


    return jsonify_audit(resp)



#UserRoleSystem
@users_bp.route('/<user_id>/systems_role_user', methods=['GET'])
@has_permission(["USER_ADM"])
def get_systems_by_id(user_id):
    """Return systems of user identified by id
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    description: Get systems of user
    responses:
      200:
        description: A system list of user
    """
    user = get_user(user_id)
    resp = user_role_system_schema.dump(User.native_query("SELECT rol.description as role, syst.name as name_system, syst.uuid as syst_uuid	FROM auth.role_user as rolus	LEFT JOIN auth.role as rol ON rol.id = rolus.role_id	LEFT JOIN auth.system as syst ON syst.id = rolus.system_id	WHERE rolus.user_id ="+str(user.id)+";"), many=True)
    return jsonify(resp)


#Temporary APIS
#TODO Delete this APIs to avoid be used
@users_bp.route('/import_users', methods=['POST'])
def create_user2():
    """Add new user2
    ---
    tags:
      - user
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/User'
    responses:
      200:
        description: User add
        schema:
          $ref: '#/definitions/User'
    """
    data = request.get_json()
    user_dict = user_schema_post.load(data)
    print(user_dict)
    name = None
    if 'name' in user_dict:
        name = user_dict['name']
    username = None
    if 'username' in user_dict:
        username = user_dict['username']
    status = None
    if 'status' in user_dict:
        status = user_dict['status']
        status = 'A'
    phone = None
    if 'phone' in user_dict:
        phone = user_dict['phone']
    email = None
    if 'email' in user_dict:
        email = user_dict['email']
    user_created = None
    if 'user_created' in user_dict:
        user_created = user_dict['user_created']

    if (email != None):
      user=None
      try: 
        
        user_temp = User(name=name, username=username, status=status, phone=phone,
                  email=email, user_created=user_created)
        user_temp.save()
        user = user_temp
        resp = user_schema.dump(user)
        if(phone == ""):
          resp2 = create_user_cognito2(username=email)
          if("err" in resp2[0].json):
              user.delete()
              return jsonify({"msg":resp2[0].json["err"]}), resp2[1]
          else:
              status_code = resp2[1]
              return jsonify({"msg":"User Created"}), status_code
        elif (phone != ""):
          resp2 = create_user_cognito(username=email, phone_number=phone)
          if("err" in resp2[0].json):
              user.delete()
              return jsonify({"msg":resp2[0].json["err"]}), resp2[1]
          else:
              status_code = resp2[1]
              return jsonify({"msg":"User Created"}), status_code
        else:
            return jsonify({"msg":resp2[0].json["err"]}), 403
      except Exception as e:
          if user!=None:
              try:
                  user.delete()
              except Exception as err:
                  raise err
                  #return jsonify({"msg":"Bad Request: An error occur, please retry"}), 400
          #import traceback
          #traceback.print_exception(e)
          print(e)
          return jsonify({"msg":"Bad Request: An error occur, please retry"}), 400
    else:
      return jsonify({"msg":"Email None"}),401



@users_bp.route('/delete_user/<user_id>', methods=['DELETE'])
def delete_user2(user_id):
    """Delete user
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: User deleted
        schema:
          $ref: '#/definitions/User'
    """

    user = get_user(user_id)

    resp = {
        'msg': 'User ' + user.name + ' is deleted'
    }
    user.delete()

    return jsonify_audit(resp)

#TODO delete this function when we end the multiple import users


@users_bp.route('/import/<user_id>/system/<system_id>/role/<role_id>', methods=['GET'])
def add_role_of_user2(user_id, system_id, role_id):
    """Add user of system
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
      - name: system_id
        in: path
        type: string
        required: true
      - name: role_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: system
        schema:
          $ref: '#/definitions/System'
    """

    user = get_user(user_id)

    system = get_system(system_id)

    role = get_role(role_id)

    role_user = RoleUser(role_id=role.id, user_id=user.id, system_id=system.id)

    role_user.save()

    resp = role_user_schema.dump(role_user)

    return jsonify_audit(resp)


@users_bp.route('/<system_id>/users_download', methods=['GET'])
@has_permission(["USER_LIST", "SYSTEM_LIST", "SYSTEM_ADM"])
def get_users_system_by_id_new(system_id):
    """Return user or system identified by id
    ---
    tags:
      - user
    parameters:
      - name: system_id
        in: path
        type: string
        required: true
    description: Get users of system
    responses:
      200:
        description: A user list of system
        schema:
          $ref: '#/definitions/Role'
    """

    name_app = system_id
    if system_id == 'all':
        verify_jwt_in_request()
        #claims = get_jwt()
        #username = claims["sub"]

        #resp = {'msg': 'no system identified'}

        #user = User.simple_filter_unique(email=username)
        resp = user_schema_down.dump(User.get_all(), many=True)

    elif system_id == 'unassigned':
        #claims = get_jwt()
        #username = claims["sub"]

        #user = User.simple_filter_unique(email=username)
        resp = user_schema_down.dump(User.native_query(sql='SELECT us.id, username, name, status, phone, email, user_created, date_created, us.uuid FROM auth."user" as us LEFT JOIN auth."role_user" as rous ON us.id=rous.user_id where rous.id is null;'), many=True)
        

    else:
        system = get_system(system_id)
        name_app = system.name
        resp = role_user_user_schema.dump(system.system_role_users, many=True)
    df = pd.DataFrame(resp)
    return send_file(
        io.BytesIO(df.to_csv(sep="\t",index=False, encoding='utf-8').encode()),
        as_attachment=True,
        download_name="User_list_" + name_app+".csv",
        mimetype='text/csv')

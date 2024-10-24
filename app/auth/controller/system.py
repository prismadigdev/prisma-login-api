###############################################
# File name: system.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
import io
import pandas as pd
from flask import request, Blueprint
from flask import request, jsonify
from flask import send_file
from flask_jwt_extended import verify_jwt_in_request, get_jwt

from app.common.error_handling import ObjectNotFound
from app.auth.models.role import Role
from app.auth.models.role_user import RoleUser
from app.auth.models.system import System
from app.auth.models.user import User
from app.auth.schemas.role_schema import RoleSchema
from app.auth.schemas.role_user_schema import RoleUserSchema
from app.auth.schemas.role_user_user_schema import RoleUserUserSchema
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.user_schema import UserSchema
from app.auth.utils.function_object import get_system, get_role, get_role_user, validate_admin
from app.common.audit import jsonify_audit
from app.common.security import api_required, has_permission
from app.decorators.PRISMAManager import jwt_required, validate_request, any_of_decorators

system_bp = Blueprint('system_bp', __name__)

system_schema = SystemSchema()
role_schema = RoleSchema()
user_schema = UserSchema()

role_user_schema = RoleUserSchema()
role_user_user_schema = RoleUserUserSchema()

@system_bp.route('', methods=['GET'])
@has_permission(["SYSTEM_LIST", "SYSTEM_ADM"])
def get_all_systems():
    """Returning list all systems
    ---
    tags:
      - system
    definitions:
      System:
        type: object
        properties:
          id:
            type: integer
          name:
            type: string
          url:
            type: string
          acronym:
            type: string
          token_structure:
            type: string
          type:
            type: string
          api:
            type: string
          uuid:
            type: string
          log_file:
            type: string
    responses:
      200:
        description: A list of options
        schema:
          $ref: '#/definitions/System'
    """

    systems = System.get_all()
    result = system_schema.dump(systems, many=True)
    return jsonify_audit(result)

@system_bp.route('/<system_id>', methods=['GET'])
@has_permission(["SYSTEM_LIST", "SYSTEM_ADM"])
def get_system_id(system_id):
    """Return system
        ---
        tags:
          - system
        description: Information of System identified by id
        parameters:
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A system
            schema:
              $ref: '#/definitions/System'
        """

    system = get_system(system_id)

    result = system_schema.dump(system)
    return jsonify_audit(result)



@system_bp.route('', methods=['POST'])
@has_permission(["SYSTEM_ADM"])
def get_create_systems():
    """Add new permission
    ---
    tags:
      - system
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/System'
    responses:
      200:
        description: system add
        schema:
          $ref: '#/definitions/System'
    """
    data = request.get_json()
    permission_dict = system_schema.load(data)

    token_structure = None
    if 'token_structure' in permission_dict:
        token_structure = permission_dict['token_structure']

    log_file = None
    if 'log_file' in permission_dict:
        log_file = permission_dict['log_file']

    system = System(name=permission_dict['name'], url=permission_dict['url'], type=permission_dict['type'],
                    acronym=permission_dict['acronym'], token_structure=token_structure, api=permission_dict['api'],
                    log_file=log_file)

    system.save()
    return jsonify_audit(system_schema.dump(system))


@system_bp.route('/<system_id>', methods=['PUT'])
@has_permission(["SYSTEM_ADM"])
def update_system(system_id):
    """Update system
    ---
    tags:
      - system
    parameters:
      - name: permission systemth
        type: integer
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/System'
    responses:
      200:
        description: system update
        schema:
          $ref: '#/definitions/System'
    """

    data = request.get_json()
    system = get_system(system_id)
    system_dict = system_schema.load(data)

    if 'name' in system_dict:
        system.name = system_dict['name']

    if 'url' in system_dict:
        system.url = system_dict['url']

    if 'type' in system_dict:
        system.type = system_dict['type']

    if 'api' in system_dict:
        system.api = system_dict['api']

    if 'acronym' in system_dict:
        system.acronym = system_dict['acronym']

    if 'log_file' in system_dict:
        system.log_file = system_dict['log_file']

    if 'token_structure' in system_dict:
        print(system_dict['token_structure'])
        system.token_structure = system_dict['token_structure']

    system.save()
    resp = system_schema.dump(system)
    return jsonify_audit(resp), 201

@system_bp.route('/<system_id>/<status>', methods=['PUT'])
@has_permission(["SYSTEM_ADM"])
def enable_disable_system(system_id,status):
    """Update system
    ---
    tags:
      - system
    parameters:
      - name: permission systemth
        type: integer
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/System'
    responses:
      200:
        description: system update
        schema:
          $ref: '#/definitions/System'
    """
    system = get_system(system_id)
    if status == "enable" and system.status ==False:
        system.status = True
        system.save()
        resp = system_schema.dump(system)
        return jsonify_audit(resp), 201
    elif status == "disable" and system.status ==True:
        system.status = False
        system.save()
        resp = system_schema.dump(system)
        return jsonify_audit(resp), 201
    else:
      return jsonify_audit({"msg": "Request invalid"}), 403

    


@system_bp.route('/<system_id>', methods=['DELETE'])
@has_permission(["SYSTEM_ADM"])
def delete_permission(system_id):
    """Delete system
    ---
    tags:
      - system
    parameters:
      - name: system_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: system
        schema:
          $ref: '#/definitions/System'
    """

    system = get_system(system_id)
    if system.system_role_users:
        return jsonify_audit('You cant delete this Application because it has users assigned. Please remove the users and try again.'), 409
    resp = {
        'msg': 'system ' + system.name + ' is deleted'
    }
    system.delete()

    return jsonify_audit(resp)


@system_bp.route('/<system_id>/roles', methods=['GET'])
@has_permission(["SYSTEM_LIST", "SYSTEM_ADM"])
def get_all_roles_of_system(system_id):
    """Return list all roles
        ---
        tags:
          - system
        description: Roles of system
        parameters:
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A list of role of system
            schema:
              $ref: '#/definitions/System'
        """
    if system_id == "all":
      verify_jwt_in_request()
      result = role_schema.dump(Role.get_all(), many=True)
      return jsonify_audit(result)
    else:
      system = get_system(system_id)

      result = role_schema.dump(system.roles, many=True)
      return jsonify_audit(result)


@system_bp.route('/<system_id>/permissions', methods=['GET'])
@has_permission(["SYSTEM_ADM"])
def list_permissions(system_id):
    """List permissions of system
        ---
        tags:
          - system
        description: List permissions of system
        parameters:
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: List of permissions of system
            schema:
              $ref: '#/definitions/System'
        """

    system = get_system(system_id)

    result = role_schema.dump(system.system_permissions, many=True)
    return jsonify_audit(result)


@system_bp.route('/<system_id>/permissions/<role_id>', methods=['POST'])
@has_permission(["SYSTEM_ADM"])
def add_equipment_asset(system_id, role_id):
    """Add role to system
        ---
        tags:
          - system
        description: Add role to system
        parameters:
          - name: role_id
            in: path
            type: string
            required: true
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A role add to system
            schema:
              $ref: '#/definitions/System'
        """

    system = get_system(system_id)

    role = get_role(role_id)

    system.roles.append(role)
    system.save()

    result = role_schema.dump(role)
    return jsonify_audit(result)


@system_bp.route('/<system_id>/permissions/<role_id>', methods=['DELETE'])
@has_permission(["SYSTEM_ADM"])
def remove_equipment_asset(system_id, role_id):
    """Delete role to system
        ---
        tags:
          - system
        description: Role of system delete
        parameters:
          - name: role_id
            in: path
            type: string
            required: true
          - name: system_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A role deleted
            schema:
              $ref: '#/definitions/Rol'
        """

    system = get_system(system_id)

    role = get_role(role_id)

    system.roles.remove(role)
    system.save()

    result = role_schema.dump(role)
    return jsonify_audit(result)


@system_bp.route('/<system_id>/users', methods=['GET'])
#@jwt_required()
#@validate_request()
@any_of_decorators(jwt_required(), validate_request)
def get_users_system_by_id(system_id):
    """Return user or system identified by id
    ---
    tags:
      - system
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


    if system_id == 'all':
        #verify_jwt_in_request()
        #claims = get_jwt()
        #username = claims["sub"]

        resp = {'msg': 'no system identified'}

        #user = User.simple_filter_unique(email=username)
        resp = user_schema.dump(User.get_all(), many=True)

    elif system_id == 'unassigned':
        #claims = get_jwt()
        #username = claims["sub"]

        #user = User.simple_filter_unique(email=username)
        resp = user_schema.dump(User.native_query(sql='SELECT us.id, username, name, status, phone, email, user_created, date_created, us.uuid FROM auth."user" as us LEFT JOIN auth."role_user" as rous ON us.id=rous.user_id where rous.id is null;'), many=True)
        

    else:
        system = get_system(system_id)
        resp = role_user_user_schema.dump(system.system_role_users, many=True)

    return jsonify(resp)

@system_bp.route('/<int:role_user_id>/role', methods=['DELETE'])
@has_permission(["SYSTEM_ADM"])
def delete_role_of_system(role_user_id):
    """Delete user of system
    ---
    tags:
      - system
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


@system_bp.route('/<system_id>/admins', methods=['GET'])
@has_permission(["SYSTEM_ADM"])
def get_users_admins_by_id(system_id):
    """Return user admins of system by id
    ---
    tags:
      - admin
    parameters:
      - name: system_id
        in: path
        type: string
        required: true
    description: Get admins of system
    responses:
      200:
        description: A user admins list of system
        schema:
          $ref: '#/definitions/User'
    """

    system = get_system(system_id)

    resp = user_schema.dump(system.users, many=True)
    return jsonify_audit(resp)



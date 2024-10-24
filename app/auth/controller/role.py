###############################################
# File name: role.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
from flask import request, Blueprint
from flask import request, jsonify
from flask_jwt_extended import jwt_required

from app.common.error_handling import ObjectNotFound
from app.auth.models.permission import Permission
from app.auth.models.role import Role
from app.auth.models.role_user import RoleUser
from app.auth.models.system import System
from app.auth.schemas.permission_schema import PermissionSchema
from app.auth.schemas.role_schema import RoleSchema
from app.auth.schemas.system_user_schema_role import RoleSystem
from app.auth.utils.function_object import get_role, get_permission
from app.common.audit import jsonify_audit
from app.common.security import api_required, has_permission

role_bp = Blueprint('role_bp', __name__)

role_schema = RoleSchema()
user_role_system_schema = RoleSystem()

permission_schema = PermissionSchema()


@role_bp.route('', methods=['GET'])
@has_permission(["ROLE_LIST", "ROLE_ADM"])
def get_all_roles():
    """Returning list all roles
    ---
    tags:
      - role
    definitions:
      Role:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
          status:
            type: string
          uuid:
            type: string
      Permission:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
    responses:
      200:
        description: A list of roles
        schema:
          $ref: '#/definitions/Role'
    """

    roles = Role.get_all()
    result = role_schema.dump(roles, many=True)
    return jsonify_audit(result)


@role_bp.route('/<role_id>', methods=['GET'])
@has_permission(["ROLE_LIST", "ROLE_ADM"])
def get_role_by_id(role_id):
    """Return role identified by id
    ---
    tags:
      - role
    parameters:
      - name: role_id
        in: path
        type: string
        required: true
    description: Get role
    responses:
      200:
        description: A role identified by id
        schema:
          $ref: '#/definitions/Role'
    """
    role = get_role(role_id)
    #resp = role_schema.dump(role)
    resp = user_role_system_schema.dump(Role.native_query("SELECT rol.uuid as id, rol.description as description, rol.status as status, sys.uuid as syst_uuid, sys.name as name_system FROM auth.role_system AS rosy LEFT JOIN auth.system as sys ON rosy.system_id = sys.id LEFT JOIN auth.role as rol ON rosy.role_id = rol.id 	WHERE rol.uuid = '"+str(role_id)+"';"), many=True)
    
    if resp == []:
        resp = role_schema.dump(role)
    return jsonify_audit(resp)


@role_bp.route('', methods=['POST'])
@has_permission(["ROLE_ADM"])
def get_create_roles():
    """Add new role
    ---
    tags:
      - role
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Role'
    responses:
      200:
        description: role add
        schema:
          $ref: '#/definitions/Role'
    """
    data = request.get_json()
    role_dict = role_schema.load(data)

    role = Role(description=role_dict['description'],
                         status=role_dict['status'])
    role.save()
    return jsonify_audit(role_schema.dump(role))


@role_bp.route('/<role_id>', methods=['PUT'])
@has_permission(["ROLE_ADM"])
def update_role(role_id):
    """Update role
    ---
    tags:
      - role
    parameters:
      - name: role_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Role'
    responses:
      200:
        description: role update
        schema:
          $ref: '#/definitions/Role'
    """

    data = request.get_json()
    role = get_role(role_id)
    role_dict = role_schema.load(data)

    if 'description' in role_dict:
        role.description = role_dict['description']

    if 'status' in role_dict:
        role.capacity = role_dict['status']

    role.save()
    resp = role_schema.dump(role)
    return jsonify_audit(resp), 201


@role_bp.route('/<role_id>', methods=['DELETE'])
@has_permission(["ROLE_ADM"])
def delete_role(role_id):
    """Delete role
    ---
    tags:
      - role
    parameters:
      - name: role_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: role
        schema:
          $ref: '#/definitions/Role'
    """

    role = get_role(role_id)

    resp = {
        'msg': 'role ' + role.description + ' is deleted'
    }
    role.delete()

    return jsonify_audit(resp)


@role_bp.route('/<role_id>/permissions', methods=['GET'])
@has_permission(["ROLE_LIST", "ROLE_ADM"])
def get_all_permissions_of_role(role_id):
    """Return list all permissions
        ---
        tags:
          - role
        description: Permissions of role
        parameters:
          - name: role_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A list of permissions of role
            schema:
              $ref: '#/definitions/Permission'
        """

    role = get_role(role_id)

    result = permission_schema.dump(role.permissions, many=True)
    return jsonify_audit(result)


@role_bp.route('/<role_id>/permissions/<permission_id>', methods=['POST'])
@has_permission(["ROLE_ADM"])
def add_equipment_asset(role_id, permission_id):
    """Add equipment to asset
        ---
        tags:
          - role
        description: Role services
        parameters:
          - name: role_id
            in: path
            type: string
            required: true
          - name: permission_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A permission add to role
            schema:
              $ref: '#/definitions/Permission'
        """

    role = get_role(role_id)

    permission = get_permission(permission_id)

    role.permissions.append(permission)
    role.save()

    result = permission_schema.dump(permission)
    return jsonify_audit(result)


@role_bp.route('/<role_id>/permissions/<permission_id>', methods=['DELETE'])
@has_permission(["ROLE_ADM"])
def remove_equipment_asset(role_id, permission_id):
    """Delete equipment to asset
        ---
        tags:
          - role
        description: Asset services
        parameters:
          - name: role_id
            in: path
            type: string
            required: true
          - name: permission_id
            in: path
            type: string
            required: true
        responses:
          200:
            description: A equipment deleted
            schema:
              $ref: '#/definitions/Equipment'
        """

    role = get_role(role_id)

    permission = get_permission(permission_id)

    role.permissions.remove(permission)
    role.save()

    result = permission_schema.dump(permission)
    return jsonify_audit(result)



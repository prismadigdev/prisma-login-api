###############################################
# File name: permission.py
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
from app.auth.schemas.permission_schema import PermissionSchema
from app.auth.schemas.permission_schema_post import PermissionSchemaPost
from app.auth.utils.function_object import get_permission, get_system
from app.common.audit import jsonify_audit
from app.common.security import api_required, has_permission

permission_bp = Blueprint('permission_bp', __name__)

permission_schema = PermissionSchema()
permission_schema_post = PermissionSchemaPost()


@permission_bp.route('', methods=['GET'])
@has_permission(["PERMISSION_LIST", "PERMISSION_ADM"])
def get_all_permissions():
    """Returning list all permissions
    ---
    tags:
      - permission
    definitions:
      Permission:
        type: object
        properties:
          id:
            type: string
          description:
            type: string
    responses:
      200:
        description: A list of permissions
        schema:
          $ref: '#/definitions/Permission'
    """

    permissions = Permission.get_all()
    result = permission_schema.dump(permissions, many=True)
    return jsonify_audit(result)


@permission_bp.route('/<permission_id>', methods=['GET'])
@has_permission(["PERMISSION_LIST", "PERMISSION_ADM"])
def get_permission_by_id(permission_id):
    """Return permission identified by id
    ---
    tags:
      - permission
    parameters:
      - name: permission_id
        in: path
        type: string
        required: true
    description: Get permission
    responses:
      200:
        description: A permission identified by id
        schema:
          $ref: '#/definitions/Permission'
    """
    permission = get_permission(permission_id)

    resp = permission_schema.dump(permission)
    return jsonify_audit(resp)


@permission_bp.route('', methods=['POST'])
@has_permission(["PERMISSION_ADM"])
def get_create_permissions():
    """Add new permission
    ---
    tags:
      - permission
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Permission'
    responses:
      200:
        description: permission add
        schema:
          $ref: '#/definitions/Permission'
    """
    data = request.get_json()
    permission_dict = permission_schema_post.load(data)
    system = get_system(permission_dict['system'])

    permission = Permission(description=permission_dict['description'],
                            system_id=system.id)
    permission.save()
    return jsonify_audit(permission_schema.dump(permission))


@permission_bp.route('/<permission_id>', methods=['PUT'])
@has_permission(["PERMISSION_ADM"])
def update_permission(permission_id):
    """Update permission
    ---
    tags:
      - permission
    parameters:
      - name: permission_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Permission'
    responses:
      200:
        description: permission update
        schema:
          $ref: '#/definitions/Permission'
    """

    data = request.get_json()
    permission = get_permission(permission_id)
    permission_dict = permission_schema.load(data)

    if 'system' in permission_dict:
        system = get_system(permission_dict['system'])
        permission.system_id = system.id

    if 'description' in permission_dict:
        permission.description = permission_dict['description']

    permission.save()
    resp = permission_schema.dump(permission)
    return jsonify_audit(resp), 201


@permission_bp.route('/<permission_id>', methods=['DELETE'])
@has_permission(["PERMISSION_ADM"])
def delete_permission(permission_id):
    """Delete permission
    ---
    tags:
      - permission
    parameters:
      - name: permission_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: permission
        schema:
          $ref: '#/definitions/Permission'
    """

    permission = get_permission(permission_id)

    resp = {
        'msg': 'permission ' + permission.description + ' is deleted'
    }
    permission.delete()

    return jsonify_audit(resp)

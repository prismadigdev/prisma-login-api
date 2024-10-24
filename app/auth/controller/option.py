###############################################
# File name: option.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
from flask import request, Blueprint
from flask import request, jsonify
from flask_jwt_extended import jwt_required

#from app import ObjectNotFound
from app.auth.models.option import Option
from app.auth.schemas.option_schema import OptionSchema
from app.auth.utils.function_object import get_option
from app.common.audit import jsonify_audit
from app.common.security import api_required, has_permission

option_bp = Blueprint('option_bp', __name__)

option_schema = OptionSchema()


@option_bp.route('', methods=['GET'])
@has_permission(["OPTION_LIST", "OPTION_ADM"])
def get_all_options():
    """Returning list all options
    ---
    tags:
      - option
    definitions:
      Option:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
    responses:
      200:
        description: A list of options
        schema:
          $ref: '#/definitions/Option'
    """

    options = Option.get_all()
    result = option_schema.dump(options, many=True)
    return jsonify_audit(result)


@option_bp.route('/<option_id>', methods=['GET'])
@has_permission(["OPTION_LIST", "OPTION_ADM"])
def get_option_by_id(option_id):
    """Return option identified by id
    ---
    tags:
      - option
    parameters:
      - name: option_id
        in: path
        type: string
        required: true
    description: Get option
    responses:
      200:
        description: A option identified by id
        schema:
          $ref: '#/definitions/option'
    """
    option = get_option(option_id)

    resp = option_schema.dump(option)
    return jsonify_audit(resp)


@option_bp.route('', methods=['POST'])
@has_permission(["OPTION_ADM"])
def get_create_options():
    """Add new option
    ---
    tags:
      - option
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/option'
    responses:
      200:
        description: option add
        schema:
          $ref: '#/definitions/option'
    """
    data = request.get_json()
    option_dict = option_schema.load(data)

    option = Option(description=option_dict['description'])
    option.save()
    return jsonify_audit(option_schema.dump(option))


@option_bp.route('/<option_id>', methods=['PUT'])
@has_permission(["OPTION_ADM"])
def update_option(option_id):
    """Update option
    ---
    tags:
      - option
    parameters:
      - name: option_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Option'
    responses:
      200:
        description: option update
        schema:
          $ref: '#/definitions/Option'
    """

    data = request.get_json()
    option = get_option(option_id)
    option_dict = option_schema.load(data)

    if 'description' in option_dict:
        option.description = option_dict['description']

    option.save()
    resp = option_schema.dump(option)
    return jsonify_audit(resp), 201


@option_bp.route('/<option_id>', methods=['DELETE'])
@has_permission(["OPTION_ADM"])
def delete_option(option_id):
    """Delete option
    ---
    tags:
      - option
    parameters:
      - name: option_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: option
        schema:
          $ref: '#/definitions/Option'
    """

    option = get_option(option_id)
    resp = {
        'msg': 'option ' + option.description + ' is deleted'
    }
    option.delete()

    return jsonify_audit(resp)

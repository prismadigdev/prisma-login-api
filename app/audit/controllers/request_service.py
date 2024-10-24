###############################################
# File name: request_service.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of Audit module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################

import csv
import io
from flask import jsonify, make_response
from flask import request, Blueprint
from flask_jwt_extended import jwt_required
from sqlalchemy import and_, or_, not_

#from app import ObjectNotFound
from app.audit.models.request_service import RequestService
from app.audit.schemas.request_service_schema import RequestServiceSchema
from app.common.security import api_required, has_permission
from app.decorators.PRISMAManager import any_of_decorators, validate_request

request_service_bp = Blueprint('request_service_bp', __name__)

request_service_schema = RequestServiceSchema()


@request_service_bp.route('', methods=['GET'])

# @jwt_required()
@any_of_decorators(jwt_required(), validate_request)
def get_all_request_service():
    """Returning list all request services
    ---
    tags:
      - request_service
    parameters:
      - name: body
        in: body
        required: false
    definitions:
      RequestService:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
    responses:
      200:
        description: A list of request services
        schema:
          $ref: '#/definitions/RequestService'
    """

    #request_services = RequestService.get_all()
    request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created,
                                                          limit_number=150)
    result = request_service_schema.dump(request_services, many=True)
    return jsonify(result)


@request_service_bp.route('/list', methods=['POST'])

# @jwt_required()
@any_of_decorators(jwt_required(), validate_request)
def get_all_request_service_post():
    """Returning list all request services for date and order
    ---
    tags:
      - request_service
    parameters:
      - name: body
        in: body
        required: false
    definitions:
      RequestService:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
    responses:
      200:
        description: A list of request services
        schema:
          $ref: '#/definitions/RequestService'
    """

    jsondata = request.get_json()
    limit = 100
    date_initial = jsondata["date_initial"]
    date_final = jsondata["date_final"]

    if "limit" in jsondata:
        limit = jsondata["limit"]

    if date_initial is None:
        request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created,
                                                              limit_number=limit)
    else:
        if date_initial == date_final:
            date_initial = date_initial + " 00:00:00"
            date_final = date_final + " 23:59:59"
            limit = 0

        if len(date_initial) <= 10:
            date_initial = date_initial + " 00:00:00"

        if len(date_final) <= 10:
            date_final = date_final + " 23:59:59"

        request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created,
                                                              limit_number=limit,
                                                              filters=RequestService.date_created.between(date_initial,
                                                                                                          date_final))
    result = request_service_schema.dump(request_services, many=True)
    return jsonify(result)


@request_service_bp.route('/<int:request_service_id>', methods=['GET'])

@any_of_decorators(jwt_required(), validate_request)
def get_request_service_by_id(request_service_id):
    """Return RequestService identified by id
    ---
    tags:
      - request_service
    parameters:
      - id: request_service_id
        in: path
        type: integer
        required: true
    description: Get RequestService
    responses:
      200:
        description: A RequestService identified by id
        schema:
          $ref: '#/definitions/RequestService'
    """
    request_service = RequestService.get_by_id(request_service_id)
    if request_service is None:
        raise ObjectNotFound('RequestService not exist')

    resp = request_service_schema.dump(request_service)
    return jsonify(resp)


@request_service_bp.route('/download', methods=['POST'])
@any_of_decorators(jwt_required(), validate_request)
def download_csv():
  """Returning list all request services for date and order
    ---
    tags:
      - request_service
    parameters:
      - name: body
        in: body
        required: false
    definitions:
      RequestService:
        type: object
        properties:
          id:
            type: integer
          description:
            type: string
    responses:
      200:
        description: A list of request services
        schema:
          $ref: '#/definitions/RequestService'
    """
  try:
    # Ejecuta la consulta y obtiene los resultados
    jsondata = request.get_json()
    date_initial = jsondata["date_initial"]
    date_final = jsondata["date_final"]
    search = ""
    if not "search" in jsondata:
      if date_initial is None:
          request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created)
      else:
          if date_initial == date_final:
              date_initial = date_initial + " 00:00:00"
              date_final = date_final + " 23:59:59"

          if len(date_initial) <= 10:
              date_initial = date_initial + " 00:00:00"

          if len(date_final) <= 10:
              date_final = date_final + " 23:59:59"

          request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created,
                                                                filters=RequestService.date_created.between(date_initial,
                                                                                                            date_final))
      result = request_service_schema.dump(request_services, many=True)
      keys = ['date_created', 'user_operation', 'type', 'status', 'id', 'url', 'data', 'date_operation', 'uuid', 'system', 'process', 'method_operation', 'endpoint']
      # Crea un archivo CSV en memoria y escribe los resultados en él

      si = io.StringIO()
      si.write(",".join(keys))
      si.write("\n")
      for dictionary in result:
        for i in keys:
          if i =="id":
            si.write(str(dictionary[i]))
          else:
            si.write(dictionary[i])
          
          if keys[-1]!=i:
            si.write(",")
        si.write("\n")

      # Crea una respuesta HTTP con el archivo CSV
      output = make_response(si.getvalue())
      output.headers["Content-Disposition"] = "attachment; filename=query_results.csv"
      output.headers["Content-type"] = "text/csv"

      return output
    else:
      search = jsondata["search"]
      if date_initial is None:
        request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created)
      else:
          if date_initial == date_final:
              date_initial = date_initial + " 00:00:00"
              date_final = date_final + " 23:59:59"

          if len(date_initial) <= 10:
              date_initial = date_initial + " 00:00:00"

          if len(date_final) <= 10:
              date_final = date_final + " 23:59:59"

          request_services = RequestService.get_all_order_limit(order_data=RequestService.date_created,
                                                                filters=and_(RequestService.date_created.between(date_initial, date_final), RequestService.url.contains(search)))
      result = request_service_schema.dump(request_services, many=True)
      keys = ['date_created', 'user_operation', 'type', 'status', 'id', 'url', 'data', 'date_operation', 'uuid', 'system', 'process', 'method_operation', 'endpoint']
      # Crea un archivo CSV en memoria y escribe los resultados en él

      si = io.StringIO()
      si.write("\t".join(keys))
      si.write("\n")
      for dictionary in result:
        for i in keys:
          if i =="id":
            si.write(str(dictionary[i]))
          else:
            si.write(dictionary[i])
          
          if keys[-1]!=i:
            si.write("\t")
        si.write("\n")

      # Crea una respuesta HTTP con el archivo CSV
      output = make_response(si.getvalue())
      output.headers["Content-Disposition"] = "attachment; filename=query_results.csv"
      output.headers["Content-type"] = "text/csv"

      return output
  except Exception as err:
    print("Exception: ",err)

from flask import Blueprint, request

import app.fields.service.field_service as field_service
from app.common.security import has_permission
# from app.auth.service.security_service import has_role
from app.decorators.PRISMAManager import jwt_required, validate_request, any_of_decorators

field_bp = Blueprint('field_bp', __name__)



"""
  Permite consultar los divisions registrados en bd
  NO recibe parámetros
  Retorna una lista con todos los divisions
"""
@field_bp.route('', methods=['GET'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def get_all():
    """Return list all fields
    ---
    tags:
      - fields
    description: Fields services
    parameters:
      - name: page
        in: query
        type: integer
        required: false
        default: 1
        description: Get field list in the number page
      - name: per_page
        in: query
        type: integer
        required: false
        default: 15
        description: Get size field list with per_page registers
    definitions:
      Field:
        type: object
        properties:
          id:
            type: integer
          name:
            type: string
          description: 
            type: string
          state: 
            type: string
          user_id: 
            type: integer
          type: 
            type: string
          time_created:
            type: string
            format: date
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: List of all fields
        schema:
          $ref: '#/definitions/Field'
    """
    return field_service.get_all()

"""
  * Método que permite consultar un call note, dado el identificador pasado cómo párametro
  * El párametro se obtiene a partir del path de la petición 
  * El servicio devuelve el call note o vacío en caso de no encontrar coincidencias
"""
@field_bp.route('/<string:field_id>', methods=['GET'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def get_field_by_id(field_id):
    """Return field identified by id
    ---
    tags:
      - fields
    parameters:
      - name: field_id
        in: path
        type: string
        required: true
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Field identified by id
        schema:
          $ref: '#/definitions/Field'
    """
   
    return field_service.get_field_by_id(field_id)


"""
  * Método que permite eliminar, de manera fisica un registro de call_note de la base de datos
  * El registro a eliminar se identifica con el id pasado cómo parámetro como parte del path
  * El sistema retorna el objeto eliminado
"""
@field_bp.route('/<int:field_id>', methods=['DELETE'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def field_delete(field_id):
    """Delete field identified by id
    ---
    tags:
      - fields
    parameters:
      - name: field_id
        in: path
        type: integer
        required: true
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Field deleted identified by id
        schema:
          $ref: '#/definitions/Field'
    """

    return field_service.field_delete(field_id)


"""
  * Método que permite crear un nuevo CALL_NOTE de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id puesto que se genera de forma automática 
  * El servicio retorna el objeto CALL_NOTE creado
"""
@field_bp.route('/', methods=['POST'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def field_new():
    """Add new user Field
    ---
    tags:
      - fields
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Field'
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Call note add
        schema:
          $ref: '#/definitions/Field'
    """

    data = request.get_json() 
    return field_service.field_new(data)


"""
  * Método que permite actualizar un field de acuerdo a los parameters body de la petición 
  * A diferencia del POST, el método PUT espera el campo id dentro del body 
  * Si la actualización se realiza correctamente, se retorna el objeto actualizado
"""
@field_bp.route('/', methods=['PUT'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def field_update():
    """Update Field
    ---
    tags:
      - fields
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Field'
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Field uodate
        schema:
          $ref: '#/definitions/Field'
    """
    
    data = request.get_json()
    return field_service.field_update(data)




"""
  * Método que permite eliminar, de manera fisica una opción de un campo de tipo select
  * El registro a eliminar se identifica con el id pasado cómo parámetro como parte del path
  * El sistema retorna el objeto eliminado
"""
@field_bp.route('/option/<int:option_id>', methods=['DELETE'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def option_delete(option_id):
    """Delete option field identified by id
    ---
    tags:
      - fields
    parameters:
      - name: option_id
        in: path
        type: integer
        required: true
    definitions:
      Option:
        type: object
        properties:
          id:
            type: integer
          name:
            type: string
          field_id: 
            type: integer
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Option field deleted identified by id
        schema:
          $ref: '#/definitions/Option'
    """

    return field_service.option_delete(option_id)



"""
  * Método que permite crear un nuevo option field de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id puesto que se genera de forma automática 
  * El servicio retorna el objeto option creado
"""
@field_bp.route('/option', methods=['POST'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def option_new():
    """Add new user Option Field
    ---
    tags:
      - fields
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Option'
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Option add
        schema:
          $ref: '#/definitions/Option'
    """

    data = request.get_json() 
    return field_service.option_new(data)



"""
  * Método que permite actualizar un option field de acuerdo a los parameters body de la petición 
  * A diferencia del POST, el método PUT espera el campo id dentro del body 
  * Si la actualización se realiza correctamente, se retorna el objeto actualizado
"""
@field_bp.route('/option', methods=['PUT'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def option_update():
    """Update option field
    ---
    tags:
      - fields
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/Option'
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Option field update
        schema:
          $ref: '#/definitions/Option'
    """
    
    data = request.get_json()
    return field_service.option_update(data)

"""
  * Función que permite consultar los usuarios asociados a una aplicación
  * Además del filtro de aplicación, se pueden filtrar la búsqueda por los siguientes parámetros: 
  * @param app: El nombre de la aplicación sobre la cual se desean consultar los usuarios
  @ @param field_id: Parametro de tipo path: Permite filtrar los usuarios que tengan asociados un custom field en particular
  @ @param field_name: Permite filtrar los usuarios que tengan asociado el nombre de un custom field en particular
  @ @param option_name: Permite filtrar los usuarios que tengan asociado value de un custom field en particular
  @ @param role: Permite filtrar los usuarios que tengan asociado un role en particular
"""
@field_bp.route('/users/app/<string:app>', methods=['GET'])
@any_of_decorators(jwt_required(), validate_request)
def get_users_by_apps(app):
    """Return field identified by id
    ---
    tags:
      - fields
    parameters:
      - name: app
        in: path
        type: string
        required: true
      - name: field_id
        in: query
        type: int
        required: false
      - name: field_name
        in: query
        type: string
        required: false
      - name: option_name
        in: query
        type: string
        required: false
      - name: role
        in: query
        type: string
        required: false
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Field identified by id
        schema:
          $ref: '#/definitions/Field'
    """
    field_id = request.args.get('field_id', '', type=int)
    field_name = request.args.get('field_name', '', type=str)
    option_name = request.args.get('option_name', '', type=str)
    role = request.args.get('role', '', type=str)

    return field_service.get_users_by_app(app, field_id, field_name, option_name, role)


@field_bp.route('/user_custom_field', methods=['POST'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def user_custom_field_new():
    """Add a Field to user
    ---
    tags:
      - fields
    parameters:
      - name: body
        in: body
        required: true
        schema:
          $ref: '#/definitions/UserCustomField'
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Call note add
        schema:
          $ref: '#/definitions/UserCustomField'
    """

    data = request.get_json()
    return field_service.user_custom_field_new(data)


@field_bp.route('/fields_user/<string:user_id>', methods=['GET'])
@any_of_decorators(jwt_required(), validate_request)
def fields_of_user_user_id(user_id):
    """Get the custom fields associated with a user
    ---
    tags:
      - fields
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Call note add
        schema:
          $ref: '#/definitions/UserCustomField'
    """

    return field_service.get_user_fields_user_id(user_id)

@field_bp.route('/fields_user/email/<string:email>', methods=['GET'])
@any_of_decorators(jwt_required(), validate_request)
def fields_of_user(email):
    """Get the custom fields associated with a user
    ---
    tags:
      - fields
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Call note add
        schema:
          $ref: '#/definitions/UserCustomField'
    """

    return field_service.get_user_fields(email)



"""
  * Función que permite consultar la lista de valores de un custom field asociado a un usuario. 
  * Con lista de valores nos referimos particularmente a los campos de tipo select que permiten 
  * que un usuario pueda tener más de una opción asocada. Por ejemplo, si estamos hablando del campo 
  * División, es posible que el usuario de HSM tenga varias divisiones asociadas (Crops, Grain, Feed, etc)
  * Este servicio permite consultar las opciones de un custom field asociadas a un usuario
  * @param email: Párametro de tipo path, con el correo electrónico del usuario a consultar 
  * @param field_name: El nombre del custom field al que se queiren consultar la opciones del usuario
"""
@field_bp.route('/options/<string:email>', methods=['GET'])
#@jwt_required()
#@validate_request
@any_of_decorators(jwt_required(), validate_request)
def option_by_user_and_field(email):
    """Add a Field to user
    ---
    tags:
      - fields
    parameters:
      - name: email
        in: path
        type: string
        required: true
      - name: field_name
        in: query
        type: string
        required: false
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Call note add
        schema:
          $ref: '#/definitions/Option'
    """
    field_name = request.args.get('field_name', '', type=str)
    return field_service.option_by_user_and_field(email, field_name)



"""
  * Método que permite eliminar un option de un campo select asociado a un usuario
  * Recibe el id de la tabla user_custom_field
"""
@field_bp.route('/user_custom_field/<int:id>', methods=['DELETE'])
@has_permission(["SYSTEM_ADM","FIELD_ADM"])
def user_custom_file_delete(id):
    """Delete option field asociated to a user 
    ---
    tags:
      - fields
    parameters:
      - name: id
        in: path
        type: integer
        required: true
    definitions:
      Option:
        type: object
        properties:
          id:
            type: integer
          name:
            type: string
          field_id: 
            type: integer
    security:
      - Bearer: ['Authorization']
    responses:
      200:
        description: Option field deleted identified by id
        schema:
          $ref: '#/definitions/Option'
    """

    return field_service.user_custom_file_delete(id)

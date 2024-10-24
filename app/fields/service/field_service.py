import os
import pandas as pd
from datetime import date
from datetime import datetime
from flask import jsonify, request, send_file
from py_linq import Enumerable
from sqlalchemy import or_
from sqlalchemy.sql import func

# User utils
import app.auth.utils.function_object as foU
from app.common.error_handling import ObjectNotFound, ObligatoryField
from app.db import db
# Model
from app.fields.model.field_model import Field
from app.fields.model.option_model import Options
from app.fields.model.user_custom_field_model import UserCustomField
# Schema
from app.fields.schema.field_schema import FieldSchema
from app.fields.schema.option_schema import OptionsSchema
from app.fields.schema.user_custom_field_get_schema import User_custom_field_get_Schema
from app.fields.schema.user_custom_field_schema import User_custom_field_Schema
from app.fields.schema.user_system_schema import UserSystemSchema

field_schema = FieldSchema()
option_schema = OptionsSchema()
user_system_schema = UserSystemSchema()
user_custom_schema = User_custom_field_Schema()
user_custom_get_schema = User_custom_field_get_Schema()

# Service
"""
  * Permite consultar todos los fields con estado ACTIVE registrados en bd
  * NO recibe parámetros
  * Retorna una lista con todos los fields acvtivos
"""
def get_all():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    
    fields = Field.simple_search_paginate(
        page=page, per_page=per_page,
        param=or_(Field.state == 'ACTIVE'))

    result = field_schema.dump(fields.items, many=True)
    
    meta = {
        "page": fields.page,
        "pages": fields.pages,
        "total_count": fields.total,
        "prev_page": fields.prev_num,
        "next_page": fields.next_num,
        "has_next": fields.has_next,
        "has_prev": fields.has_prev,
    }
    return jsonify({'data':result, 'meta': meta})

"""
  * Devuelve un field de acuerdo al identificador que recibe como parámetro
  * @param: el identificador del field a consultar
  * @return: el field que coincide con el id pasado como parametro, vacío si no hay coincidencias
"""
def get_field_by_id(field_id):
    field = Field.get_by_id(field_id)
    if field is None:
        raise ObjectNotFound('Field not exist')
    resp = field_schema.dump(field)
    return jsonify(resp)


"""
    Elimina un field de acuerdo al identificador pasado cómo parámetro
    Si no hay un registro que coincida con el id, retorna excepción de id no encontrado
    @return: Un json con la información del field eliminado
"""
def field_delete(field_id):
    
    field = Field.get_by_id(field_id)

    if field is None:
        raise ObjectNotFound('Field not exist')

    field.state = 'DELETED'
    field.save()
    resp = field_schema.dump(field)
    return jsonify(resp), 200


"""
  * Método que permite crear un nuevo field de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id, puesto que se genera de forma automática 
  * Se el field es de tipo SELECT obliga a que exista un parameter options que tiene las copciones del select 
  * El servicio retorna el objeto Field creado
"""
def field_new(data):

    field_dict = field_schema.load(data)

    if not 'name' in field_dict:
      raise ObligatoryField('Name: Obligatory field')

    if not 'type' in field_dict:
      raise ObligatoryField('Type: Obligatory field')
    
    if 'SELECT' in field_dict['type'] and not 'options' in field_dict:
        raise ObligatoryField('Options: Obligatory field for SELECT type')

    
    field = Field(
        name = field_dict['name'],
        description = field_dict['description'],
        type = field_dict['type'],
        owner_id = 3,
        time_created = func.now(),
        state = 'ACTIVE'
    )
    field.save()

    if 'SELECT' in field_dict['type']:      
        options = field_dict['options']

        # Se iteran los options que llegan cómo parámetro
        for object in options:
            option = Options(
                field_id = field.id,
                name = object['name']
            )
        
            field.options.append(option)

    field.save()
    resp = field_schema.dump(field)
    return jsonify(resp)

"""
  * Método que permite crear un nuevo field de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id, puesto que se genera de forma automática 
  * Se el field es de tipo SELECT obliga a que exista un parameter options que tiene las copciones del select 
  * El servicio retorna el objeto Field creado
"""
def field_update(data):

    print(data)
    field_dict = field_schema.load(data)

    if not 'name' in field_dict:
      raise ObligatoryField('Name: Obligatory field')

    if not 'type' in field_dict:
      raise ObligatoryField('Type: Obligatory field')
    
    #if 'SELECT' in field_dict['type'] and not 'options' in field_dict:
    #    raise ObligatoryField('Options: Obligatory field for SELECT type')

    field = Field.get_by_id(field_dict['id'])

    if field is None:
      raise ObjectNotFound('Field id not exist')

    if 'name' in field_dict:
      field.name = field_dict['name']
    
    if 'description' in field_dict:
      field.description = field_dict['description']

    if 'state' in field_dict:
      field.state = field_dict['state']

    field.save()
    resp = field_schema.dump(field)
    return jsonify(resp)



"""
    Elimina un option de un field de acuerdo al identificador pasado cómo parámetro
    Si no hay un registro que coincida con el id, retorna excepción de id no encontrado
    @return: Un json con la información del option eliminado
"""
def option_delete(option_id):
    
    option = Options.get_by_id(option_id)

    if option is None:
        raise ObjectNotFound('Option field not exist')

    option.delete()
    resp = option_schema.dump(option)
    return jsonify(resp), 200


"""
  * Método que permite crear un nuevo field de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id, puesto que se genera de forma automática 
  * Se el field es de tipo SELECT obliga a que exista un parameter options que tiene las copciones del select 
  * El servicio retorna el objeto Field creado
"""
def option_new(data):

    option_dict = option_schema.load(data)

    if not 'name' in option_dict:
      raise ObligatoryField('Name: Obligatory field')

    if not 'field_id' in option_dict:
      raise ObligatoryField('Field id: Obligatory field')
    
    option = Options(
        name = option_dict['name'],
        field_id = option_dict['field_id']
    )
    
    option.save()
    resp = option_schema.dump(option)
    return jsonify(resp)

"""
  * Método que permite crear un nuevo field de acuerdo a los parameters body de la petición 
  * A diferencia de PUT, el POST no requiere que sea enviado en id, puesto que se genera de forma automática 
  * Se el field es de tipo SELECT obliga a que exista un parameter options que tiene las copciones del select 
  * El servicio retorna el objeto Field creado
"""
def option_update(data):

    option_dict = option_schema.load(data)

    if not 'id' in option_dict:
      raise ObligatoryField('Id: Obligatory field')

    if not 'name' in option_dict:
      raise ObligatoryField('Name: Obligatory field')

    option = Options.get_by_id(option_dict['id'])
    
    if option is None:
      raise ObjectNotFound('Field option id not exist')

    option.name = option_dict['name']
    
    option.save()
    resp = option_schema.dump(option)
    return jsonify(resp)


def get_users_by_app(application, field_id, field_name, option_name, role):

    if application is None:
      raise ObligatoryField('Application: Obligatory field')

    filter = ''
    if field_id is not None and field_id != "":
       filter = f" and f.id = {field_id}"

    if field_name is not None and field_name != "":
       filter += f" and f.name ilike '%{field_name}%'"

    if option_name is not None and option_name != "":
       filter += f" and o.name ilike '%{option_name}%'"

    if role is not None and role != "":
       filter += f" and r.description ilike '%{role}%'"

    sql = f"select u.name, u.username, u.email, r.description role, f.id field_id, f.type field_type, f.name field_name, \
          case when o.name is null then uf.value else o.name end as value \
          from auth.user u \
          inner join auth.role_user ur on ur.user_id = u.id \
          inner join auth.role r on (r.id = ur.role_id) \
          inner join auth.system sy on (sy.id = ur.system_id) \
          left join auth.user_custom_field uf on (uf.user_id = u.uuid) \
          left join auth.custom_field f on (f.id = uf.field_id) \
          left join auth.option_field o on (o.id = uf.option_id and f.id = o.field_id)\
          where sy.acronym = '{application}'" + f"{filter}"

    results = Field.native_query_(sql = sql)
    result = user_system_schema.dump(results, many=True)
    return jsonify(result)

"""
Function to add field to user"""
def user_custom_field_new(data):

    user_custom_field_dict = user_custom_schema.load(data)
    
    if not 'user_id' in user_custom_field_dict:
      raise ObligatoryField('user_id: Obligatory field')

    if not 'field_id' in user_custom_field_dict:
      raise ObligatoryField('Type: Obligatory field')
    
    if not 'email' in user_custom_field_dict:
      raise ObligatoryField('Type: Obligatory field')
  
    value_dict = user_custom_field_dict.get("value",None)
    option_dict = user_custom_field_dict.get("option_id",None)
    #evitar combinación entre field_id, user_id, option_id, value
    usercustomfield = UserCustomField(
        user_id = user_custom_field_dict['user_id'],
        field_id = user_custom_field_dict['field_id'],
        email= user_custom_field_dict['email'],
        option_id=option_dict,
        value = value_dict
    )
    
    usercustomfield.save()


    resp = user_custom_schema.dump(usercustomfield)
    return jsonify(resp)


def get_user_fields(email):
    array_final = []
    fieldd= None
    fields_query = UserCustomField.simple_filter(email=email)
    fields = user_custom_get_schema.dump(fields_query, many = True)
    for field in fields:
      field_query = Field.get_by_id(field["field_id"])
      field_obj = field_schema.dump(field_query)
      fieldd = dict(field)
      fieldd["field_name"] = field_obj["name"] #if field_obj["name"] is not None else ""
      fieldd["field_type"] = field_obj["type"]
      if fieldd["option_id"] is not None:
        option_query = Options.get_by_id(field["option_id"]) 
        option_obj = option_schema.dump(option_query)
        fieldd["option_name"] = option_obj["name"]
      else:
         fieldd["option_name"] = None
      array_final.append(fieldd)
    

    if fields is None:
        raise ObjectNotFound('User not exist')

    return jsonify(array_final)

def get_user_fields_user_id(user_id):
    array_final = []
    fieldd= None
    fields_query = UserCustomField.simple_filter(user_id=user_id)
    fields = user_custom_get_schema.dump(fields_query, many = True)
    for field in fields:
      field_query = Field.get_by_id(field["field_id"])
      field_obj = field_schema.dump(field_query)
      fieldd = dict(field)
      fieldd["field_name"] = field_obj["name"] #if field_obj["name"] is not None else ""
      fieldd["field_type"] = field_obj["type"]
      if fieldd["option_id"] is not None:
        option_query = Options.get_by_id(field["option_id"]) 
        option_obj = option_schema.dump(option_query)
        fieldd["option_name"] = option_obj["name"]
      else:
         fieldd["option_name"] = None
      array_final.append(fieldd)
    

    if fields is None:
        raise ObjectNotFound('User not exist')

    return jsonify(array_final)


def option_by_user_and_field(email, field_name):

    if email is None:
      raise ObligatoryField('Email: Obligatory field')

    filter = ''
    if field_name is not None and field_name != "":
       filter = f" and cf.name = '{field_name}'"

    sql = f"select o.id, o.name, cf.id field_id, cf.name field \
          from auth.custom_field cf \
          inner join auth.user_custom_field ucf on (ucf.field_id = cf.id) \
          inner join auth.user u on (u.uuid = ucf.user_id) \
          inner join auth.option_field o on (o.id = ucf.option_id) \
          where u.email = '{email}'" + f"{filter}"

    results = Options.native_query_(sql = sql)
    result = option_schema.dump(results, many=True)
    return jsonify(result)


"""
    
"""
def user_custom_file_delete(id):
    
    option = UserCustomField.get_by_id(id)

    if option is None:
        raise ObjectNotFound('User custom field not exist')

    option.delete()
    resp = user_custom_schema.dump(option)
    return jsonify(resp), 200
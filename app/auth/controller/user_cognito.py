###############################################
# File name: user_cognito.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
import boto3
import botocore
import os
from datetime import datetime
from flask import request, Blueprint
from flask import request, jsonify, abort
from flask_jwt_extended import jwt_required

import jwt

from app import get_jwt_key
from app.auth.controller.auth import olclient
from app.auth.schemas.user_schema import UserSchema
from app.auth.schemas.user_schema_post import UserSchemaPost
from app.auth.utils.function_object import get_user, get_user_email
from app.common.audit import jsonify_audit
from app.common.security import has_permission
from app.auth.models.user import User

user_cognito_bp = Blueprint('user_cognito_bp', __name__)


def client():
    region_named = os.environ['AWS_DEFAULT_REGION']
    client = boto3.client('sesv2',
                      region_name=region_named)
    return client

def cloudw():
    region_named = os.environ['AWS_DEFAULT_REGION']
    cloudW = boto3.client("cloudwatch", region_name=region_named)
    return cloudW

user_schema = UserSchema()
user_schema_post = UserSchemaPost()

def variable_OL():
    OL = os.environ['OL']
    return OL

def variable_Userpool():
    userpool = os.environ['USERPOOL']
    return userpool



@user_cognito_bp.route("/mfa_preference", methods=["POST"])
def mfa_preference():
    """  API to select the method preferred of MFA
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: AccessToken
        in: path
        type: string
        required: true
      - name: smsEnable
        in: path
        type: string
        required: true
      - name: smsPreferred
        in: path
        type: string
        required: true
      - name: softwareEnable
        in: path
        type: string
        required: true
      - name: softwarePreferred
        in: path
        type: string
        required: true
    responses:
      200:
        description: This API doesn't return anything, just setup the MFA preference in Cognito
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "accessToken": "string",
                "smsEnable" : "string",
                "smsPreferred" : "string",
                "softwareEnable" : "string",
                "softwarePreferred" : "string"
            }
    """
    jsondata = request.get_json()
    # We need to yes/no frame to select the user MFA preference
    access_token = jsondata["accessToken"]
    SMSEnable = bool(jsondata["smsEnable"])
    SMSPreferred = bool(jsondata["smsPreferred"])
    SoftwareEnable = bool(jsondata["softwareEnable"])
    SoftwarePreferred = bool(jsondata["softwarePreferred"])
    
    OLClient = olclient()
    response = OLClient.set_user_mfa_preference(
        AccessToken=access_token,
        SMSMfaSettings={
            'Enabled': SMSEnable,
            'PreferredMfa': SMSPreferred
        },
        SoftwareTokenMfaSettings={
            'Enabled': SoftwareEnable,
            'PreferredMfa': SoftwarePreferred
        }
    )

    return response




# change_password (This API will be used only inside OL website)


@user_cognito_bp.route("/change_password", methods=["POST"])
def change_password():
    """  Changes the password for a specified user in a user pool.
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: PreviousPassword
        in: json
        type: string
        required: true
      - name: ProposedPassword
        in: json
        type: string
        required: true
      - name: AccessToken
        in: json
        type: string
        required: true
    responses:
      200:
        description: The response from the server to the change password request.
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "accessToken": "string",
                "prev_password": "string",
                "new_password": "string"
            }
    """
    jsondata = request.get_json()
    access_token = jsondata["accessToken"]
    prev_password = jsondata["prev_password"]
    new_password = jsondata["new_password"]
    
    OLClient = olclient()
    response = OLClient.change_password(
        PreviousPassword=prev_password,
        ProposedPassword=new_password,
        AccessToken=access_token,
    )
    print("change password")
    return response



@user_cognito_bp.route("/update_attribute", methods=["POST"])
def update_user_attribute():
    """  Allows to OL get information if the user exist or not, if user exist this will return an 200, if not, this will return an 400 with bad request.
    ---
    tags:
      - OL Website
    parameters:
      - name: Email
        in: json
        type: string
        required: true
      - name: Attributes
        in: json
        type: string
    responses:
      200:
        description: This API update user attributes inside the cognito user pool .
        examples:
          application/json:
            {
                "email": "string",
                "attributes": "string concat with name of attribute; value"
            }
    """
    data = request.get_json()
    user_id = data["email"]
    data2 = {'phone':data["phone"],'email':data["email"]}
    user = get_user_email(user_id)
    user_dict = user_schema_post.load(data2)
    #lista_attributess = []
    if 'phone' in user_dict:
        user.phone = user_dict['phone']
    userpool = variable_Userpool()
    OL = variable_OL()    
    OLClient = olclient()
    try:
        jsondata = request.get_json()
        username = jsondata['email']
        attributes = jsondata["attributes"].split(";")
        lista_attributes = []
        for a in range(0, len(attributes), 2):
            print(attributes[a])
            dictionario = {
                "Name": attributes[a],
                "Value": attributes[a + 1]
            }
            lista_attributes.append(dictionario)
        # print(type([attribute_final]),[attribute_final])
        response = OLClient.admin_update_user_attributes(
            UserPoolId=userpool,
            Username=username,
            UserAttributes=lista_attributes
        )
        user.save()
        resp = user_schema.dump(user)
        return jsonify(resp), 201
    except OLClient.exceptions.UserNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UserNotFoundException"), 400
    except OLClient.exceptions.UnexpectedLambdaException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UnexpectedLambdaException"), 400
    except OLClient.exceptions.InvalidParameterException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="InvalidParameterException"), 400


@user_cognito_bp.route("/send_email", methods=["POST"])
def send_email():
    CHARSET = "UTF-8"
    jsondata = request.get_json()
    # We need to yes/no frame to select the user MFA preference
    email = jsondata["email"]
    subject = jsondata["subject"]
    email_message = jsondata["email_message"]
    html = '<html>'+email_message+'</html>'
    client = client()
    response = client.send_email(
        FromEmailAddress='HensallLoginSupport@hdc.on.ca',
        Destination={
            'ToAddresses': [
                email,
            ]
        },
        Content={
            'Simple': {
                'Subject': {
                    'Data': subject,
                    'Charset': CHARSET
                },
                'Body': {
                    "Html": {
                      "Charset": CHARSET,
                      "Data": html
                    },

                }
            }
        }
    )
    resp = {
        'msg': 'Email sended'
    }
    return jsonify(resp)


@user_cognito_bp.route("/token_verification", methods=['POST'])
def verification_access_token():
    """  API to Hensall application verify the Token provided by OL website  
    This is using docstrings for specifications.
    ---
    tags:
      - Hensall application
    parameters:
      - name: AccessToken
        in: json
        type: string
        required: true
    responses:
      200:
        description: Represents the response from the server from the request to get information about the user.
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "accessToken": "string"
            }
      5xx:
        description: This error means that the token is invalid or expired
    """
    try:
        jsondata = request.get_json()
        access_token = jsondata["accessToken"]
        OLClient = olclient()
        response = OLClient.get_user(
            AccessToken=access_token
        )
        return response
    except:
        verification_jwt_token(request)


#Delete user function new
@user_cognito_bp.route("/delete_user", methods=['POST'])
@has_permission(["USER_ADM"])
def delete_user():
    """  API to delete user from Cognito by OL website  
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: email
        in: path
        type: string
        required: true
    responses:
      200:
        description: Represents the response from the server from the request to get information about the user.
        schema:
          $ref: '#/definitions/init'

      5xx:
        description: This error means that the token is invalid or expired
    """
    userpool = variable_Userpool()
    OL = variable_OL()
    OLClient = olclient()
    try:
        jsondata = request.get_json()
        username = jsondata["email"]
        response = OLClient.admin_disable_user(
            UserPoolId=userpool,
            Username=username
        )
        if (response["ResponseMetadata"]["HTTPStatusCode"]==200):
          try:
            response2 = OLClient.admin_delete_user(
                UserPoolId=userpool,
                Username=username
            )
            return response2
          except:
            return jsonify({"msg": "User not disable"}), 403
        else:
          return response
    except:
        return jsonify({"msg": "Invalid or expired token"}), 403
    

@user_cognito_bp.route("/disable_user", methods=['POST'])
@has_permission(["USER_ADM"])
def disable_cognito_user():
    userpool = variable_Userpool()
    OLClient = olclient()
    try:
        jsondata = request.get_json()
        username = jsondata["email"]
        response = OLClient.admin_disable_user(
            UserPoolId=userpool,
            Username=username
        )
        print(f"User {username} has been disabled in user pool.")
        return jsonify_audit({"msg": "User disable"}), 200
    except client.exceptions.UserNotFoundException as e:
        print(f"User {username} does not exist in user pool.")
        return jsonify_audit(message=str(e), err="UserNotFoundException"), 400
    except client.exceptions.InvalidParameterException as e:
        print(f"An error occurred: {e}")
        return jsonify_audit(message=str(e), err="InvalidParameterException"), 400
    
@user_cognito_bp.route("/enable_user", methods=['POST'])
@has_permission(["USER_ADM"])
def enable_cognito_user():
    userpool = variable_Userpool()
    OLClient = olclient()
    try:
        jsondata = request.get_json()
        username = jsondata["email"]
        response = OLClient.admin_enable_user(
            UserPoolId=userpool,
            Username=username
        )
        print(f"User {username} has been enable in user pool.")
        return jsonify_audit({"msg": "User enable"}), 200
    except client.exceptions.UserNotFoundException as e:
        print(f"User {username} does not exist in user pool.")
        return jsonify_audit(message=str(e), err="UserNotFoundException"), 400
    except client.exceptions.InvalidParameterException as e:
        print(f"An error occurred: {e}")
        return jsonify_audit(message=str(e), err="InvalidParameterException"), 400


@user_cognito_bp.route("/get_metrics", methods=['POST'])
@has_permission(["USER_ADM"])
def get_metrics():
  userpool = variable_Userpool()
  OL = variable_OL()
  jsondata = request.get_json()
  # We need to yes/no frame to select the user MFA preference
  id = jsondata["Id"]
  MetricName = jsondata["MetricName"]
  starTime = jsondata["StartTime"]
  enTime = jsondata["EndTime"]
  namespac = jsondata["Namespace"]  
  starTime = starTime.split("-")
  enTime = enTime.split("-")
  period = jsondata["Period"]
  cloudW = cloudw()
  try:
    response = cloudW.get_metric_data(
        MetricDataQueries=[#required
            {
                'Id': id, #Required
                'MetricStat': {
                    'Metric': {#required
                        'Namespace': namespac,
                        'MetricName': MetricName,
                        'Dimensions': [ #Required
                            {
                                'Name': 'UserPool',
                                'Value': userpool
                            },
                            {
                                "Name": "UserPoolClient",
                                "Value": OL
                              }
                        ]
                    },
                    'Period': period,#Required
                    'Stat': 'Sum' #Required
                    #'Unit': 'Seconds'|'Microseconds'|'Milliseconds'|'Bytes'|'Kilobytes'|'Megabytes'|'Gigabytes'|'Terabytes'|'Bits'|'Kilobits'|'Megabits'|'Gigabits'|'Terabits'|'Percent'|'Count'|'Bytes/Second'|'Kilobytes/Second'|'Megabytes/Second'|'Gigabytes/Second'|'Terabytes/Second'|'Bits/Second'|'Kilobits/Second'|'Megabits/Second'|'Gigabits/Second'|'Terabits/Second'|'Count/Second'|'None'
                },
                #'Expression': 'string',
                #'Label': 'string',
                #'ReturnData': True|False,
                #'Period': 123,
                #'AccountId': 'string'
            },
        ],
        StartTime=datetime(int(starTime[0]), int(starTime[1]), int(starTime[2])),#Required
        EndTime=datetime(int(enTime[0]), int(enTime[1]), int(enTime[2])),#Required
        #NextToken='string',
        #ScanBy='TimestampDescending'|'TimestampAscending',
        #MaxDatapoints=123,
        #LabelOptions={
        #    'Timezone': 'string'
        #}
      )
    return response
  except Exception as e:
        return jsonify({"msg": "Invalid or expired token"}), 403

def verification_jwt_token(request):
    """  API to Hensall application verify the Token provided by OL website
    This is using docstrings for specifications.
    ---
    tags:
      - Hensall application
    parameters:
      - name: AccessToken
        in: json
        type: string
        required: true
    responses:
      200:
        description: Represents the response from the server from the request to get information about the user.
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "accessToken": "string"
            }
      5xx:
        description: This error means that the token is invalid or expired
    """
    try:
        jsondata = request.get_json()
        access_token = jsondata["accessToken"]

        jwt_key = get_jwt_key()['JWT_SECRET_KEY']
        decoded_token = jwt.decode(access_token, key=jwt_key, algorithms=["HS256"])

        # Obtener el 'sub' del token decodificado
        email = decoded_token.get("sub")

        data = generate_json(email)
        response = jsonify(data)

        return response
    except Exception as e:
        return jsonify({"msg": "Invalid or expired token"}), 403
    

def generate_json(email):
    
    current_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    user = User.simple_filter_unique(email = email)

    if user is None:
        return jsonify({"msg": "User not exist in database"}), 401

    data = {
        "Username": "04238da5-30a2-4e8a-a1f0-dd79e1d71be4",
        "UserAttributes": [
            {
                "Name": "sub",
                "Value": "04238da5-30a2-4e8a-a1f0-dd79e1d71be4"
            },
            {
                "Name": "email_verified",
                "Value": "True"
            },
            {
                "Name": "phone_number_verified",
                "Value": "True"
            },
            {
                "Name": "phone_number",
                "Value": user.phone
            },
            {
                "Name": "email",
                "Value": email
            }
        ],
        "PreferredMfaSetting": "SMS_MFA",
        "UserMFASettingList": [
            "SMS_MFA"
        ],
        "ResponseMetadata": {
            "RequestId": "97cdec40-5ebd-4a82-956b-ee6f81f73812",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": current_date,
                "content-type": "application/x-amz-json-1.1",
                "content-length": "387",
                "connection": "keep-alive",
                "x-amzn-requestid": "97cdec40-5ebd-4a82-956b-ee6f81f73812"
            },
            "RetryAttempts": 0
        }
    }

    return data
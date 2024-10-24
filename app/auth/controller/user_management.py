###############################################
# File name: user_management.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
import boto3
import botocore
import json
import os
import random
import regex as re
import requests
import string
from flask import request, Blueprint
from flask import request, jsonify, abort

from app.auth.controller.auth import olclient
from app.common.limiter import limiter


def variable_OL():
    OL = os.environ['OL']
    return OL

def variable_Userpool():
    userpool = os.environ['USERPOOL']
    return userpool

def variable_zero():
    zero = os.environ['KEYZEROB']
    return zero

from app.common.security import has_permission

user_management_bp = Blueprint('user_management_bp', __name__)








@user_management_bp.route("/add_user_group", methods=['POST'])
def add_user_group():
    """  Example add user to group
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: email
        in: path
        type: string
        required: true
      - name: groups
        in: path
        type: string
        required: true
    responses:
      200:
        description: We update groups to an specific user
        examples:
          application/json:
            {
                "email": "string",
                "groups": "string of groupsseparated by comma"
            }
    """
    userpool = variable_Userpool()
    try:
        jsondata = request.get_json()
        username = jsondata['email']
        groups = jsondata["groups"].split(",")
        
        OLClient = olclient()
        for a in groups:
            response = OLClient.admin_add_user_to_group(
                UserPoolId=userpool,
                Username=username,
                GroupName=a
            )
        return response
    except OLClient.exceptions.UserNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UserNotFoundException"), 400
    except OLClient.exceptions.NotAuthorizedException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="NotAuthorizedException"), 400
    except OLClient.exceptions.ResourceNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="ResourceNotFoundException"), 500


@user_management_bp.route("/verify_email", methods=['POST'])
def verify_email():
    """  Example verify email API
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
        description: We verify email
        examples:
          application/json:
            {
                "email": "string"
            }
    """
    try:
        jsondata = request.get_json()
        username = jsondata['email']
        regex = re.compile("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")

        if (regex.match(username)):
            return jsonify(message="OK"), 200
        else:
            return jsonify(message="It isn't an email", err="Invalid Email syntax"), 400
    except Exception  as e:
        error_str = str(e)
        return jsonify(message=error_str, err="Invalid Email syntax"), 400



@user_management_bp.route("/exist_user", methods=["POST"])
@limiter.limit("20/hour")
def exist_user():
    """  Allows to OL get information if the user exist or not, if user exist this will return an 200, if not, this will return an 400 with bad request.
    ---
    tags:
      - OL Website
    parameters:
      - name: body
        in: body
        required: true
    responses:
      200:
        description: This API return if the user exist or not, this should help to know if the user is inside the cognito user pool .
        examples:
          application/json:
            {
                "email": "string"
            }
    """
    userpool = variable_Userpool()
    jsondata = request.get_json()
    username = jsondata['email']
    validmail, substatus = validator(username)
    #return the sub-status variable
    #send it with error message the sub-status
    
    OLClient = olclient()
    if validmail:
        try:

            response = OLClient.admin_get_user(
                UserPoolId=userpool,
                Username=username,
            )
            return jsonify({"msg": "ok"}), 200

        except OLClient.exceptions.UserNotFoundException as e:
            error_str = str(e)
            return jsonify(message=error_str, err="UserNotFoundException"), 400
    else:
        return jsonify(message = substatus, err="Invalid email"), 403


@user_management_bp.route("/check_email", methods=["POST"])
@limiter.limit("20/hour")
def check_user():
    """  Allows to OL get information if the user exist or not, if user exist this will return an 200, if not, this will return an 400 with bad request.
    ---
    tags:
      - OL Website
    parameters:
      - name: body
        in: body
        required: true
    responses:
      200:
        description: This API return if the user exist or not, this should help to know if the user is inside the cognito user pool .
        examples:
          application/json:
            {
                "email": "string"
            }
    """
    userpool = variable_Userpool()
    jsondata = request.get_json()
    username = jsondata['email']
    validmail, substatus = validator(username)
    #return the sub-status variable
    #send it with error message the sub-status
    
    OLClient = olclient()
    if validmail:
        try:

            response = OLClient.admin_get_user(
                UserPoolId=userpool,
                Username=username,
            )
            if response["UserStatus"]=='FORCE_CHANGE_PASSWORD':
                Password_change = set_password(username)
                print(Password_change)
                return jsonify({"msg": "ok"}), 200
            else:
                return jsonify({"msg": "ok"}), 200
        except OLClient.exceptions.UserNotFoundException as e:
            error_str = str(e)
            return jsonify(message=error_str, err="UserNotFoundException"), 400
    else:
        return jsonify(message = substatus, err="Invalid email"), 403

@user_management_bp.route("/create_user", methods=['POST'])
@has_permission(["USER_ADM"])
def create_user():
    """  Example create user in Cognito
    This is using docstrings for specifications.
    ---
    tags:
      - Prisma
    parameters:
      - name: body
        in: body
        required: true
    responses:
      200:
        description: We update groups to an specific user
        examples:
          application/json:
            {
                "email": "string",
                "phone_number":"string",
                "deliveryMediums" : "'SMS' or 'EMAIL'"
            }
    """

    jsondata = request.get_json()
    username = jsondata['email']
    phone_number = jsondata['phone_number']
    delivery = jsondata['deliveryMediums']
    
    response = create_user_cognito(username, phone_number, delivery=delivery)

    return response


def create_user_cognito(username, phone_number, delivery="EMAIL"):
    userpool = variable_Userpool()
    try:
        
        OLClient = olclient()
        response = OLClient.admin_create_user(
            UserPoolId=userpool,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': username
                },
                {
                    'Name': 'email_verified',
                    'Value': 'True'
                },
                {
                    'Name': 'phone_number',
                    'Value': phone_number
                },  # Phone Number will be required by Hensall to insert new user?
                {
                    'Name': 'phone_number_verified',
                    'Value': 'True'
                },
            ],
            DesiredDeliveryMediums=[
                delivery,
            ]
        )
        return jsonify(response),200
    except OLClient.exceptions.UsernameExistsException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UsernameExistsException"), 400
    except OLClient.exceptions.NotAuthorizedException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="NotAuthorizedException"), 400
    except OLClient.exceptions.ResourceNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="ResourceNotFoundException"), 500


def create_user_cognito2(username, delivery="EMAIL"):
    userpool = variable_Userpool()
    try:
        
        OLClient = olclient()
        response = OLClient.admin_create_user(
            UserPoolId=userpool,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': username
                },
                {
                    'Name': 'email_verified',
                    'Value': 'True'
                },
            ],
            DesiredDeliveryMediums=[
                delivery,
            ]
        )
        return jsonify(response),200
    except OLClient.exceptions.UsernameExistsException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UsernameExistsException"), 400
    except OLClient.exceptions.NotAuthorizedException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="NotAuthorizedException"), 400
    except OLClient.exceptions.ResourceNotFoundException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="ResourceNotFoundException"), 500



def validator(mail):
    url = "https://api.zerobounce.net/v2/validate"
    api_key = variable_zero()
    email = mail
    ip_address = request.remote_addr #ip_address can be blank
    params = {"email": email, "api_key": api_key, "ip_address":ip_address}
    
    response = requests.get(url, params=params)
    resp = json.loads(response.content)
    valid = None
    substatus = resp["sub_status"]
    if resp["status"] == "valid" or resp["status"]=="catch-all":
        valid = True
    else:
        valid = False
    # Catch-All
    return valid, substatus

def set_password(username):
    region_name = os.environ['AWS_DEFAULT_REGION']
    userpool = os.environ['USERPOOL']
    characters = string.ascii_letters + string.digits + "^$*.[]}{()?!@#%&/\,><':;|_~`=+-"
    while True:
        password_temp = ''.join(random.choice(characters) for i in range(8))
        if (any(c.islower() for c in password_temp) and any(c.isupper() for c in password_temp) and any(char in "^$*.[]}{()?!@#%&/\,><':;|_~`=+-" for char in password_temp) and any(c.isdigit() for c in password_temp)):
                break
    password = password_temp

    try:
        ClientInt = boto3.client('cognito-idp', region_name=region_name)
        response = ClientInt.admin_set_user_password(
            UserPoolId=userpool,
            Username=username,
            Password= password,
            Permanent=True            
        )
        return response
    except ClientInt.exceptions.UsernameExistsException as e:
        error_str = str(e)
        return jsonify(message=error_str, err="UsernameExistsException"), 400
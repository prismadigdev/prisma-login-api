###############################################
# File name: user_auth.py
# This is a product created by PRISMA DIGITAL LLC. for Hensall CO-OP 
# Description: This file contains the APIs of UAM module, for OneLogin App
# Created by: Carlos Sebastian Gomez and Carlos René Angarita
# Date: 17/02/2023
###############################################
import boto3
import botocore
import os
from flask import request, Blueprint
from flask import request, jsonify, abort

from app.auth.controller.auth import olclient
from app.auth.service.user import create_token
from app.common.limiter import limiter

user_auth_bp = Blueprint('user_auth_bp', __name__)




def variable_OL():
    OL = os.environ['OL']
    return OL

def variable_Userpool():
    userpool = os.environ['USERPOOL']
    return userpool


@user_auth_bp.route("/test", methods=["GET"])
def test():
    """ Example Endpoint to test the API is working
    This is using docstrings for specifications.
    ---
    parameters:
      - name: username
        in: path
        type: string
    definitions:
      Palette:
        type: object
        properties:
          palette_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A testing response with string in response
        schema:
          $ref: '#/definitions/Palette'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    return "Hola estoy probando"


# Authflow (iniciar sesiÃ³n)


@user_auth_bp.route("/init", methods=['POST'])
def init_auth():
    """  Example login API
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: email
        in: path
        type: string
        required: true
      - name: password
        in: path
        type: string
        required: true
    responses:
      200:
        description: We get the authentication result and access tokens
        examples:
          application/json:
            {
                "username": "string",
                "password": "string"
            }
    """
    OL = variable_OL()
    try:
         
        OLClient = olclient()
        jsondata = request.get_json()
        username = jsondata["email"]
        password = jsondata["password"]
        response = OLClient.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password},
            ClientId=OL,
        )

        # Now we recive a 'NEW_PASSWORD_REQUIRED' challenge
        if 'ChallengeName' in response:
            if response['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
                # Redirect to first login view (change temp password)
                return (response)
            elif response['ChallengeName'] == "SOFTWARE_TOKEN_MFA":
                # Guardar la SesiÃ³n y el ChallengeName
                return response
            elif response['ChallengeName'] == "SMS_MFA":
                return response
            elif response['ChallengeName'] == "MFA_SETUP":
                return response

        return (response)
    except:
        abort(401, description="Incorrect username or password")


# Forgot password API
@user_auth_bp.route("/forgot_password", methods=["POST"])
@limiter.limit("20/hour")
def forget_password():
    """  Example API to send code to restart password
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: email
        in: path
        type: string
        required: true

        schema:
            type: JSON
            example: "email.test@template.com"
    responses:
      200:
        description: We send a code to email registred in Cognito
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "email": "string"
            }
    """
    OL = variable_OL()
    try:
        jsondata = request.get_json()
        username = jsondata["email"]
         
        OLClient = olclient()
        response = OLClient.forgot_password(
            ClientId=OL,
            Username=username,

        )
        print("An email has been sent with verification code")
        return response
    except OLClient.exceptions.ResourceNotFoundException as e:
        return jsonify({"msg": "ResourceNotFoundException"}), 401
    except OLClient.exceptions.InvalidParameterException as e:
        return jsonify({"msg": "InvalidParameterException"}), 401
    except Exception as e:
        return jsonify({"msg": "Incorrect username or password"}), 403


# Get user (get user info from Access token)
def get_user(token):
     
    OLClient = olclient()
    if token != "":
        response = OLClient.get_user(AccessToken=token)

        # printing user info
        print(response['UserAttributes']),

    return ("Not logged in. Please sign in...")


# MFA token comparison


# Seting up MFA for specific user
def associate_software_token(accessToken):
    if accessToken != '':
        """ response = OLClient.set_user_mfa_preference(
            SMSMfaSettings={
                'Enabled': False,
                'PreferredMfa': False
            },
            SoftwareTokenMfaSettings={
                'Enabled': True,
                'PreferredMfa': True
            },
            Username="jdop2000@gmail.com",
            UserPoolId ="us-east-1_zoId0epNt")
        print("-----------------------------------------------------------------") 
        return response """
        print("Asosiate sftwr_token ---------------------> ", accessToken)
         
        OLClient = olclient()
        response = OLClient.associate_software_token(
            AccessToken=accessToken)
        return (response)
    return None


# Verification_software Token


@user_auth_bp.route("/verify_token", methods=["POST"])
def verify_token():
    """  Example API verify code of MFA application (Google authenticator, Authy)
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: usercode
        in: path
        type: string
        required: true
        description: A unique generated shared secret code that is used in the time-based one-time password (TOTP) algorithm to generate a one-time code.
        schema:
            type: JSON
            example: "123456"
    responses:
      200:
        description: We send a code to email registred in Cognito
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "user_code": "string",
                "accessToken": "string"
            }
    """
    jsondata = request.get_json()
    usercode = jsondata["user_code"]
    access_token = jsondata["accessToken"]
     
    OLClient = olclient()
    response = OLClient.verify_software_token(
        AccessToken=access_token,
        UserCode=usercode
    )
    print("VerifyToken")
    return response


#
# Verification_software Token First time OL First time


@user_auth_bp.route("/verify_token_ft", methods=["POST"])
def verify_token_ft():
    """  Example API verify code of MFA application (Google authenticator, Authy)
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: usercode
        in: path
        type: string
        required: true
        description: A unique generated shared secret code that is used in the time-based one-time password (TOTP) algorithm to generate a one-time code.
        schema:
            type: JSON
            example: "123456"
      - name: session
        in: path
        type: string
        required: true
        description: The session that should be passed both ways in challenge-response calls to the service.
    responses:
      200:
        description: We send a code to email registred in Cognito
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "user_code": "string",
                "session": "string"
            }
    """
    jsondata = request.get_json()
    usercode = jsondata["user_code"]
    session = jsondata["session"]
     
    OLClient = olclient()
    response = OLClient.verify_software_token(
        Session=session,
        UserCode=usercode
    )
    print("VerifyToken")
    return response


# resend token


@user_auth_bp.route("/resend_code", methods=["POST"])
def resend_token():
    """  Example API that resend the code to the email, this should be necessary if the user doesn't recive the code.
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: Email
        in: path
        type: string
        required: true
    responses:
      200:
        description: We send a code to email registred in Cognito
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "email": "string"
            }
    """
    OL = variable_OL()
    jsondata = request.get_json()
     
    OLClient = olclient()
    response = OLClient.resend_confirmation_code(
        ClientId=OL,
        Username=jsondata["email"],
    )
    print("resendToken")
    return response


# associate_software_token
@user_auth_bp.route("/software_token", methods=["POST"])
def software_token():
    """  Example to get token to add an application of TOTP
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: AccessToken
        in: path
        type: string
        required: true
    responses:
      200:
        description: We return an secret code that user must to add on authentication application to get TOTP
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "accessToken": "string",
            }
    """
    try:
      jsondata = request.get_json()
      access_token = jsondata["accessToken"]
       
      OLClient = olclient()
      response = OLClient.associate_software_token(
          AccessToken=access_token,
      )
      print("software token")
      return response
    except OLClient.exceptions.SoftwareTokenMFANotFoundException as e:
        return jsonify({"msg": "SoftwareTokenMFANotFoundException"}), 401
    except OLClient.exceptions.ResourceNotFoundException as e:
        return jsonify({"msg": "ResourceNotFoundException"}), 401
    except OLClient.exceptions.NotAuthorizedException as e:
        return jsonify({"msg": "NotAuthorizedException"}), 401
    except:
        return jsonify({"msg": "Associate software token error"}), 400



# associate_software_token First time
# Primer link para configurar el MFA Session
@user_auth_bp.route("/software_token_ft", methods=["POST"])
def software_token_ft():
    """  API to get token to add an application of TOTP first time setup
    This is using docstrings for specifications.
    ---
    parameters:
      - name: Session
        in: path
        type: string
        required: true
    responses:
      200:
        description: Secret Code to fill in the authentication application
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "session": "string",
            }
    """
    jsondata = request.get_json()
    session = jsondata["session"]
     
    OLClient = olclient()
    response = OLClient.associate_software_token(
        Session=session,
    )
    print("software token")
    print(response["SecretCode"])
    return response


# After creating user form console, respond authentication challenge
# (NEW_PASSWORD_REQUIRED, MFA_SETUP, etc)
@user_auth_bp.route("/respond_to_auth_challenge", methods=['POST'])
def respond_to_auth_challenge():
    """  Respond to auth challenge
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: Challenge
        in: json
        type: string
        required: true
      - name: Username Cognito
        in: json
        type: string
        required: true
      - name: NewPassword
        in: json
        type: string
        required: true
      - name: Session
        in: json
        type: string
        required: true
      - name: user_code
        in: json
        type: string
        required: true

    responses:
      200:
        description: The response to respond to the authentication challenge.
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            NEW_PASSWORD_REQUIRED:
                {
                    "challenge": "string",
                    "username": "string",
                    "new_password": "string",
                    "session": "string"
                }
            SOFTWARE_TOKEN_MFA:
                {
                    "challenge": "string",
                    "username": "string",
                    "user_code": "string",
                    "session": "string"
                }
            MFA_SETUP:
                {
                    "challenge": "string",
                    "username": "string",
                    "session": "string"
                }
            SMS_MFA:
                {
                    "challenge": "string",
                    "username": "string",
                    "user_code": "string",
                    "session": "string"
                }
            SELECT_MFA_TYPE:
                {
                    "challenge": "string",
                    "username": "string",
                    "choice": "string"
                }
    """
    userpool = variable_Userpool()
    OL = variable_OL()
    challenges = ['SOFTWARE_TOKEN_MFA', 'MFA_SETUP',
                  'NEW_PASSWORD_REQUIRED', "SMS_MFA", "SELECT_MFA_TYPE"]
    try:
        jsondata = request.get_json()
        challenge = jsondata['challenge']
         
        OLClient = olclient()

        if challenge in challenges:
            if challenge == 'NEW_PASSWORD_REQUIRED':

                username = jsondata['username']
                new_password = jsondata['new_password']
                init_session = jsondata['session']

                response = OLClient.respond_to_auth_challenge(
                    ClientId=OL,
                    ChallengeName=challenge,
                    ChallengeResponses={'USERNAME': username,
                                        'NEW_PASSWORD': new_password},
                    Session=init_session
                )

                if 'AuthenticationResult' in response:
                    AcsToken = response['AuthenticationResult']['AccessToken']

                return (response)
            elif challenge == "SOFTWARE_TOKEN_MFA":
                username = jsondata["username"]
                session = jsondata["session"]
                usercode = jsondata["user_code"]
                response = OLClient.respond_to_auth_challenge(
                    ClientId=OL,
                    ChallengeName="SOFTWARE_TOKEN_MFA",
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'SOFTWARE_TOKEN_MFA_CODE': usercode},
                )
                return create_token(response)
            elif challenge == "SMS_MFA":
                username = jsondata["username"]
                session = jsondata["session"]
                usercode = jsondata["user_code"]
                response = OLClient.respond_to_auth_challenge(
                    ClientId=OL,
                    ChallengeName="SMS_MFA",
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username,
                        'SMS_MFA_CODE': usercode},
                )
                return create_token(response)
                #return (response)
            elif challenge == "MFA_SETUP":
                jsondata = request.get_json()
                username = jsondata["username"]
                session = jsondata["session"]
                response = OLClient.respond_to_auth_challenge(
                    ClientId=OL,
                    ChallengeName="MFA_SETUP",
                    Session=session,
                    ChallengeResponses={
                        'USERNAME': username},
                )
                print("----- Challenge respond -----")
                return (response)
            elif challenge == "SELECT_MFA_TYPE":
                jsondata = request.get_json()
                # We need to yes/no frame to select the user MFA preference
                username = jsondata["username"]
                choice = jsondata["choice"]
                if choice == "SMS_MFA":
                    response = OLClient.admin_set_user_mfa_preference(
                        Username=username,
                        UserPoolId=userpool,
                        SMSMfaSettings={
                            'Enabled': True,
                            'PreferredMfa': True
                        },
                        SoftwareTokenMfaSettings={
                            'Enabled': True,
                            'PreferredMfa': False
                        }
                    )
                    return response
                elif choice == "SOFTWARE_TOKEN_MFA":
                    response = OLClient.admin_set_user_mfa_preference(
                        Username=username,
                        UserPoolId=userpool,
                        SMSMfaSettings={
                            'Enabled': True,
                            'PreferredMfa': False
                        },
                        SoftwareTokenMfaSettings={
                            'Enabled': True,
                            'PreferredMfa': True
                        }
                    )
                    return response
            return (None)
    except OLClient.exceptions.ExpiredCodeException as e:
        return jsonify({"msg": "ExpiredCodeException "}), 401
    except OLClient.exceptions.CodeMismatchException as e:
        return jsonify({"msg": "CodeMismatchExeption "}), 401
    except OLClient.exceptions.NotAuthorizedException as e:
        return jsonify({"msg": "NotAuthorizedException"}), 401
    except Exception as e:
        return jsonify({"msg": "Unsolved challenge "}), 403


@user_auth_bp.route("/confirm_forgot_password", methods=["POST"])
def confirm_forgot_password():
    """  Allows a user to enter a confirmation code to reset a forgotten password.
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: Email
        in: json
        type: string
        required: true
      - name: ConfirmationCode
        in: json
        type: string
        required: true
      - name: Password
        in: json
        type: string
        required: true
    responses:
      200:
        description: The response from the server that results from a user's request to retrieve a forgotten password.
        schema:
          $ref: '#/definitions/init'
        examples:
          application/json:
            {
                "email": "string",
                "confirm_code": "string",
                "new_psswrd": "string"
            }
    """
    OL = variable_OL()
     
    OLClient = olclient()
    try:
        jsondata = request.get_json()
        username = jsondata['email']
        confirm_code = jsondata['confirm_code']
        new_psswrd = jsondata['new_psswrd']

        response = OLClient.confirm_forgot_password(
            ClientId=OL,
            Username=username,
            ConfirmationCode=confirm_code,
            Password=new_psswrd)
        print("success")
        return response
    except OLClient.exceptions.CodeMismatchException as e:
        return jsonify({"msg": "CodeMismatchExeption"}), 401
    except OLClient.exceptions.InvalidPasswordException as e:
        return jsonify({"msg": "InvalidPasswordException"}), 401
    except OLClient.exceptions.NotAuthorizedException as e:
        return jsonify({"msg": "NotAuthorizedException"}), 401
    except:
        return jsonify({"msg": "Error"}), 400

@user_auth_bp.route("/mfa_preference", methods=["POST"])
def mfa_preference():
    """  API to select the method preferred of MFA with Username or email
    This is using docstrings for specifications.
    ---
    tags:
      - OL Website
    parameters:
      - name: email
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
                "email": "string",
                "smsEnable" : "string",
                "smsPreferred" : "string",
                "softwareEnable" : "string",
                "softwarePreferred" : "string"
            }
    """
    userpool = variable_Userpool()
    OL = variable_OL()
    jsondata = request.get_json()
     
    OLClient = olclient()
    # We need to yes/no frame to select the user MFA preference
    username = jsondata["email"]
    SMSEnable = bool(jsondata["smsEnable"])
    SMSPreferred = bool(jsondata["smsPreferred"])
    SoftwareEnable = bool(jsondata["softwareEnable"])
    SoftwarePreferred = bool(jsondata["softwarePreferred"])

    response = OLClient.admin_set_user_mfa_preference(
        Username=username,
        UserPoolId=userpool,
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

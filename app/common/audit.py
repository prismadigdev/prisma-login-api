import asyncio
import json
from datetime import datetime
from flask import jsonify
from flask import request
from flask_jwt_extended import get_jwt
from flask_jwt_extended import verify_jwt_in_request

from app.audit.models.request_service import RequestService


async def audit_request():
    verify_jwt_in_request()
    claims = get_jwt()
    user = claims["sub"]
    data = ""
    json_data = request.get_json(silent=True)
    if json_data is not None:
        data = str(json_data)
    request_service = RequestService(uuid=hash(request), date_operation=datetime.today(),
                                     url=request.url, data=data,
                                     type="request", method_operation=request.method,
                                     user_operation=user, endpoint=request.endpoint,
                                     system="Hensall Login", process="", status="200")

    request_service.save()
    return True


async def audit_response(info, status=200):
    verify_jwt_in_request()
    claims = get_jwt()
    user = claims["sub"]
    request_service = RequestService(uuid=hash(request), date_operation=datetime.today(),
                                     url=request.url, data=info,
                                     type="response", method_operation=request.method,
                                     user_operation=user, endpoint=request.endpoint,
                                     system="Hensall Login", process="", status=status)

    request_service.save()
    return True


async def audit_request_login():

    json_data = request.get_json(silent=True)
    user = ""
    if json_data is not None:
        user = request.json.get("email", "")


    request_service = RequestService(uuid=hash(request), date_operation=datetime.today(),
                                     url=request.url, data="",
                                     type="request", method_operation=request.method,
                                     user_operation=user, endpoint=request.endpoint,
                                     system="Hensall Login", process="", status="200")

    request_service.save()
    return True


async def audit_response_login(data="", status=200):
    user = ""

    request_service = RequestService(uuid=hash(request), date_operation=datetime.today(),
                                     url=request.url, data=str(data),
                                     type="response", method_operation=request.method,
                                     user_operation=user, endpoint=request.endpoint,
                                     system="Hensall Login", process="", status=status)

    request_service.save()
    return True


def init_audit():
    asyncio.run(audit_request())


def jsonify_audit(data, status=200):
    data_json = str(data)
    info = (data_json[:2000] + '..') if len(data_json) > 2000 else data_json
    asyncio.run(audit_response(info, status))
    response = jsonify(data)
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
    #return jsonify(data)


def login_audit():
    asyncio.run(audit_request_login())


def login_init_audit():
    asyncio.run(audit_request_login())


def end_audit(data, status=200):
    asyncio.run(audit_response_login(data, status))

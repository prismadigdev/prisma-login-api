import os
from flask import Flask, jsonify, request
import boto3, botocore
from flasgger import Swagger, LazyString, LazyJSONEncoder

from app.common.error_handling import ObjectNotFound, AppErrorBaseClass
from app.common.helpers import s3, aws_bucket_name
from app.common.secret_manager import get_database_uri, get_jwt_key
from app.common.limiter import limiter

from app.db import db
from app.ext import ma, migrate, filtr

from flask_jwt_extended import JWTManager

from app.auth.controller.auth import auth_bp
from app.auth.controller.user import users_bp
from app.auth.controller.role import role_bp
from app.auth.controller.option import option_bp
from app.auth.controller.permission import permission_bp
from app.auth.controller.system import system_bp
from app.auth.controller.user import admins_bp
from app.auth.controller.user_auth import user_auth_bp
from app.auth.controller.user_management import user_management_bp
from app.auth.controller.user_cognito import user_cognito_bp
from app.audit.controllers.request_service import request_service_bp
from app.fields.controller.field_controller import field_bp
from app.sso.controller.sso_controller import sso_bp
from flask_jwt_extended import jwt_required
from app.support.controller.health import health_support_bp

from flask_cors import CORS

version = os.environ.get('API_VERSION', 'v1')

prefix = f"/api/{version}"


def create_app(settings_module):
    app = Flask(__name__)
    app.config.from_object(settings_module)

    host = app.config.get('SITE_HOST', 'localhost:5000')

    limiter.init_app(app)

    swagger_template = {
        "info": {
            'title': 'Hensall Login Api Project',
            'version': '0.1',
            'description': 'This document contains the list of API services of the Hensall Login project developed '
                           'with Python.',
        },
        "host": host,
        "static_url_path": "/flasgger_static",
        "static_folder": "login",
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": 'JWT Authorization header using the Bearer scheme. '
                               'Example: "Authorization: Bearer {token}"'
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ]
    }

    os.environ['PROJECT'] = app.config.get('PROJECT')
    os.environ['AWS_PROFILE'] = app.config.get('AWS_PROFILE')
    os.environ['AWS_DEFAULT_REGION'] = app.config.get('AWS_DEFAULT_REGION')

    if not app.config.get('SQLALCHEMY_DATABASE_URI'):
        app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()

    #os.environ['SMTP_KEY'] = app.config.get('SMTP_KEY')
    #os.environ['SMTP_SECRET'] = app.config.get('SMTP_SECRET')
    os.environ['SMTP_HOST'] = app.config.get('SMTP_HOST')
    os.environ['SMTP_FROM'] = app.config.get('SMTP_FROM')

    os.environ['S3_BUCKET'] = app.config.get('S3_BUCKET')
    #os.environ['S3_KEY'] = app.config.get('S3_KEY')
    os.environ['SMTP_HOST'] = app.config.get('SMTP_HOST')

    os.environ['SECURITY'] = app.config.get('SECURITY_ROLE', 'NO')
    os.environ['SECURITY_IP'] = app.config.get('SECURITY_IP', 'NO')

    os.environ['OL'] = app.config.get('OL')
    os.environ['USERPOOL'] = app.config.get('USERPOOL')
    os.environ['KEYZEROB'] = app.config.get('KEYZEROB')
    os.environ['RECAPTCHA'] = app.config.get('RECAPTCHA')

    CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": app.config.get('CORS')},
                                                    f'{prefix}/auth/init/*': {"origins": "*"}})
    # Inicializa las extensiones
    swagger = Swagger(app, template=swagger_template, decorators=[jwt_required()])
    # app.config['SQLALCHEMY_DATABASE_URI'] =
    # 'postgresql://postgres:Aelm2022@database-2.cr5kiddvokid.us-east-2.rds.amazonaws.com:5432/hensall'

    db.init_app(app)
    ma.init_app(app)
    filtr.init_app(app)
    migrate.init_app(app, db)

    jwt_key = get_jwt_key()

    if jwt_key:
        app.config["JWT_SECRET_KEY"] = get_jwt_key()['JWT_SECRET_KEY']
    else:
        app.config["JWT_SECRET_KEY"] = "H3ns4llOn3Log1n*"

    os.environ['SMTP_HOST'] = app.config["JWT_SECRET_KEY"]

    jwt = JWTManager(app)

    # Captura todos los errores 404
    # Api(app, '/api/v1.0/customers', catch_all_404s=True)

    # Deshabilita el modo estricto de acabado de una URL con /
    app.url_map.strict_slashes = False

    # Registra los blueprints

    app.register_blueprint(auth_bp, url_prefix=f'{prefix}/auth')

    app.register_blueprint(users_bp, url_prefix=f'{prefix}/users')
    app.register_blueprint(role_bp, url_prefix=f'{prefix}/roles')
    app.register_blueprint(option_bp, url_prefix=f'{prefix}/options')
    app.register_blueprint(permission_bp, url_prefix=f'{prefix}/permissions')
    app.register_blueprint(system_bp, url_prefix=f'{prefix}/systems')
    app.register_blueprint(user_cognito_bp, url_prefix=f'{prefix}/users')
    app.register_blueprint(user_auth_bp, url_prefix=f'{prefix}/auth')
    app.register_blueprint(user_management_bp, url_prefix=f'{prefix}/users_management')
    app.register_blueprint(admins_bp, url_prefix=f'{prefix}/admins')
    app.register_blueprint(field_bp, url_prefix=f'{prefix}/field')
    app.register_blueprint(sso_bp, url_prefix=f'{prefix}/sso')
    app.register_blueprint(request_service_bp, url_prefix=f'{prefix}/audit')

    app.register_blueprint(health_support_bp, url_prefix=f'{prefix}/health')

    # Registra manejadores de errores personalizados
    register_error_handlers(app)

    return app


def register_error_handlers(app):
    @app.errorhandler(Exception)
    def handle_exception_error(e):
        if "psycopg2" in str(e):
            app.logger.error(e)
            return jsonify({'msg': "Bad Request: An error occur, please retry"}), 400
        app.logger.error(e)
        return jsonify({'msg': e.args}), 500

    @app.errorhandler(405)
    def handle_405_error(e):
        app.logger.error(e)
        return jsonify({'msg': 'Method not allowed'}), 405

    @app.errorhandler(403)
    def handle_403_error(e):
        app.logger.error(e)
        return jsonify({'msg': 'Forbidden error'}), 403

    @app.errorhandler(404)
    def handle_404_error(e):
        app.logger.error(e)
        return jsonify({'msg': 'Not Found error'}), 404

    @app.errorhandler(AppErrorBaseClass)
    def handle_app_base_error(e):
        if "psycopg2" in str(e):
            app.logger.error(e)
            return jsonify({'msg': "Bad Request: An error occur, please retry"}), 400
        app.logger.error(e)
        return jsonify({'msg': str(e)}), 500

    @app.errorhandler(ObjectNotFound)
    def handle_object_not_found_error(e):
        app.logger.error(e)
        return jsonify({'msg': str(e)}), 404
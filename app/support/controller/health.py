from flask import request, Blueprint, jsonify
import os

import requests
from flask import make_response

from app.auth.controller.system import system_bp
from app.auth.utils.function_object import get_system

health_support_bp = Blueprint('health_support_bp', __name__)
@health_support_bp.route('/', methods=['GET'])
def ok():
    """
        Check if integration is active and ok
        :return: "ok"
    """
    return "health_integration_ok"

#@health_support_bp.route('/log/<option_id>', methods=['GET'])

@health_support_bp.route('/logs/<system_id>/<int:number_lines>', methods=['GET'])
def get_report_number(system_id, number_lines):
    try:
        system = get_system(system_id)
        if system is None:
            return jsonify({"error": "System dont exist"}), 404
        if system.log_file is None:
            return jsonify({"error": "System dont have log file"}), 404
        else:
            log_file_path = system.log_file
            last_500_lines = tail(log_file_path, number_lines)
            log_content = ''.join(last_500_lines)
            return jsonify({"log": log_content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@health_support_bp.route('/logs/<system_id>', methods=['GET'])
def get_report(system_id):
    try:
        system = get_system(system_id)
        if system is None:
            return jsonify({"error": "System dont exist"}), 404
        if system.log_file is None:
            return jsonify({"error": "System dont have log file"}), 404
        else:
            log_file_path = system.log_file
            last_500_lines = tail(log_file_path, 500)
            log_content = ''.join(last_500_lines)
            return jsonify({"log": log_content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#LOG_FILE_PATH = '/home/centos/logs/3energy/3energy-error.log'

def tail(file, n=500):
    with open(file, 'r') as f:
        lines = f.readlines()
        return lines[-n:]

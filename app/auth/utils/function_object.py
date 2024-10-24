import os

from app.common.error_handling import ObjectNotFound
from app.auth.models.option import Option
from app.auth.models.permission import Permission
from app.auth.models.role import Role
from app.auth.models.role_user import RoleUser
from app.auth.models.system import System
from app.auth.models.user import User


def get_user(user_id):
    user = None
    if len(user_id) > 16:
        user = User.simple_filter_unique(uuid=user_id)
    else:
        user = User.get_by_id(user_id)
    if user is None:
        raise ObjectNotFound('User not exist')
    return user


def get_system(system_id):
    system = None
    if len(system_id) > 16:
        system = System.simple_filter_unique(uuid=system_id)
    else:
        system = System.get_by_id(system_id)

    if system is None:
        raise ObjectNotFound('System not exist')

    return system


def get_role(role_id):
    role = None
    if len(role_id) > 16:
        role = Role.simple_filter_unique(uuid=role_id)
    else:
        role = Role.get_by_id(role_id)

    if role is None:
        raise ObjectNotFound('Role not exist')

    return role


def get_permission(permission_id):
    permission = None
    if len(permission_id) > 16:
        permission = Permission.simple_filter_unique(uuid=permission_id)
    else:
        permission = Permission.get_by_id(permission_id)

    if permission is None:
        raise ObjectNotFound('Permission not exist')

    return permission


def get_option(option_id):
    option = None
    if len(option_id) > 16:
        option = Option.simple_filter_unique(uuid=option_id)
    else:
        option = Option.get_by_id(option_id)

    if option is None:
        raise ObjectNotFound('Option not exist')

    return option

def get_role_user(role_user_id):
    role_user = None
    if len(role_user_id) > 16:
        role_user = RoleUser.simple_filter_unique(uuid=role_user_id)
    else:
        role_user = RoleUser.get_by_id(role_user_id)

    if role_user is None:
        raise ObjectNotFound('Role user not exist')

    return role_user

def validate_admin(user_id):
    user = get_user(user_id)
    for system in user.systems:
        if system.acronym == os.environ['PROJECT']:
            return True
    return False


def get_user_email(username):
    user = None
    user = User.simple_filter_unique(email=username)
    if user is None:
        raise ObjectNotFound('User not exist')
    return user

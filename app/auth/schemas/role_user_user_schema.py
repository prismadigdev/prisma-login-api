from marshmallow import fields

from app.auth.models.user import User
from app.auth.schemas.role_schema import RoleSchema
from app.auth.schemas.user_schema import UserSchema
from app.ext import ma


class RoleUserUserSchema(ma.Schema):

    id = fields.String(attribute="user.uuid")
    username = fields.String(attribute='user.username')
    name = fields.String(attribute='user.name')
    email = fields.String(attribute='user.email')
    phone = fields.String(attribute='user.phone')
    role = fields.String(attribute='role.description')


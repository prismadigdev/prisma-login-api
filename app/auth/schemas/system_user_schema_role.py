from marshmallow import fields

from app.auth.models.user import User
from app.auth.schemas.role_schema import RoleSchema
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.user_schema import UserSchema
from app.ext import ma


class RoleSystem(ma.Schema):
    id = fields.String()
    description = fields.String()
    status = fields.String()
    syst_uuid = fields.String()
    name_system = fields.String()


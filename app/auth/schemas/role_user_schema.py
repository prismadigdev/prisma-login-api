from marshmallow import fields

from app.auth.schemas.role_schema import RoleSchema
from app.auth.schemas.system_schema import SystemSchema
from app.auth.schemas.user_schema import UserSchema
from app.ext import ma


class RoleUserSchema(ma.Schema):
    #id = fields.Integer()
    #uuid = fields.String(allow_none=True)
    id = fields.String(attribute="uuid", allow_none=True)
    role_id = fields.String(load_only=True)
    role = fields.Nested(RoleSchema)
    system_id = fields.String(load_only=True)
    system = fields.Nested(SystemSchema)
    user_id = fields.String(load_only=True)
    user = fields.Nested(UserSchema)
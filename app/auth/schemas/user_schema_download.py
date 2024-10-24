from marshmallow import fields

from app.auth.schemas.role_schema import RoleSchema
from app.ext import ma
from app.fields.schema.field_schema import FieldSchema


class UserSchemaDownload(ma.Schema):
    #id = fields.Integer()
    id = fields.String(attribute="uuid", allow_none=True)
    username = fields.String()
    name = fields.String()
    email = fields.String()
    phone = fields.String()
    #uuid = fields.String(allow_none=True)
    status = fields.String()
    user_created = fields.String()
    date_created = fields.Date()
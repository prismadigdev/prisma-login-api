from marshmallow import fields

from app.ext import ma
from app.fields.schema.option_schema import OptionsSchema


class UserSystemSchema(ma.Schema):
    
    class Meta:
        ordered = True
    
    name = fields.String(allow_none=False)
    username = fields.String(allow_none=True)
    role = fields.String(allow_none=True)
    email = fields.String(allow_none=True)
    field_id = fields.String(allow_none=True)
    field_type = fields.String(allow_none=True)
    field_name = fields.String(allow_none=True)
    value = fields.String(allow_none=True)
    
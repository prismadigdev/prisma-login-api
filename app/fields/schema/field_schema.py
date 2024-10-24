from marshmallow import fields

from app.ext import ma
from app.fields.schema.option_schema import OptionsSchema


class FieldSchema(ma.Schema):
    
    class Meta:
        ordered = True
    
    id = fields.String()
    name = fields.String(allow_none=False)
    description = fields.String(allow_none=True)
    type = fields.String(allow_none=True)
    state = fields.String(allow_none=True)
    time_created = fields.DateTime(allow_none=True)

    owner_id = fields.Integer(allow_none=True)
    #owner = fields.Nested('UserSchema', many=False)

    options = fields.Nested('OptionsSchema', many=True)
    
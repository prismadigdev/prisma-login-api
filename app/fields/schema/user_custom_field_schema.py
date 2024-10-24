from marshmallow import fields

from app.ext import ma


class User_custom_field_Schema(ma.Schema):
    
    class Meta:
        ordered = True
    
    id = fields.Integer()
    user_id = fields.String(allow_none=True)
    email = fields.String(allow_none = True)
    field_id = fields.Integer(allow_none=True)
    option_id = fields.Integer(allow_none=True)
    value = fields.String(allow_none=False)

    
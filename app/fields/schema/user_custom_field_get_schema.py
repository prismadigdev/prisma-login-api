from marshmallow import fields

from app.ext import ma


class User_custom_field_get_Schema(ma.Schema):
    
    class Meta:
        ordered = True
    
    id = fields.Integer()
    user_id = fields.String(allow_none=True)
    email = fields.String(allow_none = True)
    field_id = fields.Integer(allow_none=True)
    field_name = fields.String(allow_none=False, default="")
    option_name = fields.String(allow_none=False,default="")
    field_type = fields.String(allow_none=False,default="")
    option_id = fields.Integer(allow_none=True)
    value = fields.String(allow_none=False)

    
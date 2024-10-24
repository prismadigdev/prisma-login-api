from marshmallow import fields

from app.ext import ma


class OptionsSchema(ma.Schema):
    
    class Meta:
        ordered = True
    
    id = fields.Integer()
    name = fields.String(allow_none=False)
    field_id = fields.Integer(allow_none=True)
    field = fields.Nested('FieldSchema', many=False)
    
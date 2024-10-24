from marshmallow import fields

from app.ext import ma


class OptionSchema(ma.Schema):
    #id = fields.Integer()
    id = fields.String(attribute="uuid", allow_none=True)
    description = fields.String()
    #uuid = fields.String(allow_none=True)

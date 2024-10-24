from marshmallow import fields

from app.ext import ma


class SystemSchemaSingle(ma.Schema):
    #id = fields.Integer()
    id = fields.String(attribute="uuid", allow_none=True)
    acronym = fields.String()

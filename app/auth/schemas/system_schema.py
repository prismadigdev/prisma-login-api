from marshmallow import fields

from app.ext import ma


class SystemSchema(ma.Schema):
    #id = fields.Integer()
    id = fields.String(attribute="uuid")
    name = fields.String()
    url = fields.String()
    type = fields.String()
    #uuid = fields.String(allow_none=True)
    acronym = fields.String()
    api = fields.String()

    log_file = fields.String(allow_none=True)

    token_structure = fields.String(allow_none=True)
    status = fields.Boolean(allow_none=True)

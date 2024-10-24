from marshmallow import fields

from app.ext import ma


class RequestServiceSchema(ma.Schema):
    id = fields.Integer()
    description = fields.String()
    uuid = fields.String()
    date_operation = fields.DateTime()
    url = fields.String()
    data = fields.String()
    type = fields.String()
    method_operation = fields.String()
    user_operation = fields.String()
    endpoint = fields.String()
    system = fields.String()
    process = fields.String()
    status = fields.String()
    date_created = fields.DateTime()

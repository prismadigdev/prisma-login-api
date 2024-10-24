from marshmallow import fields

from app.ext import ma


class UserSchemaPost(ma.Schema):
    #id = fields.Integer()
    id = fields.String(attribute="uuid", allow_none=True)
    username = fields.String()
    name = fields.String()
    passwd = fields.String()
    email = fields.String()
    phone = fields.String()
    status = fields.String()
    user_created = fields.String()
    date_created = fields.Date()
    azure = fields.String(allow_none=True)

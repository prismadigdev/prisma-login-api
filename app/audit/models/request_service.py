from datetime import datetime

from app.db import db, BaseModelMixin


class RequestService(db.Model, BaseModelMixin):
    __tablename__ = "request_service"
    __table_args__ = {"schema": "audit"}
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String)
    date_operation = db.Column(db.Date)
    date_created = db.Column(db.DateTime)
    url = db.Column(db.String)
    data = db.Column(db.String)
    type = db.Column(db.String)
    method_operation = db.Column(db.String)
    user_operation = db.Column(db.String)
    endpoint = db.Column(db.String)
    system = db.Column(db.String)
    process = db.Column(db.String)
    status = db.Column(db.String)

    def __init__(self, uuid, date_operation, url, data, type, method_operation, user_operation,
                 endpoint, system, process, status):
        self.uuid = uuid
        self.date_operation = date_operation
        self.url = url
        self.data = data
        self.type = type
        self.method_operation = method_operation
        self.user_operation = user_operation
        self.endpoint = endpoint
        self.system = system
        self.process = process
        self.status = status
        self.date_created = datetime.today()

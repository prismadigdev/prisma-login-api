import uuid

from app.db import db, BaseModelMixin


class Option(db.Model, BaseModelMixin):
    __tablename__ = "option"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String)
    uuid = db.Column(db.String)
    permissions = db.relationship('Permission', backref='permissions', lazy=False,
                                  cascade='all, delete-orphan')

    def __init__(self, description):
        self.description = description
        self.uuid = uuid.uuid4()

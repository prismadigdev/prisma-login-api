from app.auth.models.user import User
from app.db import db, BaseModelMixin


class Options(db.Model, BaseModelMixin):

    __tablename__ = 'option_field'
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    
    field_id = db.Column(db.Integer, db.ForeignKey('auth.custom_field.id'))

    def __init__(self, name, field_id):
        self.name = name
        self.field_id = field_id

    def __repr__(self):
        return f'Options({self.name})'

    def __str__(self):
        return f'{self.name}'
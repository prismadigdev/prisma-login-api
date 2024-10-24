from app.auth.models.user import User
from app.db import db, BaseModelMixin


class UserCustomField(db.Model, BaseModelMixin):

    __tablename__ = 'user_custom_field'
    __table_args__ = {"schema": "auth",'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)    
    field_id = db.Column(db.Integer, db.ForeignKey('auth.custom_field.id'))
    option_id = db.Column(db.Integer, db.ForeignKey('auth.option.id'))
    user_id = db.Column(db.String, db.ForeignKey('auth.user.uuid'))
    email = db.Column(db.String)
    value = db.Column(db.String)

    def __init__(self, field_id, option_id, user_id, email, value):
        self.option_id = option_id
        self.field_id = field_id
        self.user_id = user_id
        self.email = email
        self.value = value

    def __repr__(self):
        return f'User({self.user_id})'

    def __str__(self):
        return f'{self.user_id}'
    
from app.db import db, BaseModelMixin, user_field
#from app.auth.model.user_model import User
from app.fields.model.option_model import Options

class Field(db.Model, BaseModelMixin):

    __tablename__ = 'custom_field'
    __table_args__ = {"schema": "auth",'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    state = db.Column(db.String)
    type = db.Column(db.String)
    time_created = db.Column(db.DateTime)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('auth.user.id'))
    owner = db.relationship('User', back_populates="fields")
    
    options = db.relationship('Options', backref='Options', lazy=False, cascade='all, delete-orphan')
    users = db.relationship('User', secondary = user_field, back_populates="fields")
    
    def __init__(self, name, description, type, owner_id, time_created, state):
        self.name = name
        self.description = description
        self.state = state
        self.type = type
        self.time_created = time_created
        self.owner_id = owner_id

    def __repr__(self):
        return f'Field({self.name})'

    def __str__(self):
        return f'{self.name}'
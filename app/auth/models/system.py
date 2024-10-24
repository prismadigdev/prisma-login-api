import uuid

from app.db import db, BaseModelMixin


class System(db.Model, BaseModelMixin):
    __tablename__ = "system"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    url = db.Column(db.String)
    type = db.Column(db.String)
    acronym = db.Column(db.String)
    token_structure = db.Column(db.String)
    uuid = db.Column(db.String)
    api = db.Column(db.String)
    status = db.Column(db.Boolean)
    log_file = db.Column(db.String)



    roles = db.relationship('Role', secondary='auth.role_system', back_populates="systems")
    users = db.relationship('User', secondary='auth.admin_system', back_populates="systems")

    system_role_users = db.relationship('RoleUser', back_populates='system', lazy=False,
                                 cascade='all, delete-orphan')

    system_permissions = db.relationship('Permission', back_populates='system', lazy=False,
                                        cascade='all, delete-orphan')


    def __init__(self, name, url, type, acronym, token_structure, api, log_file=None):
        self.name = name
        self.url = url
        self.type = type
        self.acronym = acronym
        self.token_structure = token_structure
        self.api = api
        self.uuid = uuid.uuid4()
        self.status = True
        self.log_file = log_file

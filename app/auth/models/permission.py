
import uuid

from app.db import db, BaseModelMixin


class Permission(db.Model, BaseModelMixin):
    __tablename__ = "permission"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String)
    uuid = db.Column(db.String)

    option_id = db.Column(db.Integer, db.ForeignKey('auth.option.id'), nullable=False)

    system_id = db.Column(db.Integer, db.ForeignKey('auth.system.id'), nullable=False)
    system = db.relationship("System", back_populates="system_permissions")

    #roles = db.relationship('Role', secondary='role_permission')
    roles = db.relationship('Role', secondary='auth.role_permission', back_populates="permissions")

    def __init__(self, description, system_id, option_id=1):
        self.description = description
        self.system_id = system_id
        self.option_id = option_id
        self.uuid = uuid.uuid4()

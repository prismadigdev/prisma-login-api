import uuid

from app.db import db, BaseModelMixin


class RoleUser(db.Model, BaseModelMixin):
    __tablename__ = "role_user"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)

    uuid = db.Column(db.String)

    role_id = db.Column(db.Integer, db.ForeignKey('auth.role.id'), nullable=False)
    role = db.relationship("Role", back_populates="role_role_users")

    system_id = db.Column(db.Integer, db.ForeignKey('auth.system.id'), nullable=False)
    system = db.relationship("System", back_populates="system_role_users")

    user_id = db.Column(db.Integer, db.ForeignKey('auth.user.id'), nullable=False)
    user = db.relationship("User", back_populates="user_role_users")

    def __init__(self, role_id, system_id, user_id):
        self.role_id = role_id
        self.system_id = system_id
        self.user_id = user_id
        self.uuid = uuid.uuid4()




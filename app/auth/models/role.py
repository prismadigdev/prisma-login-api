import uuid

from app.db import db, BaseModelMixin

role_permission = db.Table("role_permission",
                           db.Column("role_id", db.Integer, db.ForeignKey("auth.role.id"), primary_key=True),
                           db.Column("permission_id", db.Integer, db.ForeignKey("auth.permission.id"),
                                     primary_key=True), schema="auth", extend_existing=True)

role_system = db.Table("role_system",
                           db.Column("role_id", db.Integer, db.ForeignKey("auth.role.id"), primary_key=True),
                           db.Column("system_id", db.Integer, db.ForeignKey("auth.system.id"),
                                     primary_key=True), schema="auth", extend_existing=True)


class Role(db.Model, BaseModelMixin):
    __tablename__ = "role"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String)
    status = db.Column(db.String)
    uuid = db.Column(db.String)

    #user = db.relationship("User", back_populates="roles")
    permissions = db.relationship('Permission', secondary='auth.role_permission', back_populates="roles")
    systems = db.relationship('System', secondary='auth.role_system', back_populates="roles")
    #permissions = db.relationship('RolePermission', back_populates="role")

    role_role_users = db.relationship('RoleUser', back_populates='role', lazy=False,
                                 cascade='all, delete-orphan')

    def __init__(self, description, status):
        self.description = description
        self.status = status
        self.uuid = uuid.uuid4()

import uuid
from datetime import datetime
from hmac import compare_digest

from app.db import db, BaseModelMixin
from app.db import user_field

user_system = db.Table("admin_system",
                       db.Column("user_id", db.Integer, db.ForeignKey("auth.user.id"), primary_key=True),
                       db.Column("system_id", db.Integer, db.ForeignKey("auth.system.id"),
                                 primary_key=True), schema="auth", extend_existing=True)


class User(db.Model, BaseModelMixin):
    __tablename__ = "user"
    __table_args__ = {"schema": "auth"}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    name = db.Column(db.String)
    phone = db.Column(db.String)
    email = db.Column(db.String)
    status = db.Column(db.String)
    uuid = db.Column(db.String)
    user_created = db.Column(db.String)
    date_created = db.Column(db.Date)

    user_role_users = db.relationship('RoleUser', back_populates='user', lazy=False,
                                      cascade='all, delete-orphan')

    systems = db.relationship('System', secondary='auth.admin_system', back_populates="users")
    fields = db.relationship('Field', secondary = user_field, back_populates="users")

    def __init__(self, name, username, status, phone, email, user_created,
                 date_created=datetime.today()):
        self.name = name
        self.status = status
        self.username = username
        self.phone = phone
        self.email = email
        self.uuid = uuid.uuid4()
        self.user_created = user_created
        self.date_created = date_created

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, passw):
        return compare_digest(passw, "password")

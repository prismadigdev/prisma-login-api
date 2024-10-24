from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from sqlalchemy.sql import text


db = SQLAlchemy()

user_field = db.Table('user_custom_field',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('user_id', db.String, db.ForeignKey('auth.user.uuid')),
    db.Column('field_id', db.Integer, db.ForeignKey('auth.custom_field.id')),
    db.Column('option_id', db.Integer, db.ForeignKey('auth.option_field.id')),
    db.Column('value', db.String),
    db.Column('email', db.String),
    schema='auth'
)


class BaseModelMixin:

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get_all_order_limit(cls, order_data, limit_number=0, filters=None):
        if filters is None:
            if limit_number == 0:
                return cls.query.order_by(desc(order_data)).all()
            else:
                return cls.query.order_by(desc(order_data)).limit(limit_number).all()
        else:
            if limit_number == 0:
                return cls.query.filter(filters).order_by(desc(order_data)).all()
            else:
                return cls.query.filter(filters).order_by(desc(order_data)).limit(limit_number).all()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get(id)

    @classmethod
    def simple_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()

    @classmethod
    def simple_filter_paginate(cls, page, per_page, **kwargs):
        return cls.query.filter_by(**kwargs).paginate(page=page, per_page=per_page)

    @classmethod
    def simple_search_paginate(cls, page, per_page, param):
        return cls.query.filter(param).paginate(page=page, per_page=per_page)

    @classmethod
    def simple_filter_unique(cls, **kwargs):
        return cls.query.filter_by(**kwargs).first()

    @classmethod
    def native_query(cls, sql, **kwargs):
        engine = db.get_engine()
        conn = engine.connect()
        return conn.execute(text(sql))

    @classmethod
    def native_query_(cls, sql):
        engine = db.get_engine()
        conn = engine.connect()
        return conn.execute(text(sql))
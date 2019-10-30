import time

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields

from database import Base

class KycRequestSchema(Schema):
    date = fields.Float()
    token = fields.String()
    greenid_verification_id = fields.String()
    status = fields.String()

class KycRequest(Base):
    __tablename__ = 'kyc_requests'
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False, unique=False)
    token = Column(String, nullable=False, unique=True)
    greenid_verification_id = Column(String, nullable=True, unique=True)
    status = Column(String )

    def __init__(self, token, greenid_verification_id):
        self.date = time.time()
        self.token = token
        self.greenid_verification_id = greenid_verification_id
        self.status = "created"

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_token(cls, session, token):
        return session.query(cls).filter(cls.token == token).first()

    def __repr__(self):
        return '<KycRequest %r>' % (self.token)

    def to_json(self):
        schema = KycRequestSchema()
        return schema.dump(self).data

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, unique=True)

    def __init__(self, email):
        self.email = email

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_id(cls, session, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def from_email(cls, session, email):
        return session.query(cls).filter(cls.email == email).first()

class UserRequest(Base):
    __tablename__ = 'user_requests'
    user_id = Column(Integer, primary_key=True)
    kyc_request_id = Column(Integer, primary_key=True)

    def __init__(self, user, kyc_request):
        self.user_id = user.id
        self.kyc_request_id = kyc_request.id

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    @classmethod
    def from_request(cls, session, kyc_request):
        return session.query(cls).filter(cls.kyc_request_id == kyc_request.id).first()

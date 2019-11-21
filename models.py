import time

from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey
import sqlalchemy.types as types
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import func
from sqlalchemy import or_, and_, desc
from marshmallow import Schema, fields

from database import Base

class GreenId(Base):
    __tablename__ = 'greenid'
    id = Column(Integer, primary_key=True)
    greenid_verification_id = Column(String, nullable=False, unique=True)
    kyc_request_id = Column(Integer, ForeignKey('kyc_requests.id'))
    kyc_request = relationship("KycRequest", back_populates="greenid")

    def __init__(self, kyc_request, greenid_verification_id):
        self.kyc_request = kyc_request
        self.greenid_verification_id = greenid_verification_id

class EzyPay(Base):
    __tablename__ = 'ezypay'
    id = Column(Integer, primary_key=True)
    ezypay_username = Column(String, nullable=False, unique=True)
    kyc_request_id = Column(Integer, ForeignKey('kyc_requests.id'))
    kyc_request = relationship("KycRequest", back_populates="ezypay")

    def __init__(self, kyc_request, ezypay_username):
        self.kyc_request = kyc_request
        self.ezypay_username = ezypay_username

class KycRequestSchema(Schema):
    date = fields.Float()
    token = fields.String()
    status = fields.String()

class KycRequest(Base):
    __tablename__ = 'kyc_requests'
    id = Column(Integer, primary_key=True)
    date = Column(Float, nullable=False, unique=False)
    token = Column(String, nullable=False, unique=True)
    status = Column(String)
    greenid = relationship("GreenId", uselist=False, back_populates="kyc_request")
    ezypay = relationship("EzyPay", uselist=False, back_populates="kyc_request")

    def __init__(self, token):
        self.date = time.time()
        self.token = token
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

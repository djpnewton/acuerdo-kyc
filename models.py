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
    greenid_verification_id = Column(String, nullable=False, unique=True)
    status = Column(String )

    def __init__(self, token, greenid_verification_id):
        self.date = time.time()
        self.token = token
        self.greenid_verification_id = greenid_verification_id
        self.status = "created"

    @classmethod
    def count(cls, session):
        return session.query(cls).count()

    def __repr__(self):
        return '<KycRequest %r>' % (self.token)

    def to_json(self):
        schema = KycRequestSchema()
        return schema.dump(self).data

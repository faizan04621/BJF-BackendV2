from marshmallow import fields, Schema
from .SuscriptionSchema import SubscriptionSchema

class UserSchema(Schema):
  """
  User Schema
  """
  id = fields.Int(dump_only=True)
  name = fields.Str(required=True)
  cc = fields.Str(required=True)
  mobile = fields.Str(required=True)
  email = fields.Str(required=True)
  password = fields.Str(required=True)
  adhaar = fields.Str(required=True)
  pan = fields.Str(required=False)
  address = fields.Str(required=False)
  created_at = fields.DateTime(dump_only=True)
  modified_at = fields.DateTime(dump_only=True)
  active = fields.Int(required=True)
  verified = fields.Int(required=True)
  subscriptions = fields.Nested(SubscriptionSchema, many=True)
from marshmallow import fields, Schema

class SubscriptionSchema(Schema):
  """
  Subscription Schema
  """
  id = fields.Int(dump_only=True)
  user_id = fields.Int(required=True)
  parent_id = fields.Int(required=False)
  join_type = fields.Int(required=True)
  gift_from = fields.Int(required=False)
  created_at = fields.DateTime(dump_only=True)
  status = fields.Int(required=True)
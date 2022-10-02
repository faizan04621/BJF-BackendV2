from app import db
import datetime

class SubscriptionModel(db.Model):
  """
  Subscription Model
  """

  # table name
  __tablename__ = 'subscriptions'

  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
  parent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
  join_type = db.Column(db.SmallInteger, nullable=False)#1-DIRECT 2-REFER 3-GIFT
  gift_from = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
  created_at = db.Column(db.DateTime)
  status = db.Column(db.SmallInteger, default=0)

  # class constructor
  def __init__(self, data):
    """
    Class constructor
    """
    self.user_id = data.get('userId')
    self.parent_id = data.get('parentId')
    self.join_type = data.get('joinType')
    self.gift_from = data.get('giftFrom')
    self.created_at = datetime.datetime.utcnow()
    self.status = data.get('status')

  def save(self):
    db.session.add(self)
    db.session.commit()
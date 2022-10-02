from app import db
import datetime

class OtpModel(db.Model):
  """
  OTP Model
  """

  # table name
  __tablename__ = 'otp'

  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, nullable=False)
  cc = db.Column(db.String(5), nullable=False)
  mobile = db.Column(db.String(15), nullable=False)
  otp = db.Column(db.String(6), nullable=False)
  created_at = db.Column(db.DateTime)

  # class constructor
  def __init__(self, data):
    """
    Class constructor
    """
    self.user_id = data.get('userId')
    self.cc = data.get('cc')
    self.mobile = data.get('mobile')
    self.otp = data.get('otp')
    self.created_at = datetime.datetime.utcnow()

  def save(self):
    db.session.add(self)
    db.session.commit()

  @staticmethod
  def get_one_user(id):
    return OtpModel.query.get(id)

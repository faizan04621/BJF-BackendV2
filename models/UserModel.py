from app import db, bcrypt
import datetime


class UserModel(db.Model):
  """
  User Model
  """

  # table name
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(128), nullable=False)
  cc = db.Column(db.String(5), nullable=False)
  mobile = db.Column(db.String(15), unique=True, nullable=False)
  email = db.Column(db.String(100), unique=True, nullable=False)
  password = db.Column(db.String(128), nullable=False)
  adhaar = db.Column(db.String(12), nullable=True)
  pan = db.Column(db.String(10), nullable=True)
  address = db.Column(db.Text, nullable=True)
  created_at = db.Column(db.DateTime)
  modified_at = db.Column(db.DateTime, nullable=True)
  active = db.Column(db.SmallInteger, default=1)#1-active
  verified = db.Column(db.SmallInteger, default=0)#1-verified
  referral_code = db.Column(db.String(12), nullable=False)
  referred_by = db.Column(db.String(12), nullable=True)
  #subscriptions = db.relationship('SubscriptionModel', backref='users', lazy=True)


  # class constructor
  def __init__(self, data):
    """
    Class constructor
    """
    self.name = data.get('name')
    self.cc = data.get('cc')
    self.mobile = data.get('mobile')
    self.email = data.get('email')
    self.password = self.__generate_hash(data.get('password')) # add this line
    self.adhaar = data.get('adhaar')
    self.pan = data.get('pan')
    self.address = data.get('address')
    self.created_at = datetime.datetime.utcnow()
    self.modified_at = datetime.datetime.utcnow()
    self.active = data.get('active')
    self.verified = data.get('verified')
    self.referral_code = 'CHK007'
    self.referred_by = 'GJS001'

  def save(self):
    db.session.add(self)
    db.session.commit()

  def update(self, data):
    for key, item in data.items():
      if key == 'password': # add this new line
        self.password = self.__generate_hash(item) # add this new line
      setattr(self, key, item)
    self.modified_at = datetime.datetime.utcnow()
    db.session.commit()

  def delete(self):
    db.session.delete(self)
    db.session.commit()

  @classmethod
  def get_users(cls):
    return cls.query.all()

  @classmethod
  def get_one_user(id):
    return UserModel.query.get(id)

  
  def __repr(self):
    return '<id {}>'.format(self.id)

  # add this new method
  def __generate_hash(self, password):
    return bcrypt.generate_password_hash(password, rounds=10).decode("utf-8")
  
  # add this new method
  def check_hash(self, password):
    return bcrypt.check_password_hash(self.password, password)

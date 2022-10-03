from crypt import methods
from operator import and_
from unicodedata import name
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from  werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid

from email.policy import default
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from marshmallow import fields, Schema
from datetime import datetime, timedelta
import http.client
import json
from functools import wraps

import os
import re

SMS_PROVIDER_AUTH=os.getenv('sms_provider_auth', '953968b9-15a2-11ed-9c12-0200cd936042')
OTP_TEMPLATE_ID=os.getenv('sms_otp_template_id', 'Register')
SEND_OTP_URL="/api/v5/otp?template_id=&mobile=&authkey="
conn = http.client.HTTPSConnection("2factor.in")
headers = { 'Content-Type': "application/json" }


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chakry123456789bjf'
app.config["SQLALCHEMY_DATABASE_URI"]='postgresql://chakry:chakry@localhost:5432/bjf'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False

db=SQLAlchemy(app)

#Passwors Hash
bcrypt = Bcrypt()

@app.route('/users',methods=['GET'])
def get_all_users():
    users=UserModel.get_users()
    serializer=UserSchema(many=True)
    data=serializer.dump(users)
    return jsonify(data)

@app.route('/users',methods=['POST'])
def create_a_user():
    data=request.get_json()

    new_user=UserModel(data)
    #Save user
    new_user.save()

    #OTO FLOW
    otp_details = sendOTP(new_user.cc + new_user.mobile)
    #print('OTP'+otp_details)
    otp_request = {
      'userId': new_user.pid,
      'cc': new_user.cc,
      'mobile': new_user.mobile,
      'otp': otp_details['OTP']
    }

    otp_save = OtpModel(otp_request)
    otp_save.save()
    #RefCode
    refData = {
      'referral_code': data['name'][0:3].upper() + str(new_user.id)+ '0',
      'id': new_user.id
    }
    #update
    new_user.update(refData)
    

    #OUTPUT
    #serializer=UserSchema()

    #data=serializer.dump(new_user)

    result = {
      'status': True,
      'id': new_user.pid,
      'otpId': otp_save.id
    }

    return jsonify(result),200

@app.route('/users/<userId>', methods=['GET'])
def get_user_info(userId):
  user = UserModel.query.filter_by(pid = userId).first()
  if not user:
    return jsonify({'status': False, 'message': 'Invalid User'}), 200

  result = {
    'id': user.pid,
    'name': user.name,
    'email': user.email,
    'mobile': user.mobile,
    'active': user.active,
    'verified': user.verified,
    'adhaar': user.adhaar,
    'pan': user.pan,
    'cc': user.cc,
    'address': user.address,
    'referralCode': user.referral_code,
    'referredBy': user.referred_by
  }

  return jsonify({'status': True, 'user': result}), 200

@app.route('/login', methods=['POST'])
def login():
  data = request.get_json()
  if not data or not data.get('username') or not data.get('password'):
    return jsonify({'status': False, 'message':'Invalid Request'}),200

  if checkEmail(data.get('username')):
  
    user = UserModel.query\
          .filter_by(email = data.get('username'))\
          .first()
  else:
    user = UserModel.query\
          .filter_by(mobile = data.get('username'))\
          .first()

  if not user:
    return jsonify({'status': False, 'message':'Invalid User'}),200
  
  if check_password_hash(user.password, data.get('password')):
    token = jwt.encode({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'mobile': user.mobile,
            'pid': user.pid,
            'exp' : datetime.utcnow() + timedelta(minutes = 1440)
        }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'status': True,'jwt': token}),200
  return jsonify({'status': False}),200


@app.route('/sendOtp', methods=['POST'])
def sendOtp():
  data = request.get_json()
  if not data or not data.get('userId'):
    return jsonify({'status': False, 'message':'Invalid Reuqest'}),200
  user = UserModel.query.filter_by(pid = data.get('userId')).first()
  if not user:
    return jsonify({'status': False, 'message':'Invalid User'}),200

  otp_details = sendOTP(user.cc + user.mobile)
  otp_request = {
      'userId': user.id,
      'cc': user.cc,
      'mobile': user.mobile,
      'otp': otp_details['OTP']
    }

  otp_save = OtpModel(otp_request)
  otp_save.save()
  result = {
      'status': True,
      'id': user.pid,
      'otpId': otp_save.id
    }
  return jsonify({'status': True, 'data': result}),200

@app.route('/verifyOtp', methods=['POST'])
def verifyOtp():
  data = request.get_json()
  if not data or not data.get('cc') or not data.get('mobile') or not data.get('otp') or not data.get('userId') or not data.get('otpId'):
    return jsonify({'status': False, 'message':'Invalid Request'}),200
  user = UserModel.query.filter_by(pid = data.get('userId')).first()
  if not user:
    return jsonify({'status': False, 'message':'Invalid User'}),200  

  otp = OtpModel.query\
        .filter_by(cc = data.get('cc'), mobile = data.get('mobile'), otp = data.get('otp'), user_id = user.id, id = data.get('otpId'))\
        .first()
  if not otp:
    return jsonify({'status': False, 'message':'Invalid OTP'}),200
  otpReq = {
      'id': user.id,
      'verified': 1
  }
  user.update(otpReq)
  return jsonify({'status': True, 'message': 'User Verified Successfully'}), 200


@app.route('/token', methods=['POST'])
def token():
  token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
  return jsonify({'token': token}), 200

@app.route('/userExist', methods=['POST'])
def user_exist():
  data = request.get_json()
  exist = UserModel.user_exist(data['mobile'], data['email'])
  #serializer=UserSchema()

  #data=serializer.dump(data)
  return jsonify(data),200
#API END

def checkEmail(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    # pass the regular expression
    # and the string into the fullmatch() method
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

#OTP
def sendOTP(mobileNumber):
    payload = ''
    conn.request("GET", '/API/V1/' + SMS_PROVIDER_AUTH + '/SMS/' + '+'+mobileNumber + '/AUTOGEN2/' + OTP_TEMPLATE_ID, payload, headers)
    res = conn.getresponse()
    data = res.read()
    return json.loads(data.decode("utf-8"))

#MODELS
class UserModel(db.Model):
  """
  User Model
  """

  # table name
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  pid = db.Column(db.String(50), unique = True)
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

  # decorator for verifying the JWT
  def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = UserModel.query\
                .filter_by(pid = data['pid'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

  # class constructor
  def __init__(self, data):
    """
    Class constructor
    """
    self.name = data.get('name')
    self.cc = data.get('cc')
    self.mobile = data.get('mobile')
    self.email = data.get('email')
    self.password = generate_password_hash(data.get('password'))
    self.adhaar = data.get('adhaar')
    self.pan = data.get('pan')
    self.address = data.get('address')
    self.created_at = datetime.utcnow()
    self.modified_at = datetime.utcnow()
    self.active = data.get('active')
    self.verified = data.get('verified')
    self.referral_code = data.get('name')[0:3].upper()
    self.referred_by = data.get('referralCode')

  def save(self):
    self.pid = str(uuid.uuid4())
    db.session.add(self)
    db.session.commit()

  def update(self, data):
    for key, item in data.items():
      if key == 'password': # add this new line
        self.password = generate_password_hash(item) # add this new line
      setattr(self, key, item)
    self.modified_at = datetime.utcnow()
    db.session.commit()

  def delete(self):
    db.session.delete(self)
    db.session.commit()

  @classmethod
  def get_users(cls):
    return cls.query.all()

  #User Exit 
  @staticmethod
  def user_exist(mob, mail):
    return UserModel.query.filter_by(or_(dict(mobile=mob, email=mail))).first()

  @classmethod
  def get_one_user(cls):
    return cls.query.get(id)

  @classmethod
  def user_by_code(cls, payload):
    return cls.query.filter_by(payload)

  
  def __repr(self):
    return '<id {}>'.format(self.id)

  # add this new method
  def __generate_hash(self, password):
    return bcrypt.generate_password_hash(password, rounds=10).decode("utf-8")
  
  # add this new method
  def check_hash(self, password):
    return bcrypt.check_password_hash(self.password, password)

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
    self.created_at = datetime.utcnow()

  def save(self):
    db.session.add(self)
    db.session.commit()

  @staticmethod
  def get_one_user(id):
    return OtpModel.query.get(id)
  
  def update(self, data):
    for key, item in data.items():
      setattr(self, key, item)
    db.session.commit()

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
    self.created_at = datetime.utcnow()
    self.status = data.get('status')

  def save(self):
    db.session.add(self)
    db.session.commit()

#SCHEMAS
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


#ERROR
@app.errorhandler(404)
def not_found(error):
    return jsonify({"message":"BJF Resource not found"}),404

@app.errorhandler(500)
def internal_server(error):
    return jsonify({"message":"There is a problem"}),500




# DebugToolbarExtension(app)
CORS(app)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5001", debug=True)
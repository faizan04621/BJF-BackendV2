import os

SMS_PROVIDER_AUTH=os.getenv('sms_provider_auth', '123')
OTP_TEMPLATE_ID=os.getenv('sms_otp_template_id', 2)
SEND_OTP_URL="/api/v5/otp?template_id=&mobile=&authkey="
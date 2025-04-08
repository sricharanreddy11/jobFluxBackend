import uuid
from datetime import datetime, timedelta, timezone
from random import randint

from django.contrib.auth import login

from authenticator.Services.email_service import EmailService
from authenticator.Services.sms_service import SMSService
from authenticator.constants import OTPConstant, LoginTypeConstant
from authenticator.models import User, OtpValidator
from authenticator.serializers import CustomTokenSerializer


class OTPService(object):
    """
    OTP service is to send OTP for any channel
    """
    EMAIL_CHANNEL = 'EMAIL'
    SMS_CHANNEL = 'SMS'

    def __init__(self, channel: str, expiry_interval=OTPConstant.valid_for):
        """
        :description:initialize the channel and expiry_intervel
        :param channel: channel type
        :param expiry: expiry time in seconds defaults to 10 min
        """
        self.channel = channel
        self.expiry_interval = expiry_interval

    def _get_channel_executor(self):
        """
        description:selects the execution channel by checking if the channel is supported
        :return appropriate execution channel
        """
        registry = {self.SMS_CHANNEL: SMSService, self.EMAIL_CHANNEL: EmailService}
        if self.channel not in registry:
            raise Exception('channel not supported')
        return registry.get(self.channel)

    def _generate_otp(self, digits=6):
        """
        description:Generates a random number for OTP
        :param digits:Defaults to 6
        :return otp:int
        """
        range_start = 10 ** (digits - 1)
        range_end = (10 ** digits) - 1
        otp = randint(range_start, range_end)
        # if is_hash:
        #     otp = hashlib.sha256(str(otp).encode('UTF-8'))
        return otp

    @staticmethod
    def check_email_mobile_user(_email_mobile):
        """
        description:checks if there is any user object that has the given email or mobile number
        :return: first matching user object if any , else returns None
        """
        return (User.objects.filter(email=_email_mobile) | User.objects.filter(mobile_number=_email_mobile)).first()

    def save_otp(self, otp, email_mobile):
        """
        saves the otp and create a object in OtpValidator for this otp and email,generates token
        :param email_mobile: str
        :param otp: str
        :return: created object
        """
        temp_token = uuid.uuid4()
        expiry = datetime.utcnow() + timedelta(minutes=self.expiry_interval)
        otp_obj = OtpValidator(channel_type=self.channel, email_or_mobile=email_mobile, otp=otp, temp_token=temp_token,
                               status=True, verification_status='PENDING', created_at=datetime.utcnow(), expiry=expiry)
        otp_obj.save()
        return otp_obj

    def send_otp(self, email_mobile, otp=None, request_id=None):
        """
        required request_id and otp in case of resending
        :param email_mobile: str
        :param otp: str optional
        :param request_id: str optional 'but required in case of resending
        :return: tuple with (status, request_id/error_messages)
        """
        user = self.check_email_mobile_user(email_mobile)
        if user is None:
            return False, 'email or mobile not registered'
        if otp is None:
            otp = self._generate_otp()
        executor = self._get_channel_executor()
        res, error = executor(email_mobile).send_otp(otp, user.get_full_name())
        if res:
            if request_id is None:
                otp_obj = self.save_otp(otp, email_mobile)
                return True, otp_obj.temp_token
            else:
                # Ensuring the object is saved to update 'updated_at'
                otp_obj = OtpValidator.objects.filter(temp_token=request_id).first()
                otp_obj.otp = otp  # We can update the Otp here if needed
                otp_obj.save()  # This will update the 'updated_at' timestamp
                return True, request_id
        else:
            return False, error

    @staticmethod
    def verify(request, request_id, entered_otp):
        """
        description:verifies the entered otp
        :param request:
        :param request_id:str - received request id
        :param entered_otp:str received entered otp
        :return dictionary with keys refresh and access token
        """
        check_obj = OtpValidator.objects.filter(temp_token=request_id, otp=entered_otp).first()
        if check_obj is None:
            return False, 'Please enter valid Verification Code'
        if check_obj.status is False or check_obj.verification_status != 'PENDING' or check_obj.expiry < datetime.now(
                timezone.utc):
            return False, 'Verification Code expired, try generating new Verification Code'
        user = OTPService.check_email_mobile_user(check_obj.email_or_mobile)

        refresh_token = CustomTokenSerializer.get_token(user)
        access_token = refresh_token.access_token
        access_token["login_type"] = LoginTypeConstant.JWT_TOKEN
        user_backend = 'allauth.account.auth_backends.AuthenticationBackend'
        login(request, user, backend=user_backend)
        check_obj.verification_status = 'VERIFIED'
        check_obj.verified_at = datetime.now(timezone.utc)
        check_obj.save()
        return True, {"refresh": str(refresh_token), "access": str(access_token)}

    @staticmethod
    def resend(request_id):
        """
        resend will send same otp to same channel and 'expiry time will not change upon resending'
        :param request_id:str - received request id for send otp of earlier request
        :return:
        """
        check_obj = OtpValidator.objects.filter(temp_token=request_id).first()
        if check_obj is None or check_obj.status is False or check_obj.verification_status != 'PENDING' or check_obj.expiry < datetime.now(
                timezone.utc):
            return False, 'Verification Code expired try generating new Verification Code'
        if (datetime.now(timezone.utc) - check_obj.updated_at) < timedelta(seconds=OTPConstant.resend_after):
            return False, 'Please wait before trying to resend OTP'

        return OTPService(check_obj.channel_type).send_otp(check_obj.email_or_mobile, check_obj.otp,
                                                           check_obj.temp_token)

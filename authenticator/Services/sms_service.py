from authenticator.Services.communication_channel import CommunicationChannel


class SMSService(CommunicationChannel):
    def __init__(self, mobile):
        self.mobile_no = mobile
        super(SMSService, self).__init__(mobile)

    def validate(self):
        if not self.email_or_mobile.startswith('+'):
            return False, "mobile number should start with '+'"
        """
        add validation for country code and length
        """
        return True, ""

    def send_otp(self, otp, user_name=""):
        res, error = self.validate()
        if not res:
            return False, error
        return True, ""

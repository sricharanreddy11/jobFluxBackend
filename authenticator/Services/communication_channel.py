class CommunicationChannel(object):
    """Abstract class that defines the basic structure and behavior of a communication channel"""
    def __init__(self, email_or_mobile):
        self.email_or_mobile = email_or_mobile

    def validate(self):
        raise Exception('validate method not implemented')

    def send_otp(self, otp, user_name=""):
        raise Exception('method not implemented')

import ssl
import smtplib

from email.mime.text import MIMEText
from email.utils import formatdate
from email.mime.multipart import MIMEMultipart
from typing import Any
from django.core.validators import validate_email

from authenticator.Services.communication_channel import CommunicationChannel
from jobflux_backend.settings import env


class EmailService(CommunicationChannel):
    """
    inherited the features CommunicationChannel
    sends otp to email
    """
    server = ''
    port = ''
    username = ''
    password = ''
    from_mail = ''
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    def __init__(self, email):
        """
        :description:initialize the executory channel to email
        """
        self.email = email
        super(EmailService, self).__init__(email)

    def validate(self):
        try:
            validate_email(self.email)
        except Exception as e:
            return False, str(e)
        """
        add any extra validation 
        """
        return True, ""

    def send_mail(self, send_to: list, subject: str = '', cc_mails: list = [], bcc_mails: list = [], body: Any = [], from_mail:str=''):
        """
        validate if required
        :param send_to:
        :param subject:
        :param cc_mails:
        :param bcc_mails:
        :param body:
        :return:
        """
        if send_to is None:
            send_to = [self.email, ]
        return self._send_mail(send_to=send_to, subject=subject, cc_mails=cc_mails, bcc_mails=bcc_mails, body=body,from_mail=from_mail)

    def _send_mail(self, send_to: list, subject: str = '', cc_mails: list = [], bcc_mails: list = [], body: Any = [], from_mail:str=''):
        """
        :param send_to:list of emails
        :param subject:str
        :param cc_mails:list
        :param bcc_mails:list
        :returns len of the to_addresses list
        """
        msg = MIMEMultipart()
        if from_mail:
            self.configure_smtp_credentials(mail=from_mail)
        else:
            self.configure_smtp_credentials(mail=env("FROM_MAIL"))
        msg['From'] = from_mail
        msg['To'] = ','.join(send_to)
        msg['Cc'] = ','.join(cc_mails)
        msg['Bcc'] = ','.join(bcc_mails)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        for part in body:
            msg.attach(part)
        smtp = smtplib.SMTP(self.server, self.port)
        smtp.starttls()
        smtp.login(self.username, self.password)
        to_addresses = send_to + cc_mails + bcc_mails
        smtp.sendmail(self.from_mail, to_addresses, msg.as_string())
        smtp.quit()
        return len(to_addresses)

    def send_otp(self, otp, user_name=""):
        """
        description:sends otp to verified email
        :param user_name:
        :param otp:str
        """
        res, error = self.validate()
        if not res:
            return False, error
        otp_subject = "Your Secure Access Code for NoteFlux AI"
        body_msg = MIMEText(
            f"Hello {user_name},<br><br>"
            f"Your one-time verification code is <strong>{otp}</strong>.<br>"
            f"This code will secure your access to Note Flux AI, ensuring that only you can manage your tasks and "
            f"notes efficiently.<br><br>"
            f"Please use this code within the next 10 minutes.<br><br>"
            f"Cheers,<br>"
            f"The TaskMaster AI Team"
            , 'html')

        try:
            self._send_mail([self.email], otp_subject, body=[body_msg])
        except Exception as e:
            return False, str(e)
        return True, ""

    def configure_smtp_credentials(self, mail):
        emails_conf_dict = [
            {
                'server': 'smtp.gmail.com',
                'port': 587,
                'username': env('MAIL_USERNAME'),
                'password': env('MAIL_PASSWORD'),
                'from_mail': env('FROM_MAIL')
            },
        ]
        for email in emails_conf_dict:
            if email.get('from_mail') == mail:
                self.server = email.get('server')
                self.port = email.get('port')
                self.username = email.get('username')
                self.password = email.get('password')

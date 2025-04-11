import mimetypes
import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.core.validators import validate_email
from email.utils import formatdate

from notification.models import EmailConfigurations


class SystemEventMailService(object):
    def __init__(self, message):
        """
        :description:initialize the executory channel to email
        """

        self.server = ''
        self.port = 0
        self.username = ''
        self.password = ''
        self.message = message

    def validate(self, email):
        try:
            validate_email(email)
        except Exception as e:
            return False, str(e)
        """
        add any extra validation
        """
        return True, ""

    def send_mail(self, send_to: list, attachments, email_format, subject: str = '', cc_mails: list = [],
                  bcc_mails=None, from_mail: str = ''
                  ):
        """
        :param send_to:list of emails
        :param attachments
        :param email_format: plain or html
        :param subject:str
        :param cc_mails:list of cc_mails
        :param bcc_mails:list of bcc_mails
        :param from_mail: str
        :returns status of request and status message
        """
        from_addr = self.configure_from_mail(mail=from_mail)
        if bcc_mails is None:
            bcc_mails = []
        msg = MIMEMultipart('alternative')
        msg['From'] = from_addr
        msg['To'] = ','.join(send_to)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        if cc_mails:
            msg['Cc'] = ','.join(cc_mails)
        if bcc_mails:
            msg['Bcc'] = ','.join(bcc_mails)
        if email_format == 'HTML':
            text_message = MIMEText(self.message + '<br>', 'html')
        else:
            text_message = MIMEText(self.message + '\n', 'plain')
        msg.attach(text_message)
        total_file_size = 0
        fs = FileSystemStorage(location='temp/')  # defaults to   MEDIA_ROOT
        for attachment_obj in attachments:
            attachment_url = attachment_obj.get("url")
            content_type, encoding = mimetypes.guess_type(attachment_url)
            file_name = attachment_obj.get("filename") or urlparse(attachment_url).path.split('/')[-1]
            try:
                response = requests.get(url=attachment_url)
                file_size = int(response.headers.get('Content-Length', 0))  # in bytes
                total_file_size += file_size
                if total_file_size < settings.MAX_FILE_UPLOAD_SIZE:
                    file = ContentFile(response.content, name=file_name)
                    filename = fs.save(file.name, file)
                    with open('temp/' + filename, 'rb') as f:
                        # Create a MIME base object for the attachment
                        attachment = MIMEBase(*content_type.split('/'))
                        attachment.set_payload(f.read())
                    encoders.encode_base64(attachment)  # encode the attachment
                    attachment.add_header('Content-Disposition',
                                          f'attachment; filename= {file_name}')
                    os.remove('temp/' + filename)
                else:
                    html = "<a href=" + attachment_url + ">" + attachment_url + "</a><br>"
                    attachment = MIMEText(html, 'html')
                msg.attach(attachment)
            except Exception as e:
                print(str(e))
                return False, str(e)
        if settings.ENVIRONMENT in ('DEV', 'PROD'):
            try:
                smtp = smtplib.SMTP(self.server, self.port)
                smtp.starttls()
                # smtp = smtplib.SMTP_SSL(self.server, self.port)
                smtp.login(self.username, self.password)
                smtp.send_message(msg)
                smtp.quit()
                return True, "Mail sent successfully"
            except Exception as e:
                print(str(e))
                return False, str(e)
        else:
            return False, "Not Supported in this Environment"

    def configure_from_mail(self, mail: str):
        """
           :description: Configures the 'From' email address based on the provided or default email configuration.

           :param mail: The provided 'From' email address.
           :returns: The validated 'From' email address.
        """
        mail_obj = EmailConfigurations.objects.filter(from_mail=mail).first()
        if mail_obj:
            self.configure_smtp_server(mail_obj=mail_obj)
            return mail_obj.from_mail
        else:
            mail_obj = EmailConfigurations.objects.filter(from_mail=settings.DEFAULT_FROM_EMAIL).first()
            self.configure_smtp_server(mail_obj=mail_obj)
            return mail_obj.from_mail

    def configure_smtp_server(self, mail_obj):
        """
            :description: Configures the SMTP server settings based on the email configuration object.

            :param mail_obj: An EmailConfigurations object containing the SMTP server details.
        """
        if mail_obj:
            self.server = mail_obj.server
            self.port = mail_obj.port
            self.password = mail_obj.password
            self.username = mail_obj.user_name

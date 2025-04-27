import base64
import logging
from datetime import datetime, timezone, timedelta
import imaplib
import socket
import re
import requests
from cryptography.fernet import Fernet
from django.db import transaction
from imap_tools import MailBox, AND


from .email_service import MailService
from typing import List
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders, utils

from ..constants import Constant, TokenStatusConstants
from ..models import MailToken, Provider, Email, Thread
from ..utils import format_datetime, convert_timestamp_to_utc


class OtherMail(MailService):
    """
        A service class for managing interactions with other mail providers through SMTP/IMAP protocols.
        Extends the base MailService class to provide additional functionality for sending, receiving, and
        managing email threads.
    """

    def __init__(self, mail_token: MailToken = None, **kwargs):
        """
           Initializes the OtherMail service.

           Parameters:
               mail_token (MailToken): The mail token containing account information.
               **kwargs: Additional arguments passed to the MailService base class.
        """
        super().__init__(mail_token, **kwargs)

    def create_user(self, code, data, **kwargs):
        """
            Connects and creates a new user account with SMTP/IMAP details.

            Parameters:
                code (str): A verification code.
                data (dict): A dictionary containing the SMTP/IMAP server and email details.
                **kwargs: Optional arguments, including 'is_primary' to set this account as primary.

            Returns:
                tuple: (bool, str) indicating success and a corresponding message.
        """
        provider = Provider.objects.get(name=Constant.OTHERS_MAIL_PROVIDER)
        token_obj = MailToken.objects.filter(provider=provider.id, status=TokenStatusConstants.ACTIVE).first()
        if token_obj:
            return False, "You are already connected to a primary mail"
        else:
            smtp_status = self.verify_host_and_port(data.get('smtpserver'), data.get('smtpserverport'))
            imap_status = self.verify_imap_server(data.get('imapserver'), data.get('username', data.get('email')),
                                                  data.get('password'))
            imap_host_port_status = self.verify_host_and_port(data.get('imapserver'), data.get('imapserverport'))
            if smtp_status and imap_status and imap_host_port_status:
                email = data.pop('email')
                token_obj = MailToken.objects.filter(email=email, provider=provider.id).first()
                if token_obj and token_obj.status == TokenStatusConstants.ACTIVE:
                    return False, "Mail already connected Please connect to another mail"
                elif token_obj:
                    data['password'], data['key'] = self.encrypt_password(data['password'], key=self.generate_key())
                    smtp_imap_detail = {
                        "others_mail": data
                    }
                    MailToken.objects.filter(email=email, provider=provider.id).update(
                        email=email,
                        access_token='',
                        refresh_token='',
                        expires_at=datetime.now(), meta=smtp_imap_detail,
                        token_type="EMAIL",
                        status=TokenStatusConstants.ACTIVE,
                        provider=provider,
                        last_sync_time=datetime.now().timestamp(),
                        last_connected_at=datetime.now(),
                    ),
                    return True, f"{email} reconnected successfully"
                else:
                    data['password'], data['key'] = self.encrypt_password(data['password'], key=self.generate_key())
                    smtp_imap_detail = {
                        "others_mail": data
                    }
                    MailToken.objects.create(email=email, access_token='', refresh_token='',
                                             expires_at=datetime.now(), meta=smtp_imap_detail,
                                             token_type="EMAIL",
                                             provider=provider,
                                             last_sync_time=datetime.now().timestamp(),
                                             last_connected_at=datetime.now())
                    return True, f"{email} connected successfully"
        return False, "Error While connecting...."

    @staticmethod
    def verify_imap_server(imap_server, username, password):
        """
            Verifies if the IMAP server connection is valid by attempting to log in.

            Parameters:
                imap_server (str): The IMAP server address.
                username (str): The user's login username.
                password (str): The user's password.

            Returns:
                bool: True if the IMAP connection is successful, False otherwise.
        """
        try:
            mail = imaplib.IMAP4_SSL(imap_server)
            mail.login(username, password)

            mailbox_status, _ = mail.select('inbox')
            if mailbox_status == 'OK':
                mail.close()
                mail.logout()
                return True
            return False

        except:
            return False

    def send_message(self, sender: str,
                     to: List[str],
                     subject: str = '',
                     msg_html: str = None,
                     msg_plain: str = None,
                     cc: List[str] = None,
                     bcc: List[str] = None,
                     attachments: List[str] = None,
                     signature: bool = False,
                     user_id: str = 'me',
                     message_id: str = None,
                     thread_id: str = None):
        """
            Sends an email message using SMTP.

            Parameters:
                sender (str): The sender's email address.
                to (List[str]): List of recipients.
                subject (str): Subject of the email.
                msg_html (str): HTML body of the email.
                msg_plain (str): Plain text body of the email.
                cc (List[str]): List of CC recipients.
                bcc (List[str]): List of BCC recipients.
                attachments (List[str]): List of attachments.
                signature (bool): Flag to include the signature.
                user_id (str): User ID (default is 'me').
                message_id (str): The ID of the message being replied to.
                thread_id (str): The thread ID of the conversation.

                Returns:
                    tuple: (bool, dict) containing the success flag and email metadata.
            """

        message = MIMEMultipart()
        message['From'] = sender
        # to_recipients = ", ".join(recipients)
        message['To'] = ",".join(to)
        message['Subject'] = subject
        if cc and isinstance(cc, list):
            message['Cc'] = ",".join(cc)
            to.extend(cc)
        if bcc and isinstance(bcc, list):
            message['Bcc'] = ",".join(bcc)
            to.extend(bcc)

        if message_id:
            message['In-Reply-To'] = message_id
            message['References'] = message_id
            thread_id = thread_id
        message_id = f'<{datetime.now().strftime("%d%m%Y%H%M%s")}-{self.mail_token.user_id}-{sender}>'
        message['Message-ID'] = message_id
        if not thread_id:
            thread_id = message_id
        body = msg_html
        message.attach(MIMEText(body, 'html'))
        if attachments:
            for attachment in attachments:
                filename = attachment.get('filename')
                data = attachment.get('data')
                self._attach_remote_attachment(message, filename, data)

        server = smtplib.SMTP(self.mail_token.meta.get('others_mail').get('smtpserver'),
                              self.mail_token.meta.get('others_mail').get('smtpserverport'))
        server.starttls()
        server.login(self.mail_token.meta.get('others_mail', {}).get('username', sender),
                     self.decrypt_password(self.mail_token.meta.get('others_mail').get('password'),
                                           self.mail_token.meta.get('others_mail').get('key')))
        server.send_message(message)
        server.quit()
        return True, {
            "id": message_id,
            "threadId": thread_id,
            "internetMessageId": message_id
        }

    @staticmethod
    def get_message_data(message):
        """
            Extracts and returns the plain text or HTML content of a message.

            Parameters:
                message (email.message.Message): The email message object.

            Returns:
                str: The email body, preferring HTML if available, otherwise plain text.
        """
        plain_text = None
        html_text = None

        for part in message.walk():
            if part.get_content_type() == "text/plain":
                if plain_text is None:  # Store the first plain text part found
                    charset = part.get_content_charset() or 'utf-8'
                    plain_text = part.get_payload(decode=True).decode(charset, errors='replace')
            elif part.get_content_type() == "text/html":
                if html_text is None:  # Store the first HTML part found
                    charset = part.get_content_charset() or 'utf-8'
                    html_text = part.get_payload(decode=True).decode(charset, errors='replace')
        if html_text:
            return html_text
        elif plain_text:
            return plain_text
        else:
            return ''

    def get_message_attachments(self, message):
        """
           Retrieves attachments from the message and returns them as a list of attachment objects.

           Parameters:
               message (email.message.Message): The email message object.

           Returns:
               list: A list of attachment objects with details like filename, MIME type, and content.
        """
        attachment_list = []
        for part in message.walk():
            content_disposition = part.get('Content-Disposition')
            if content_disposition is not None:
                content_disposition = str(content_disposition)
                if part.get_content_type() not in ['text/plain', 'text/html']:
                    attachment_obj = {
                        "filename": part.get_filename().replace('\u202f', '') if part.get_filename() else None,
                        "mimetype": part.get_content_type(),
                        "data": part.get_payload(decode=True),
                        "content_id": part.get('Content-ID', '').strip('<>'),
                        "binary_data": True
                    }
                    # attachment_obj['s3_url'] = get_file_and_upload(attachment_obj,message_id=message.get('Message-ID'))
                    if "attachment" in content_disposition:
                        attachment_obj[Constant.IS_INLINE] = False
                    else:
                        attachment_obj[Constant.IS_INLINE] = True

                    attachment_list.append(attachment_obj)
        return attachment_list

    def _attach_remote_attachment(self, msg, filename, url):
        """
           Attaches a file to the message by fetching it from a remote URL.

           Parameters:
               msg (MIMEMultipart): The email message.
               filename (str): The name of the file.
               url (str): The URL to fetch the file from.
        """
        response = requests.get(url)
        if response.status_code == 200:
            base64_data = base64.b64encode(response.content).decode()
            self._attach_base64_attachment(msg, filename, base64_data)

    def _attach_base64_attachment(self, msg, filename, base64_data):
        """
            Attaches a base64 encoded file to an email message.

            Parameters:
            - msg: The MIMEMultipart message object where the attachment will be added.
            - filename: Name of the file to be attached.
            - base64_data: The base64 encoded content of the file.

            Returns:
            - None: The function modifies the `msg` object in-place by adding the attachment.
        """
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(base64.b64decode(base64_data))
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
        msg.attach(part)


    def pull_mail(self, start_date=None, end_date=None):
        """
            Pulls all emails from the IMAP server.

            This function fetches emails, processes them to identify contacts, users, sent/received emails, and updates
            the system with relevant email threads and messages.

            Returns:
            - dict: A dictionary with keys "pulled_mails", "replies", "sent_threads", and "received_threads", representing
              the number of pulled mails, replies, sent threads, and received threads respectively.
        """
        from notification.constants import Constant
        creds = self.mail_token.meta.get('others_mail')
        pulled_mails = 0
        replies = 0
        sent_threads = 0
        received_threads = 0

        start_date = start_date if start_date else datetime.fromtimestamp(self.mail_token.last_sync_time).date()
        end_date = end_date if end_date else datetime.now().date() + timedelta(days=1)

        difference = end_date - start_date
        difference_days = difference.days

        for day in range(difference_days):

            with MailBox(creds.get('imapserver')).login(
                    self.mail_token.meta.get('others_mail', {}).get('username', self.mail_token.email),
                    self.decrypt_password(
                            self.mail_token.meta.get('others_mail').get('password'),
                            self.mail_token.meta.get('others_mail').get('key'))) as mailbox:

                email_messages = []
                emails = []

                current_date = start_date + timedelta(days=day)
                logging.info("fetching mails on " + str(current_date))
                search_criteria = AND(date=current_date)
                folders = mailbox.folder.list()

                for folder in folders:
                    if 'INBOX' in folder.name or 'SENT' in folder.name or 'Inbox' in folder.name or 'Sent' in folder.name:
                        mailbox.folder.set(folder=folder.name)
                        mails = list(mailbox.fetch(criteria=search_criteria))
                        logging.info("Fetched folder" + folder.name)
                        for mail in mails:
                            message_id_list = mail.headers.get('message-id', '')
                            if message_id_list:
                                message_id = str(message_id_list[0])
                            else:
                                continue
                            attachments = []
                            for attachment in mail.attachments:
                                content_id = attachment.content_id
                                is_inline = True if attachment.content_disposition == "inline" else (
                                        content_id != "" and content_id in mail.html)
                                attachment = {
                                    "filename": attachment.filename,
                                    "mimetype": attachment.content_type,
                                    "data": attachment.payload,
                                    "content_id": content_id,
                                    "binary_data": True,
                                    "is_inline": is_inline,
                                }
                                attachments.append(attachment)

                            message_dict = {
                                "message_id": message_id,
                                'subject': mail.subject,
                                'from': [mail.from_],
                                'data': mail.html,
                                'to': list(mail.to),
                                'cc': list(mail.cc),
                                'bcc': list(mail.bcc),
                                'attachments': attachments,
                                'binary_data': True,
                                'mail_created_time': mail.date,
                                Constant.SEND_NOTIFICATION: True,
                                "internet_message_id": message_id,
                                "In-Reply-To": mail.obj['In-Reply-To'] if mail.obj['In-Reply-To'] else "",
                                'date': mail.date_str
                            }
                            email_messages.append(message_dict)
                            emails.append(mail.from_)
                            emails.extend(list(mail.to))
                            emails.extend(list(mail.cc) + list(mail.bcc) if mail.cc or mail.bcc else [])

            self.contacts = self.get_contact_emails(emails=emails)

            # print("Contact with the emails fetched:" + str(self.contacts))
            # print("Users with the emails fetched:" + str(self.users))

            if len(email_messages) > 0:
                email_messages = sorted(email_messages, key=lambda email: email["mail_created_time"])
                for email_message in email_messages:
                    pulled_mails = pulled_mails + 1
                    print("Pulled Mails: " + str(pulled_mails))

                    mail_time = email_message.get("mail_created_time")
                    mail_time = format_datetime(scheduled_at=mail_time,
                                                date_format='%a, %d %b %Y %H:%M:%S %z')

                    mail_time = datetime.strptime(mail_time, '%a, %d %b %Y %H:%M:%S %z').timestamp()
                    if mail_time > self.mail_token.last_sync_time:
                        reply_id = None
                        if email_message.get('In-Reply-To'):
                            reply_id = self.remove_escape_characters(
                                email_message.get('In-Reply-To')).strip()
                        message_reply_obj = Email.objects.filter(message_id=reply_id).first()
                        message_obj = Email.objects.filter(
                            message_id=email_message.get('message_id')).first()
                        if message_reply_obj:
                            # message_list.append(self.format_message_data(email_message))
                            replies = replies + 1
                            if email_message and not message_obj:
                                thread_obj = Thread.objects.filter(thread_id=message_reply_obj.thread.thread_id).first()
                                if thread_obj:
                                    self.create_email_and_attachments(email_message, thread_obj=thread_obj)
                        else:
                            sent_thread_status = False
                            received_thread_status = False
                            sender = email_message.get('from')[0] if len(email_message.get('from')) > 0 else ""
                            mail_sender, check_user, check_contact = self.check_mail_sender_user_contact(
                                sender=sender)
                            if mail_sender:
                                to = self.check_recipients_in_user_and_contacts(list(
                                    set(email_message.get('to'))))
                                cc = self.check_recipients_in_user_and_contacts(list(set
                                                                                     (email_message.get('cc'))))
                                bcc = self.check_recipients_in_user_and_contacts(list(
                                    set(email_message.get('bcc'))))
                                if to or bcc or cc:
                                    sent_thread_status = True
                                    email_message[Constant.MAIL_STATUS] = Constant.DELIVERED
                                    self.create_thread_and_message_data(email_message,
                                                                        threadId=email_message.get(
                                                                            'message_id'),
                                                                        sender=sender,
                                                                        mail_status=Constant.DELIVERED)
                            elif check_user:
                                received_thread_status = True
                                email_message[Constant.MAIL_STATUS] = Constant.RECEIVED
                                self.create_thread_and_message_data(message=email_message,
                                                                    threadId=email_message.get(
                                                                        'message_id'),
                                                                    sender=sender,
                                                                    mail_status=Constant.RECEIVED)

                            elif check_contact:
                                received_thread_status = True
                                email_message[Constant.MAIL_STATUS] = Constant.RECEIVED
                                self.create_thread_and_message_data(message=email_message,
                                                                    threadId=email_message.get(
                                                                        'message_id'),
                                                                    sender=sender,
                                                                    mail_status=Constant.RECEIVED)

                            if sent_thread_status:
                                sent_threads = sent_threads + 1
                            if received_thread_status:
                                received_threads = received_threads + 1

        return {
            "pulled_mails": pulled_mails,
            "replies": replies,
            "sent_threads": sent_threads,
            "received_threads": received_threads

        }

    def format_message_data(self, mail_message):
        """
           Formats email message data into a structured dictionary.

           Parameters:
           - mail_message: The raw email message object to be formatted.

           Returns:
           - dict: A dictionary containing structured email data, including message ID, subject,
             sender, recipients, attachments, and creation time.
        """

        message_dict = {
            "message_id": self.remove_escape_characters(mail_message.get('Message-ID')).strip(),
            'subject': mail_message.get('subject'),
            'from': self.extract_emails_from_str(mail_message.get('From')),
            'data': self.get_message_data(mail_message),
            'to': self.extract_emails_from_str(mail_message.get('To')),
            'cc': self.extract_emails_from_str(mail_message.get('Cc')),
            'bcc': self.extract_emails_from_str(mail_message.get('Bcc', )),
            'attachments': self.get_message_attachments(mail_message),
            'binary_data': True,
            'mail_created_time': utils.parsedate_to_datetime(mail_message.get('date')),
            Constant.SEND_NOTIFICATION: True,
            "internet_message_id": self.remove_escape_characters(mail_message.get('Message-ID')).strip(),
            "In-Reply-To": mail_message.get('In-Reply-To'),
            'date': mail_message.get('date')

        }

        return message_dict

    def verify_host_and_port(self, host, port):
        """
           Verifies if a given host and port are accessible.

           Parameters:
           - host: The hostname or IP address to check.
           - port: The port number to check.

           Returns:
           - bool: True if the host and port are accessible, False otherwise.
        """
        try:
            ip_address = socket.gethostbyname(host)

            with socket.create_connection((ip_address, port), timeout=15):
                return True

        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception as e:
            return False

    def encrypt_password(self, password: str, key):
        """
            Encrypts a password using a given encryption key.

            Parameters:
            - password: The password to encrypt.
            - key: The encryption key to use for encryption.

            Returns:
            - tuple: A tuple containing the encrypted password and the key used.
        """
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return (
            encrypted_password.decode('utf-8'), key.decode('utf-8')
        )

    def decrypt_password(self, password: str, key: str):
        """
           Decrypts a previously encrypted password using the corresponding key.

           Parameters:
           - password: The encrypted password to decrypt.
           - key: The key to use for decryption.

           Returns:
           - str: The decrypted password.
        """
        cipher_suite = Fernet(key.encode('utf-8'))
        decrypted_password = cipher_suite.decrypt(password.encode('utf-8')).decode()
        return decrypted_password

    def generate_key(self):
        """
            Generates a new encryption key using the Fernet symmetric encryption method.

            Returns:
            - bytes: The generated encryption key.
        """
        key = Fernet.generate_key()
        return key

    def create_thread_and_message_data(self, message, threadId, sender, mail_status):
        """
            Creates a new thread and message data in the database.

            Parameters:
            - message: The email message data.
            - threadId: The unique identifier for the thread.
            - sender: The sender of the email.
            - mail_status: The status of the email (sent or received).

            Returns:
            - None: This method modifies the database in-place.
        """
        with transaction.atomic():
            sent, inbox = self.get_sent_and_inbox_values(mail_status=mail_status)
            thread_obj = Thread.objects.filter(thread_id=threadId).first()
            if message and not thread_obj:
                thread_obj = Thread.objects.create(thread_id=threadId, size=0, provider=self.mail_token.provider,
                                                   participants={}, sender=sender, user_id=self.mail_token.user_id,
                                                   thread_owner=self.mail_token.email, is_sent=sent, is_inbox=inbox,
                                                   last_active_time=message.get('mail_created_time'))
                thread_obj.participants = self.build_mail_thread_participants(message)
                thread_obj.save()
                message[Constant.MAIL_STATUS] = mail_status
                self.create_email_and_attachments(data=message, thread_obj=thread_obj)

    @staticmethod
    def get_mail_box_name(folder_info):
        """
            Extracts the mailbox name from folder information.

            Parameters:
            - folder_info: The folder information returned by the IMAP server.

            Returns:
            - tuple: A tuple containing a boolean indicating if the mailbox is relevant
              (either sent or inbox) and the mailbox name if relevant.
        """
        mailbox = ""
        new_val = str(folder_info.decode('utf-8'))
        if ('sent' in new_val.lower()) or ('inbox' in new_val.lower()):
            mailbox = new_val.split('"/"')[len(new_val.split('"/"')) - 1].strip()
            return True, mailbox
        return False, mailbox

    @staticmethod
    def remove_escape_characters(input_string):
        """
            Removes escape characters from a string.

            Parameters:
            - input_string: The input string potentially containing escape characters.

            Returns:
            - str: The cleaned string without escape characters.
        """
        escape_characters_pattern = r'[\n\r\t\b\f\v\\]'
        cleaned_string = re.sub(escape_characters_pattern, '', input_string)

        return cleaned_string

    def get_mail_messages(self, mail):
        """
           Retrieves email messages from the IMAP server.

           Parameters:
           - mail: The IMAP connection object.

           Returns:
           - list: A sorted list of email messages with their respective dates.
        """
        from email import message_from_bytes
        status, folder_list = mail.list()
        # Iterate over each folder
        list_mails = []
        for folder_info in folder_list:
            status, mailbox_name = self.get_mail_box_name(folder_info)
            if status:
                mail_box = mail.select(mailbox_name)

                # Define the search criteria
                search_criteria = '(SINCE {})'.format(
                    convert_timestamp_to_utc(timestamp=self.mail_token.last_sync_time, format="%d-%b-%Y"))

                # Search for emails within the selected folder based on the criteria
                status, messages = mail.search(None, search_criteria)
                if status == 'OK':
                    mail_ids = messages[0].split()
                    for email_id in mail_ids:
                        try:
                            status, msg_data = mail.fetch(email_id, '(RFC822)')
                            for response_part in msg_data:
                                if isinstance(response_part, tuple):
                                    email_message = message_from_bytes(response_part[1])

                                    list_mails.append({
                                        'data': email_message,
                                        'date': self.make_aware_to_utc(
                                            utils.parsedate_to_datetime(email_message.get('date')))
                                    })
                        except:
                            pass
        sorted_emails = sorted(list_mails, key=lambda x: x['date'])
        return sorted_emails

    @staticmethod
    def make_aware_to_utc(dt):
        """
            Converts a naive or aware datetime object to UTC.

            Parameters:
            - dt: The datetime object to convert.

            Returns:
            - datetime: The converted datetime object in UTC.
        """
        if dt.tzinfo is None:  # Offset-naive datetime
            return dt.replace(tzinfo=timezone.utc)
        else:  # Offset-aware datetime
            return dt.astimezone(timezone.utc)

    def get_message_emails_and_data(self, message_list):
        """
            Extracts and formats email addresses and data from a list of messages.

            Parameters:
            - message_list: A list of raw email messages.

            Returns:
            - tuple: A list of formatted email message data and a list of email addresses found.
        """
        formatted_data_list = []
        message_mails = []
        for message in message_list:
            formatted_data = self.format_message_data(message.get('data'))
            if formatted_data:
                message_mails.extend(formatted_data.get('from'))
                message_mails.extend(formatted_data.get('to'))
                message_mails.extend(formatted_data.get('cc'))
                message_mails.extend(formatted_data.get('bcc'))
                formatted_data_list.append(formatted_data)
        return formatted_data_list, message_mails

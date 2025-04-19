import base64
import logging
import re
from datetime import datetime, timedelta
from email import policy, encoders, utils
from email.mime.base import MIMEBase

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from io import BytesIO
from typing import List

import requests
from django.db import transaction
from google.auth.transport.requests import Request
from google.oauth2 import credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

from notification.constants import Constant, TokenStatusConstants
from notification.models import MailToken, Provider, Thread, Email
from notification.services.email_service import MailService


class Gmail(MailService):

    def __init__(self, mail_token: MailToken = None, **kwargs):
        """
           Initializes the Gmail service with the given mail token.

           Parameters:
           - mail_token: An instance of MailToken containing the user's OAuth credentials.
           - **kwargs: Additional keyword arguments.
        """
        super().__init__(mail_token)
        if self.mail_token:
            self.credentials = self.get_credentials()
            self.service = build('gmail', 'v1', credentials=self.credentials)

    def update_mail_token(self, access_token, refresh_token, expires_at):
        """
            Updates the mail token with new access and refresh tokens.

            Parameters:
            - access_token: The new access token.
            - refresh_token: The new refresh token.
            - expires_at: The expiration time of the access token.
        """
        self.mail_token.access_token = str(access_token)
        self.mail_token.refresh_token = str(refresh_token)
        self.mail_token.expires_at = expires_at
        self.mail_token.save()

    def get_credentials(self):
        """
           Retrieves and refreshes OAuth credentials for the Gmail API.

           Returns:
           - credentials: The refreshed credentials object.
        """
        # TODO cache providers objects
        provider_obj = Provider.objects.get(name=Constant.GOOGLE_MAIL_PROVIDER)
        # user = ThreadContainer.get_current_user_id()
        token_obj = self.mail_token
        credentials_json = {
            "client_id": provider_obj.client_id,
            "client_secret": provider_obj.client_secret,
            "token": token_obj.access_token,
            "refresh_token": token_obj.refresh_token,
            "token_uri": "https://oauth2.googleapis.com/token",
            "scopes": provider_obj.scope.get('SCOPE'),
            "grant_type": "refresh_token"
        }
        creds = credentials.Credentials.from_authorized_user_info(credentials_json)

        if not creds.valid:
            try:
                creds.refresh(Request())
                self.update_mail_token(access_token=creds.token, refresh_token=creds.refresh_token,
                                       expires_at=creds.expiry)
            except Exception as e:
                self.discard_mail_token()
                return

        return creds

    def get_provider_url(self, **kwargs):
        """
           Constructs the OAuth authorization URL for the Gmail provider.

           Parameters:
           - **kwargs: Additional keyword arguments (e.g., is_primary).

           Returns:
           - str: The constructed authorization URL.
        """
        provider_obj = Provider.objects.get(name=Constant.GOOGLE_MAIL_PROVIDER)
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={provider_obj.client_id}&redirect_uri={self.get_redirect_url(provider_obj=provider_obj)}&response_type=code&scope={' '.join(provider_obj.scope.get('SCOPE'))}&access_type=offline&prompt=consent"
        return auth_url

    def create_user(self, code, data, **kwargs):
        """
            Creates a user account by exchanging the authorization code for tokens.

            Parameters:
            - code: The authorization code received from Google.
            - data: Additional data for user creation.
            - **kwargs: Additional keyword arguments (e.g., is_primary).

            Returns:
            - tuple: A boolean indicating success and a message.
        """
        provider_obj = Provider.objects.get(name=Constant.GOOGLE_MAIL_PROVIDER)
        token_obj = MailToken.objects.filter(provider=provider_obj.id,
                                             status=TokenStatusConstants.ACTIVE)
        if token_obj:
            return False, "You are already connected to a primary mail"
        else:
            token_response = {
                "client_id": provider_obj.client_id,
                "client_secret": provider_obj.client_secret,
                "code": code,
                "redirect_uri": self.get_redirect_url(provider_obj=provider_obj),
                "grant_type": "authorization_code",
            }
            response = requests.post(url="https://oauth2.googleapis.com/token", data=token_response)
            email = None
            if response.status_code == 200:
                data = response.json()
                credentials_json = {
                    "client_id": provider_obj.client_id,
                    "client_secret": provider_obj.client_secret,
                    "token": data.get('access_token'),
                    "refresh_token": data.get('refresh_token'),
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "grant_type": "refresh_token"
                }
                creds = credentials.Credentials.from_authorized_user_info(credentials_json)
                service = build('gmail', 'v1', credentials=creds)
                profile = service.users().getProfile(userId='me').execute()

                # profile = service.people().get(resourceName='google/me', personFields='emailAddresses').execute()
                required_scopes = provider_obj.scope.get('SCOPE')
                scope_verify_url = "https://www.googleapis.com/oauth2/v3/tokeninfo"
                headers = {
                    "Authorization": "Bearer " + data.get('access_token')
                }
                scope_verify_response = requests.get(url=scope_verify_url, headers=headers)
                if scope_verify_response.status_code == 200:
                    given_scopes = scope_verify_response.json().get('scope').split(' ')
                    if self.verify_scopes(required_scopes=required_scopes, given_scopes=given_scopes):
                        email = profile.get('emailAddress')

                        resp = requests.get(url="https://www.googleapis.com/oauth2/v1/userinfo",
                                                          headers=headers)
                        name = ''
                        if resp.status_code == 200:
                            name = resp.json().get('name')
                        current_datetime = datetime.now()
                        token_obj = MailToken.objects.filter(email=email, provider=provider_obj.id).first()
                        if token_obj and token_obj.status == TokenStatusConstants.ACTIVE:
                            return False, "Mail already connected Please connect to another mail"
                        elif token_obj:
                            MailToken.objects.filter(email=email, provider=provider_obj.id).update(
                                provider=provider_obj,
                                email=email,
                                access_token=data.get('access_token'),
                                refresh_token=data.get('refresh_token'),
                                expires_at=current_datetime + timedelta(seconds=data.get('expires_in')),
                                status=TokenStatusConstants.ACTIVE,
                                token_type="EMAIL",
                                meta={'name': name},
                                last_sync_time=datetime.now().timestamp(),
                                last_connected_at=datetime.now(),
                            )
                            return True, f"{email} reconnected successfully"
                        else:
                            MailToken.objects.create(provider=provider_obj, email=email,
                                                     access_token=data.get('access_token'),
                                                     refresh_token=data.get('refresh_token'),
                                                     expires_at=current_datetime + timedelta(
                                                         seconds=data.get('expires_in')),
                                                     token_type="EMAIL",
                                                     meta={'name': name},
                                                     last_sync_time=datetime.now().timestamp(),
                                                     last_connected_at=datetime.now(),)
                            return True, f"{email} connected successfully"
                    return False, "Please provide all the required scopes"
                return False, "Error While connecting...."

    def send_message(
            self,
            sender: str,
            to: str,
            subject: str = '',
            msg_html: str = None,
            msg_plain: str = None,
            cc: List[str] = None,
            bcc: List[str] = None,
            attachments: List[str] = None,
            signature: bool = False,
            user_id: str = 'me',
            message_id: str = None,
            thread_id: str = None,

    ):
        """
               Sends an email message using the Gmail API.

               Parameters:
               - sender: The email address of the sender.
               - to: The recipient's email address(es).
               - subject: The subject of the email.
               - msg_html: The HTML body of the email.
               - msg_plain: The plain text body of the email.
               - cc: List of CC email addresses.
               - bcc: List of BCC email addresses.
               - attachments: List of attachments to include in the email.
               - signature: Boolean indicating whether to include a signature.
               - user_id: The user ID (default is 'me').
               - message_id: The ID of the message being replied to (optional).
               - thread_id: The ID of the thread to which the message belongs (optional).

               Returns:
               - tuple: A boolean indicating success and the response data.
               """

        msg = self._create_message(
            sender, to, subject, msg_html, msg_plain, cc=cc, bcc=bcc,
            attachments=attachments, signature=signature, user_id=user_id, message_id=message_id,
            thread_id=thread_id
        )
        try:
            media = MediaIoBaseUpload(BytesIO(msg.get('raw').as_bytes()), mimetype='message/rfc822', resumable=True)
            body_metadata = {
                "threadId": msg.get('threadId')
            }
            resp = self.service.users().messages().send(userId='me', body=body_metadata,
                                                        media_body=media).execute()
            if resp:
                internet_message_id = self.get_internet_message_id(message_id=resp.get('id'))
                resp['internetMessageId'] = internet_message_id
                return True, resp
            return False, resp  # TODO check the error msg

        except HttpError as error:
            raise error

    def _create_message(
            self,
            sender: str,
            to: List[str],
            subject: str = '',
            msg_html: str = None,
            msg_plain: str = None,
            cc: List[str] = None,
            bcc: List[str] = None,
            message_id: str = None,
            thread_id: str = None,
            attachments: List[str] = None,
            signature: bool = False,
            user_id: str = 'me',
    ) -> dict:
        """
                Creates a MIME message for the email to be sent.

                Parameters:
                - sender: The email address of the sender.
                - to: List of recipient email addresses.
                - subject: The subject of the email.
                - msg_html: The HTML body of the email.
                - msg_plain: The plain text body of the email.
                - cc: List of CC email addresses.
                - bcc: List of BCC email addresses.
                - message_id: The ID of the message being replied to (optional).
                - thread_id: The ID of the thread to which the message belongs (optional).
                - attachments: List of attachments to include in the email.
                - signature: Boolean indicating whether to include a signature.
                - user_id: The user ID (default is 'me').

                Returns:
                - dict: A dictionary containing the raw MIME message and the thread ID.
            """

        msg = MIMEMultipart('mixed' if attachments else 'alternative')
        if isinstance(to, list):
            msg['To'] = ",".join(to)
        msg['From'] = sender
        msg['Subject'] = subject
        msg['Content_Type'] = "text/html; charset='UTF-8"
        msg['Content-Transfer-Encoding'] = "base64"

        if message_id:
            msg['In-Reply-To'] = self.reply_to(message_id)
            msg['References'] = self.reply_to(message_id)
        if cc:
            msg['Cc'] = ', '.join(cc)

        if bcc:
            msg['Bcc'] = ', '.join(bcc)

        if signature:
            m = re.match(r'.+\s<(?P<addr>.+@.+\..+)>', sender)
            address = m.group('addr') if m else sender
            account_sig = self._get_alias_info(address, user_id)['signature']

            if msg_html is None:
                msg_html = ''

            msg_html += "<br /><br />" + account_sig

        # attach_plain = MIMEMultipart('alternative') if attachments else msg
        # attach_html = MIMEMultipart('related') if attachments else msg

        if msg_plain:
            msg.attach(MIMEText(msg_plain, 'plain'))

        if msg_html:
            msg.attach(MIMEText(msg_html, 'html'))

        if attachments:
            for attachment in attachments:
                filename = attachment.get('filename')
                data = attachment.get('data')
                self._attach_remote_attachment(msg, filename, data)

        return {
            'raw': msg,
            'threadId': thread_id
        }

    def _attach_base64_attachment(self, msg, filename, base64_data):
        """
            Attaches a base64-encoded file to the email message.

            Parameters:
            - msg: The email message to which the attachment will be added.
            - filename: The name of the attachment file.
            - base64_data: The base64-encoded content of the attachment.
        """

        part = MIMEBase('application', 'octet-stream')
        part.set_payload(base64.b64decode(base64_data))
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
        msg.attach(part)

    def _attach_remote_attachment(self, msg, filename, url):
        """
           Downloads a file from a URL and attaches it to the email message.

           Parameters:
           - msg: The email message to which the attachment will be added.
           - filename: The name of the attachment file.
           - url: The URL from which to download the attachment.
        """
        response = requests.get(url)
        if response.status_code == 200:
            base64_data = base64.b64encode(response.content).decode()
            self._attach_base64_attachment(msg, filename, base64_data)

    def _get_alias_info(
            self,
            send_as_email: str,
            user_id: str = 'me'
    ) -> dict:
        """
            Retrieves information about the alias for sending emails.

            Parameters:
            - send_as_email: The email address used for sending.
            - user_id: The user ID (default is 'me').

            Returns:
            - dict: The alias information.
        """
        req = self.service.users().settings().get(
            sendAsEmail=send_as_email, userId=user_id)

        res = req.execute()
        return res

    def get_header_value(self, headers: list, name):
        """
            Retrieves the value of a specified header from the list of headers.

            Parameters:
            - headers: The list of headers.
            - name: The name of the header to retrieve.

            Returns:
            - str: The value of the specified header or None if not found.
        """
        for header in headers:
            if header['name'] == name:
                return header['value']

    def reply_to(self, message_id):
        """
           Retrieves the 'Message-ID' of a specified email message to use for replies.

           Parameters:
           - message_id: The ID of the message to reply to.

           Returns:
           - str: The 'Message-ID' of the specified message or None if not found.
        """
        resp = self.service.users().messages().get(userId='me', id=message_id, format='metadata',
                                                   metadataHeaders=['Subject', 'References',
                                                                    'Message-ID']).execute()
        if resp:
            data = resp
            val = self.get_header_value(data.get('payload').get('headers'), 'Message-ID')
            if val is None:
                val = self.get_header_value(data.get('payload').get('headers'), 'Message-Id')
            return val

    def pull_mail(self):
        """
            Pulls emails from the user's inbox and updates their statuses.

            Returns:
            - dict: A summary of pulled mails, replies, sent threads, and received threads.
        """
        pulled_mails = 0
        replies = 0
        sent_threads = 0
        received_threads = 0
        messages, emails = self.get_message_emails_and_data(message_list=self.message_resp_data())
        self.contacts = self.get_contact_emails(emails=emails)

        if messages:
            for message_data in messages:
                thread_obj = Thread.objects.filter(thread_id=message_data.get('threadID'),
                                                   user_id=self.mail_token.user_id).first()
                pulled_mails = pulled_mails + 1
                if thread_obj:
                    message_obj = Email.objects.filter(message_id=message_data.get('message_id')).first()
                    if not message_obj:
                        replies = replies + 1
                        if message_data:
                            message_data[Constant.MAIL_STATUS] = Constant.RECEIVED
                            self.create_email_and_attachments(message_data, thread_obj)
                else:
                    sent_thread_status = False
                    received_thread_status = False
                    sender = message_data.get('from')
                    if len(sender):
                        sender = sender[0]
                    mail_sender, check_user, check_contact = self.check_mail_sender_user_contact(sender=sender)
                    if mail_sender:
                        to = self.check_recipients_in_user_and_contacts(list(
                            set(message_data.get('to'))))
                        cc = self.check_recipients_in_user_and_contacts(list(set
                                                                             (message_data.get('cc'))), )
                        bcc = self.check_recipients_in_user_and_contacts(list(
                            set(message_data.get('bcc'))))
                        if to or bcc or cc:
                            sent_thread_status = True
                            message_data[Constant.MAIL_STATUS] = Constant.DELIVERED
                            self.create_thread_and_message_data(message=message_data,
                                                                threadId=message_data.get('threadID'),
                                                                sender=sender, mail_status=Constant.DELIVERED)
                    elif check_user:
                        received_thread_status = True
                        self.create_thread_and_message_data(message=message_data, threadId=message_data.get('threadID'),
                                                            sender=sender, mail_status=Constant.RECEIVED)
                    elif check_contact:
                        received_thread_status = True
                        self.create_thread_and_message_data(message=message_data, threadId=message_data.get('threadID'),
                                                            sender=sender, mail_status=Constant.RECEIVED)
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

    def get_attachment_data(self, message_id, attachment_id):
        """
           Retrieves the data of a specified attachment from a message.

           Parameters:
           - message_id: The ID of the message containing the attachment.
           - attachment_id: The ID of the attachment to retrieve.

           Returns:
           - str: The data of the attachment.
        """
        logging.info(attachment_id)
        resp = self.service.users().messages().attachments().get(userId='me', messageId=message_id,
                                                                 id=attachment_id).execute()
        if resp:
            return resp.get('data')

    @staticmethod
    def get_message_data(message):
        """
            Extracts the HTML content from a MIME message.

            Parameters:
            - message: The MIME message object.

            Returns:
            - str: The HTML content of the message or None if unable to decode.
        """
        for part in message.walk():
            if part.get_content_type() == "text/html":
                charset = part.get_content_charset() or 'utf-8'
                try:
                    content = part.get_payload(decode=True).decode(charset, errors='replace')
                    return content
                except UnicodeDecodeError:
                    return None

    def get_message_attachments(self, message):
        """
            Retrieves attachments from a MIME message.

            Parameters:
            - message: The MIME message object.

            Returns:
            - list: A list of attachment dictionaries.
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

    def format_message_data(self, mail_message, message_id, thread_id):
        """
            Formats a message's data into a structured dictionary.

            Parameters:
            - mail_message: The original mail message.
            - message_id: The ID of the message.
            - thread_id: The ID of the thread.

            Returns:
            - dict: A structured dictionary containing message details.
        """
        message_dict = {
            "message_id": message_id,
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
            "internet_message_id": mail_message.get('Message-ID'),
            'threadID': thread_id
        }

        return message_dict

    @staticmethod
    def bulid_header_values(headers: list, key):
        """
            Retrieves the value of a specified header from a list of headers.

            Parameters:
            - headers: The list of headers.
            - key: The name of the header to retrieve (case insensitive).

            Returns:
            - str: The value of the specified header or None if not found.
        """
        for header in headers:
            if header['name'].lower() == key.lower():
                return header['value']

    def create_thread_and_message_data(self, message, threadId, sender, mail_status):
        """
        it is used to create a thread
        """
        with transaction.atomic():
            sent, inbox = self.get_sent_and_inbox_values(mail_status=mail_status)
            if len(message):
                thread_obj = Thread.objects.create(thread_id=threadId, size=0, provider=self.mail_token.provider,
                                                   participants={}, sender=sender,
                                                   user_id=self.mail_token.user_id,
                                                   thread_owner=self.mail_token.email, is_sent=sent, is_inbox=inbox,
                                                   last_active_time=message.get('mail_created_time'))
                message[Constant.MAIL_STATUS] = mail_status
                self.create_email_and_attachments(data=message, thread_obj=thread_obj)

    def convert_str_to_html(self, text: str):
        """
        converts the string to html format
        """
        if text:
            html_text = ""

            for line in text.split('\n'):
                html_text += f'<p>{line}</p>\n'
            return html_text
        return text

    def get_internet_message_id(self, message_id):
        """
        returns the internet message id for a particular message id
        """
        message_res = self.service.users().messages().get(userId='me', id=message_id).execute()
        if message_res:
            message_parts = message_res.get('payload')
            headers = message_parts.get('headers')
            return self.bulid_header_values(headers, 'Message-Id')

    def get_message_content(self, message_id: str, thread_id):
        """
        it is used to retrieve the message content using the raw format for a particular thread id and formats the data and returns it
        """
        resp = self.service.users().messages().get(userId='me', id=message_id,
                                                   format='raw').execute()
        if resp:
            raw_data = resp.get('raw')
            raw_bytes = base64.urlsafe_b64decode(raw_data)
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            email_data = self.format_message_data(mail_message=msg, message_id=message_id, thread_id=thread_id)
            return email_data

    def message_resp_data(self):
        """
        returns the list of formatted mail messages after a particular date time
        """
        # formatted_date = datetime.fromtimestamp(int(self.mail_token.last_sync_time)).strftime('%Y/%m/%d')
        formatted_date = int(self.mail_token.last_sync_time)
        query = f'after:{formatted_date}'
        messages = []
        nextPageToken = None

        while True:
            req = self.service.users().messages().list(userId='me', q=query, pageToken=nextPageToken)
            resp = req.execute()
            if resp:
                messages.extend(resp.get('messages', []))
                nextPageToken = resp.get('nextPageToken')
                if not nextPageToken:
                    break
            else:
                break
        return messages

    def get_message_emails_and_data(self, message_list):
        """
        retrieves the message info from the list of message_ids and appends them to the list and returns it
        """
        formatted_data_list = []
        message_mails = []
        for message in message_list:
            formatted_data = self.get_message_content(message_id=message.get('id'), thread_id=message.get('threadId'))
            message_mails.extend(formatted_data.get('from'))
            message_mails.extend(formatted_data.get('to'))
            message_mails.extend(formatted_data.get('cc'))
            message_mails.extend(formatted_data.get('bcc'))
            formatted_data_list.append(formatted_data)
        return formatted_data_list, message_mails

    @staticmethod
    def verify_scopes(required_scopes, given_scopes):
        """
        checks whether the given scopes are present in the required scopes
        """
        for scopes in required_scopes:
            if scopes not in given_scopes:
                return False
        return True

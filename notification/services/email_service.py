import re
from datetime import datetime

from django.db.models import F, Func, Value
from rest_framework.response import Response

from notification.constants import Constant, TokenStatusConstants
from notification.models import MailToken, Provider, Email, Thread
from notification.serializers import MailSerializer
from notification.services.provider_request_service import ProviderService

from notification.tasks import send_mail


class MailService(object):
    def __init__(self, mail_token: MailToken = None, **kwargs):
        self.mail_token: MailToken = mail_token
        self.contacts = {}
        self.users = {}
        self.marketing_contacts = {}

    @staticmethod
    def get_contact_emails(emails):
        """
        gets all the contacts info with given list of emails
        """
        return {}

    def send_mail(self):
        raise Exception("send_mail method not implemented")

    def get_message(self):
        raise Exception("get_message not implemented")

    @staticmethod
    def get_redirect_url(provider_obj: Provider):
        """
        return the redirect url based upon whether it is primary or secondary mail
        """
        redirect_url = provider_obj.redirect_url.get('redirect_url')
        return redirect_url

    @staticmethod
    def get_auth_url_from_provider(provider):
        """
        returns the auth url based upon the specified provider
        """
        try:
            executor = ProviderService(provider).get_provider_executor()
            url = executor().get_provider_url()
            return url
        except Exception as e:
            return str(e)

    @staticmethod
    def create_mail_user(provider, code, data, is_primary):
        """
        used to create user(basically maps to mail token to which type of configuration they selects like google mail,outlook mail,zoho mail
        """
        try:
            executor = ProviderService(provider).get_provider_executor()
            status, email = executor().create_user(code, data, is_primary=is_primary)
            return status, email
        except Exception as e:
            return False, str(e)

    def create_email_and_attachments(self, data, thread_obj):
        """

        """
        mail_status = None
        try:
            sender = data.get('from')[0]
            sender_email = sender.lower()
            email_obj = Email.objects.filter(thread_id=thread_obj.id).order_by('-created_at').first()
            if Constant.GOOGLE_TRACK_MAIL in sender_email or Constant.OUTLOOK_TRACK_MAIL in sender_email or Constant.ZOHO_TRACK_MAIL in sender_email or any(mail in sender_email for mail in Constant.OTHER_BOUNCED_TRACK_MAILS):
                if email_obj.mail_status != Constant.BOUNCED:
                    email_obj.mail_status = Constant.BOUNCED
                    email_obj.save()
                    mail_status = Constant.BOUNCED
            else:
                mail_status = "REPLY"
                meta = {
                    'provider': thread_obj.provider.name
                }
                attachments = data.get('attachments')
                body = data.get('data')

                email_obj = Email.objects.create(message_id=data.get('message_id'),
                                                 sender=sender,
                                                 recipients=data.get('to'),
                                                 body=body,
                                                 subject=data.get('subject'),
                                                 meta=meta, thread_id=thread_obj.id,
                                                 time_stamp=int(datetime.now().timestamp() * 1000),
                                                 mail_status=data.get('mail_status'),
                                                 cc=data.get('cc'),
                                                 bcc=data.get('bcc'),
                                                 mail_created_time=data.get('mail_created_time'),
                                                 internet_message_id=data.get('internet_message_id'))
                email_obj.refresh_from_db()

                thread_obj = self.update_message_thread(thread_obj=thread_obj, from_mail=sender)

        except Exception as e:
            serializer = MailSerializer
            mails_objs = Email.objects.filter(thread_id=thread_obj.id)
            ser = serializer(mails_objs, many=True)
            return Response(ser.data)

    def extract_emails_from_str(self, mail):
        """
        extracts emails from given string using the regex pattern
        """
        if mail:
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, mail)
            return emails
        return []

    def check_the_email_user(self, email):
        mail_tokens_emails = MailToken.objects.exclude(email=self.mail_token.email).filter(
            email=email).first()
        if mail_tokens_emails:
            return mail_tokens_emails.user_id

        return self.users.get(email, None)

    def get_sent_and_inbox_values(self, mail_status: str):
        """

        """
        sent = 0
        inbox = 0
        if mail_status in [Constant.DELIVERED, Constant.BOUNCED, Constant.READ]:
            sent = 1
        else:
            inbox = 1
        return sent, inbox

    def check_the_email_contact(self, email):
        """
        checks whether the given email is present in the loaded contacts
        """
        return self.contacts.get(email, None)


    def check_recipients_in_user_and_contacts(self, emails: list):
        """
        check whether a particular email belongs to a user or a contact
        """
        if emails:
            mail_token_obj = MailToken.objects.exclude(email=self.mail_token.email).filter(
                email__in=emails).first()
            if mail_token_obj:
                return True

            for email in emails:
                if self.contacts.get(email):
                    return True
            return False



    def discard_mail_token(self):
        """
        it deletes the mail token
        """
        mail_token_obj = MailToken.objects.filter(id=self.mail_token.id).first()
        if mail_token_obj:
            mail_token_obj.status = TokenStatusConstants.EXPIRED
            mail_token_obj.save()
        # mail_token_obj.delete()

    def check_mail_sender_user_contact(self, sender):
        """
        check whether the particular mail sender is user or contact
        """
        if sender == self.mail_token.email:
            return True, False, False
        else:
            check_user = self.check_the_email_user(email=sender)
            if check_user:
                return False, True, False
            check_contact = self.check_the_email_contact(email=sender)
            if check_contact:
                return False, False, True
        return False, False, False

    def update_message_thread(self, thread_obj, from_mail):
        """
        updates the thread object fields like size and folders which it should be present based upon the incoming
        mail messages
        """
        if thread_obj and self.mail_token.email == from_mail:
            thread_obj.is_sent = True
        else:
            thread_obj.is_inbox = True

        email_count = Email.objects.filter(thread=thread_obj).count()
        if email_count > 0:
            thread_obj.size = email_count
            latest_email = Email.objects.filter(thread=thread_obj).order_by('-mail_created_time').first()
            thread_obj.latest_message_id = latest_email.id
            thread_obj.last_active_time = latest_email.mail_created_time
        thread_obj.save()
        return thread_obj

    def send_mail_message(self, provider, mail_token, sender, to, recipients, subject, msg_html, cc, bcc,
                        thread_id=None, message_id=None,
                          timestamp=int(datetime.now().timestamp() * 1000),
                          **kwargs
                          ):
        """
        it is used to send mail message based on the parameters if the scheduled time is specified then the mail will
        be scheduled or else the mail will be added to celery and processed asyncronously
        """
        thread_obj = self.get_thread_obj(thread_id)

        provider_obj = Provider.objects.filter(name=provider).first()
        dummy_message_id = self.generate_unique_identifier()

        email_list = self.aggregate_email_list(recipients, cc, bcc, self.mail_token.email)
        self.contacts = self.get_contact_emails(emails=email_list)
        # self.users = self.get_all_users_for_tenant(emails=email_list)

        meta = self.build_email_meta(provider, recipients, cc, bcc)
        email_params = self.prepare_email_params(dummy_message_id, sender, recipients, subject, msg_html, cc, bcc, meta,
                                                 timestamp, kwargs.get('timezone'))

        email_message = self.handle_email_thread_creation(thread_obj, email_params, provider_obj,
                                                          {},
                                                          sender, dummy_message_id)

        send_mail(sender=sender, provider=provider, cc=cc, bcc=bcc, to=to, msg_html=msg_html, subject=subject,
                                                   dummy_message_id=dummy_message_id, thread_id=thread_id, message_id=message_id,
                                                   )

        return {"message_identifier": dummy_message_id}


    @staticmethod
    def get_thread_obj(thread_id):
        """
        returns the thread object based upon the given thread id
        """
        return Thread.objects.filter(thread_id=thread_id).first()

    @staticmethod
    def aggregate_email_list(recipients, cc, bcc, mail_token_email):
        """
        aggregates the email list on the given recipients , cc, bcc and mail token email
        """
        email_list = []
        email_list.extend(recipients)
        email_list.extend(cc)
        email_list.extend(bcc)
        email_list.append(mail_token_email)
        return email_list

    def build_email_meta(self, provider, recipients, cc, bcc):
        """
        it is used to build the meta data for the email message
        """
        return {
            'provider': {'name': provider}
        }

    @staticmethod
    def prepare_email_params(dummy_message_id, sender, recipients, subject, msg_html, cc, bcc, meta, timestamp,
                            timezone):
        """
        it is used to build the email params
        """
        return {
            'message_id': dummy_message_id, 'sender': sender, 'recipients': recipients,
            'subject': subject, 'is_read': 1, 'internet_message_id': dummy_message_id,
            'cc': cc, 'bcc': bcc, 'body': msg_html, 'meta': meta, 'time_stamp': timestamp,
            'mail_status': Constant.SENDING,
            'mail_created_time': datetime.now(),
        }


    def handle_email_thread_creation(self, thread_obj, email_params, provider_obj, participants,
                                     sender, dummy_message_id, **kwargs):
        """
        it is used to create or update  the email thread based upon the thread obj provided
        """
        if thread_obj:
            email_obj = self.update_thread_obj(thread_obj, email_params)
        else:
            new_thread = self.create_new_thread(dummy_message_id, provider_obj, participants, sender,
                                             **kwargs)
            email_params['thread_id'] = new_thread.id
            email_obj = Email.objects.create(**email_params)
            new_thread.latest_message_id = email_obj.id
            new_thread.save()
        return email_obj

    @staticmethod
    def update_thread_obj(thread_obj, email_params):
        """
        it updates the thread object based upon the email configuration
        """
        email_params['thread_id'] = thread_obj.id
        email_obj = Email.objects.create(**email_params)
        thread_obj.last_active_time = datetime.now()
        thread_obj.latest_message_id = email_obj.id
        thread_obj.size += 1
        thread_obj.is_sent = True
        thread_obj.save()
        return email_obj

    @staticmethod
    def create_new_thread(dummy_message_id, provider_obj,
                          participants,
                          sender, **kwargs):
        """

        """
        is_sent = 0 if kwargs.get("is_scheduled") else 1
        return Thread.objects.create(
            thread_id=dummy_message_id, size=1, provider=provider_obj,
            participants=participants, sender=sender,
            thread_owner=sender, is_sent=is_sent, last_active_time=datetime.now(), **kwargs
        )

    def generate_unique_identifier(self):
        """
        generates an unique identifier for each email message
        """
        identifier = f'<{str(datetime.now())}-{self.mail_token.user_id}-{self.mail_token.email.split("@")[0]}>'
        restricted_chars_pattern = r'[.$#\[\]/]'
        clean_identifier = re.sub(restricted_chars_pattern, '', identifier)
        return clean_identifier

    @staticmethod
    def modify_thread_scheduled_status(thread_obj):
        """
        updates the scheduled thread status
        """
        email_objs = Email.objects.filter(thread_id=thread_obj.id, is_scheduled=1)
        if not email_objs:
            thread_obj.is_sent = 1
            thread_obj.is_scheduled = 0
            thread_obj.save()

    @staticmethod
    def update_mail_and_thread_status(identifier, message_id, thread_id, internet_message_id, is_scheduled):
        Email.objects.filter(message_id=identifier).update(message_id=message_id,
                                                           internet_message_id=internet_message_id,
                                                           mail_status=Constant.DELIVERED,
                                                           is_scheduled=0 if is_scheduled else F('is_scheduled')
                                                           )
        thread_objs = Thread.objects.filter(thread_id=identifier)
        if is_scheduled and thread_objs:
            MailService.modify_thread_scheduled_status(thread_obj=thread_objs.first())
        thread_objs.update(thread_id=thread_id)
        email_obj = Email.objects.filter(message_id=message_id).first()
        return email_obj

    @staticmethod
    def update_mail_message_as_draft(identifier, error_msg: str = ''):
        Email.objects.filter(message_id=identifier).update(mail_status=Constant.DRAFT,
                                                               meta=Func(F('meta'), Value('$.error'), Value(error_msg),
                                                                         function='JSON_SET'))

        return "Updated successfully"

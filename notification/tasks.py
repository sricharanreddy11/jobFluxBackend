import logging

from notification.constants import TokenStatusConstants
from notification.models import MailToken
from notification.services.provider_request_service import ProviderService


def send_mail(**kwargs):
    """
    it is used to send mail based upon the kwargs provided
    """

    provider = kwargs.get('provider')
    identifier = kwargs.get('identifier')
    mail_token = MailToken.objects.filter(email=kwargs.get('sender'), status__in=[TokenStatusConstants.ACTIVE],
                                          token_type="EMAIL", provider__name=provider).first()
    executor = ProviderService(provider).get_provider_executor()
    executor = executor(mail_token)
    try:
        message_status, res = executor.send_message(sender=kwargs.get("sender"), to=kwargs.get('to'),
                                                subject=kwargs.get("subject"),
                                                msg_html=kwargs.get('msg_html'), cc=kwargs.get("cc"),
                                                bcc=kwargs.get("bcc", []),
                                                attachments=kwargs.get('attachments'),
                                                thread_id=kwargs.get('thread_id'),
                                                message_id=kwargs.get("message_id"))
        if message_status:
            message_id = res.get("id")
            internet_message_id = res.get("internetMessageId")
            thread_id = res.get('threadId')


        else:
            executor.update_mail_message_as_draft(identifier, error_msg=res)
    except Exception as e:
        res = executor.update_mail_message_as_draft(identifier, str(e))
        logging.info(res)

class ProviderService(object):
    """
       :description: This class provides a mapping between email service providers and their respective service classes.
                     It allows the user to dynamically select an email provider and get the corresponding service class for execution.

       Attributes:
           Google (str): Constant for Google Mail service.
           Outlook (str): Constant for Outlook Mail service.
           Zoho (str): Constant for Zoho Mail service.
           Others (str): Constant for other mail services.
    """

    Google = 'google_mail'
    Outlook = 'outlook_mail'
    Zoho = 'zoho_mail'
    Others = 'others_mail'
    Sendgrid = 'sendgrid_mail'

    def __init__(self, provider):
        self.provider = provider

    def get_provider_executor(self):
        from .gmail_service import Gmail
        # from .outlook_service import Outlook
        # from .zoho_service import Zoho
        from .others_mail_service import OtherMail
        # from .sendgrid_service import  Sendgrid

        registry = {
            self.Google: Gmail,
            # self.Outlook: Outlook,
            # self.Zoho: Zoho,
            self.Others: OtherMail,
            # self.Sendgrid: Sendgrid,
        }
        if self.provider not in registry:
            raise Exception('provider not supported')
        return registry.get(self.provider)

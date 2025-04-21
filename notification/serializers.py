from rest_framework.serializers import ModelSerializer

from notification.models import Provider, Email, MailToken, Thread


class ProviderSerializer(ModelSerializer):
    class Meta:
        model = Provider
        exclude = ['scope', 'client_id', 'client_secret', 'tenant_id', 'redirect_url']


class MailTokenSerializer(ModelSerializer):
    provider = ProviderSerializer()

    class Meta:
        model = MailToken
        exclude = ['access_token', 'refresh_token']


class MailSerializer(ModelSerializer):

    class Meta:
        model = Email
        fields = '__all__'


class ThreadSerializer(ModelSerializer):
    latest_message = MailSerializer()

    class Meta:
        model = Thread
        fields = '__all__'


class ThreadRetrieveSerializer(ModelSerializer):
    emails = MailSerializer(many=True)

    class Meta:
        model = Thread
        fields = '__all__'

class VerifyMailSerializer(ModelSerializer):
    class Meta:
        model = MailToken
        fields = '__all__'
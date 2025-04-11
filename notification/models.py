from django.db import models

from authenticator.user_manager import UserAbstractModel


class Provider(models.Model):
    name = models.CharField(max_length=255)
    scope = models.JSONField(default=dict)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    tenant_id = models.CharField(max_length=255, null=True, blank=True)
    redirect_url = models.JSONField(default=dict)
    configurations = models.JSONField(default=dict)
    meta = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'provider'


class MailToken(UserAbstractModel):

    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('EXPIRED', 'Expired'),
        ('DISCONNECTED', 'Disconnected'),
        ('VERIFIED', 'Verified'),
        ('PENDING', 'Pending')
    ]

    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    email = models.EmailField()
    access_token = models.TextField()
    refresh_token = models.TextField()
    account_id = models.CharField(max_length=255, null=True, blank=True)
    expires_at = models.DateTimeField()
    token_type = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(
        max_length=255,
        choices=STATUS_CHOICES,
        null=True,
        blank=True,
        default="ACTIVE"
    )
    meta = models.JSONField()
    last_connected_at = models.DateTimeField(null=True, blank=True)
    last_sync_time = models.BigIntegerField(null=True, blank=True)
    scheduled_count = models.IntegerField(null=True, blank=True, default=0)
    sent_count = models.IntegerField(null=True, blank=True, default=0)
    unsubscribed_count = models.IntegerField(null=True, blank=True, default=0)

    class Meta:
        db_table = 'mail_token'


class Thread(UserAbstractModel):
    thread_id = models.CharField(max_length=255, null=True, blank=True)
    provider = models.ForeignKey(Provider, on_delete=models.CASCADE)
    sender = models.EmailField(null=True, blank=True)
    user_id = models.CharField(max_length=255, null=True, blank=True)
    participants = models.JSONField(null=True, blank=True, default=dict)
    is_trash = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)
    is_sent = models.BooleanField(default=False)
    is_inbox = models.BooleanField(default=False)
    is_draft = models.BooleanField(default=False)
    last_active_time = models.DateTimeField(db_index=True)
    size = models.IntegerField(null=True, blank=True)
    thread_owner = models.CharField(max_length=255, null=True, blank=True)
    latest_message = models.ForeignKey('Email', on_delete=models.DO_NOTHING, null=True, blank=True,
                                       related_name='messages')
    meta_data = models.JSONField(default=dict)

    class Meta:
        db_table = 'mail_thread'


class Email(UserAbstractModel):
    message_id = models.CharField(max_length=255)
    internet_message_id = models.TextField(null=True, blank=True)
    sender = models.EmailField()
    recipients = models.JSONField(default=dict, null=True, blank=True)
    cc = models.JSONField(default=dict, null=True, blank=True)
    bcc = models.JSONField(default=dict, null=True, blank=True)
    subject = models.CharField(max_length=255, null=True, blank=True)
    is_external = models.BooleanField(default=False)
    body = models.TextField(null=True, blank=True)
    time_stamp = models.BigIntegerField()
    mail_status = models.CharField(max_length=255, null=True, blank=True)
    is_read = models.BooleanField(default=False)
    is_starred = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    is_scheduled = models.BooleanField(default=False)
    thread = models.ForeignKey('Thread', on_delete=models.CASCADE, null=True, blank=True, related_name='emails')
    meta = models.JSONField()
    mail_created_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'email'


class EmailConfigurations(models.Model):
    server = models.CharField(max_length=255, null=True, blank=True)
    port = models.IntegerField(null=True, blank=True)
    user_name = models.CharField(max_length=255, null=True, blank=True)
    password = models.CharField(max_length=255, null=True, blank=True)
    from_mail = models.EmailField()
    meta = models.JSONField(default=dict)

    class Meta:
        db_table = 'email_config'
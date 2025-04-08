from django.utils import timezone
from django.contrib.auth.models import AbstractUser, Permission, Group
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = [('Admin', 'Admin'), ('Member', 'Member')]
    mobile_number = models.CharField(max_length=15, null=True, blank=True)
    email = models.EmailField(blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, blank=True)
    designation = models.CharField(max_length=255, null=True, blank=True)
    experience = models.FloatField(null=True, blank=True)
    role = models.CharField(max_length=10, blank=True, null=True, choices=ROLE_CHOICES)
    email_verified = models.BooleanField(default=False)
    mobile_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    meta_data = models.JSONField(null=True, blank=True)

    class Meta:
        db_table = 'user'

    USERNAME_FIELD = 'username'


class OtpValidator(models.Model):
    """Used for validating otp"""
    VERIFICATION_STATUS_CHOICES = (('VERIFIED', 'VERIFIED'), ('PENDING', 'PENDING'), ('EXPIRED', 'EXPIRED'))
    CHANNEL_TYPES = (('EMAIL', 'EMAIL'), ('SMS', 'SMS'))
    channel_type = models.CharField(max_length=50, choices=CHANNEL_TYPES, default='EMAIL', db_index=True)
    email_or_mobile = models.CharField(max_length=255)
    otp = models.CharField(max_length=20)
    temp_token = models.CharField(max_length=255, unique=True)
    status = models.BooleanField(default=True)
    verification_status = models.CharField(max_length=50, choices=VERIFICATION_STATUS_CHOICES, db_index=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'otp_validator'

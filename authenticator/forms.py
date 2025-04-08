from django import forms
from django.core.validators import validate_email


def validate_email_mobile(value: str):
    if value.startswith('+'):
        return
    return validate_email(value)


class RequestLoginOTPForm(forms.Form):
    """ form for requesting email or mobile number for otp"""
    email_mobile = forms.CharField(strip=True, min_length=5, label='Email Or Mobile', required=True,
                                   validators=[validate_email_mobile])

    class Meta:
        fields = ['email_mobile']


class OTPVerificationForm(forms.Form):
    """form for requesting request_id and otp to validate otp"""
    request_id = forms.CharField(required=True, widget=forms.HiddenInput())
    otp = forms.CharField(min_length=4)

    class Meta:
        fields = ['request_id', 'otp']

    def __init__(self, *args, **kwargs):
        # Optionally, initialize form fields with values
        request_id = kwargs.pop('request_id', None)
        super(OTPVerificationForm, self).__init__(*args, **kwargs)
        if request_id:
            self.fields['request_id'].initial = request_id


class OTPResendForm(forms.Form):
    "form for requesting request_id  to resend otp"
    request_id = forms.CharField(required=True)

    class Meta:
        fields = ['request_id', ]


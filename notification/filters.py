from typing import Union

import django_filters
from django import forms
from django_filters.rest_framework import filters

from jobflux_backend.filters import LazyAllValuesMultipleFilter
from notification.models import Email, MailToken, Thread


def boolean_parser(value: Union[bool, str]):
    if isinstance(value, bool):
        return value
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    return value


class MailFilter(django_filters.FilterSet):
    class Meta:
        model = Email
        fields = ['updated_at', 'mail_status']


class MailTokenFilter(django_filters.FilterSet):
    provider = LazyAllValuesMultipleFilter(field_name='provider', lookup_expr="exact")
    email = LazyAllValuesMultipleFilter(lookup_expr="exact")
    status = LazyAllValuesMultipleFilter(field_name='status', lookup_expr="exact")
    token_type = LazyAllValuesMultipleFilter(lookup_expr="exact")

    class Meta:
        model = MailToken
        fields = ['status', 'provider', 'user_id', 'email', 'token_type']

    def filter_boolean_value(self, qs, key, value):
        status = boolean_parser(value=value)
        filters = {key: status}
        return qs.filter(**filters)


class MailThreadFilter(django_filters.FilterSet):
    thread_owner = LazyAllValuesMultipleFilter(lookup_expr='exact')
    is_trash = filters.BooleanFilter(method='filter_is_trash')

    class Meta:
        model = Thread
        fields = ['user_id', 'is_trash', 'is_sent', 'is_inbox']

    def filter_is_trash(self, qs, key, value):
        trash_value = boolean_parser(value=value)
        return qs.filter(is_trash=trash_value)
from typing import Union

import django_filters

from core.models import Application
from jobflux_backend.filters import LazyAllValuesMultipleFilter


def boolean_parser(value: Union[bool, str]):
    if isinstance(value, bool):
        return value
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    return value


class ApplicationFilter(django_filters.FilterSet):
    company = LazyAllValuesMultipleFilter(field_name='company__name', lookup_expr="exact")
    remote = LazyAllValuesMultipleFilter(method='filter_boolean_value', label='remote')
    employment_type = LazyAllValuesMultipleFilter(lookup_expr="exact")
    status = LazyAllValuesMultipleFilter(field_name='status__name', lookup_expr="exact")

    class Meta:
        model = Application
        fields = ['status', 'employment_type', 'company', 'remote']

    def filter_boolean_value(self, qs, key, value):
        remote = boolean_parser(value=value)
        filters = {key: remote}
        return qs.filter(**filters)

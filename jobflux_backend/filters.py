from django import forms
from django_filters.rest_framework import filters


class NonValidatingMultipleChoiceField(forms.MultipleChoiceField):

    def validate(self, value):
        pass

class LazyAllValuesMultipleFilter(filters.MultipleChoiceFilter):
    """Default AllValuesMultipleFilter tries to validate the incoming values from the DB Table hence making a DB
    query and performing really slow. We are avoiding all that functionality here. """

    field_class = NonValidatingMultipleChoiceField

    @property
    def field(self):
        self.extra['choices'] = [()]
        return super().field
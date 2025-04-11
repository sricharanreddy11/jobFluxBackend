from django.db import models
from django.db.models.manager import Manager
from django.db.models.query import QuerySet

from authenticator.thread_container import ThreadContainer


class UserFilterQuerySet(QuerySet):
    """
    Custom QuerySet that automatically filters by the current user_id
    from ThreadContainer for all query operations.
    """

    def _get_user_filter(self):
        """Returns user filter kwargs or empty dict."""
        user_id = ThreadContainer.get_current_user_id()
        return {'user_id': user_id} if user_id is not None else {}

    def _apply_user_filter(self, queryset):
        """Applies user filter only once."""
        if not getattr(self, '_user_filter_applied', False):
            user_filter = self._get_user_filter()
            if user_filter:
                queryset = queryset.filter(**user_filter)
                setattr(queryset, '_user_filter_applied', True)
        return queryset

    def _clone(self):
        """Ensure user filtering flag is preserved across clones."""
        clone = super()._clone()
        if hasattr(self, '_user_filter_applied'):
            setattr(clone, '_user_filter_applied', getattr(self, '_user_filter_applied'))
        return clone

    def all(self):
        return self._apply_user_filter(super().all())

    def filter(self, *args, **kwargs):
        return self._apply_user_filter(super().filter(*args, **kwargs))

    def exclude(self, *args, **kwargs):
        return self._apply_user_filter(super().exclude(*args, **kwargs))

    def get(self, *args, **kwargs):
        if 'user_id' not in kwargs:
            kwargs.update(self._get_user_filter())
        return super().get(*args, **kwargs)


class CustomUserManager(Manager):
    """
    Custom manager that uses UserFilterQuerySet and adds user_id
    from ThreadContainer to create operations.
    """

    def get_queryset(self):
        return UserFilterQuerySet(self.model, using=self._db)

    def create(self, **kwargs):
        """Add current user_id to create operation if not provided"""
        if 'user_id' not in kwargs:
            user_id = ThreadContainer.get_current_user_id()
            if user_id is not None:
                kwargs['user_id'] = user_id
        return super().create(**kwargs)


class UserAbstractModel(models.Model):
    """
    Abstract base class for models that should be associated with a user.
    Includes automatic user_id field and the custom UserManager.
    """
    user_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    # Use plain Manager for admin or when you need to bypass user filtering
    admin_objects = Manager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """Override save to add user_id if not set"""
        if not self.user_id:
            user_id = ThreadContainer.get_current_user_id()
            if user_id is not None:
                self.user_id = user_id
        super().save(*args, **kwargs)
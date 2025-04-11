from django.db import models
from django.db.models.manager import Manager
from django.db.models.query import QuerySet

from authenticator.thread_container import ThreadContainer


class UserFilterQuerySet(QuerySet):
    """
    Custom QuerySet that automatically filters by the current user_id
    from ThreadContainer for all query operations.
    """

    def _get_current_user_filter(self):
        """Internal method to get the current user filter as kwargs"""
        user_id = ThreadContainer.get_current_user_id()
        if user_id is not None:
            return {'user_id': user_id}
        return {}

    def _clone(self):
        """Override _clone to ensure user filtering is preserved"""
        clone = super()._clone()
        # Store original state
        if hasattr(self, '_user_filter_applied'):
            setattr(clone, '_user_filter_applied', getattr(self, '_user_filter_applied'))
        return clone

    def all(self):
        """Override all() to filter by current user"""
        queryset = super().all()
        # Only apply user filter if not already applied
        if not getattr(self, '_user_filter_applied', False):
            user_filter = self._get_current_user_filter()
            if user_filter:
                queryset = super(UserFilterQuerySet, queryset).filter(**user_filter)
                # Mark as filtered
                setattr(queryset, '_user_filter_applied', True)
        return queryset

    def filter(self, *args, **kwargs):
        """Apply regular filter and then user filter"""
        queryset = super().filter(*args, **kwargs)
        # Only apply user filter if not already applied
        if not getattr(self, '_user_filter_applied', False):
            user_filter = self._get_current_user_filter()
            if user_filter:
                queryset = super(UserFilterQuerySet, queryset).filter(**user_filter)
                # Mark as filtered
                setattr(queryset, '_user_filter_applied', True)
        return queryset

    def exclude(self, *args, **kwargs):
        """Apply regular exclude and then user filter"""
        queryset = super().exclude(*args, **kwargs)
        # Only apply user filter if not already applied
        if not getattr(self, '_user_filter_applied', False):
            user_filter = self._get_current_user_filter()
            if user_filter:
                queryset = super(UserFilterQuerySet, queryset).filter(**user_filter)
                # Mark as filtered
                setattr(queryset, '_user_filter_applied', True)
        return queryset

    def get(self, *args, **kwargs):
        """Override get to include user_id in the filter"""
        user_id = ThreadContainer.get_current_user_id()
        if user_id is not None and 'user_id' not in kwargs:
            kwargs['user_id'] = user_id
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
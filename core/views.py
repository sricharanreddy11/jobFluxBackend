from rest_framework import filters
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework.viewsets import GenericViewSet

from .models import Company, Contact, ApplicationStatus, Application, Task
from .serializers import (
    CompanySerializer, ContactSerializer, ApplicationStatusSerializer,
    ApplicationListSerializer, ApplicationDetailSerializer,
    TaskSerializer, TaskDetailSerializer
)


class CompanyAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = CompanySerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'industry', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Company.objects.all()


class ContactAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = ContactSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['company']
    search_fields = ['name', 'email', 'position', 'notes']
    ordering_fields = ['name', 'company__name', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Contact.objects.all()


class ApplicationStatusAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = ApplicationStatusSerializer

    def get_queryset(self):
        return ApplicationStatus.objects.all()


class ApplicationAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['company', 'status', 'remote', 'employment_type']
    search_fields = ['title', 'company__name', 'location', 'description', 'notes']
    ordering_fields = ['title', 'application_date', 'company__name', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Application.objects.all()

    def get_serializer_class(self):
        if self.action == 'list':
            return ApplicationListSerializer
        return ApplicationDetailSerializer



class TaskAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['application', 'task_type', 'priority', 'status']
    search_fields = ['title', 'description', 'notes']
    ordering_fields = ['due_date', 'priority', 'created_at']
    ordering = ['due_date', 'priority']

    def get_queryset(self):
        return Task.objects.all()

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return TaskDetailSerializer
        return TaskSerializer
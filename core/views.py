from rest_framework import filters
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin, \
    RetrieveModelMixin
from django_filters.rest_framework import DjangoFilterBackend

from rest_framework.viewsets import GenericViewSet

from .filters import ApplicationFilter
from .models import Company, Contact, ApplicationStatus, Application, Task, Note
from .serializers import (
    CompanySerializer, ContactSerializer, ApplicationStatusSerializer,
    ApplicationListSerializer, ApplicationDetailSerializer,
    TaskSerializer, TaskDetailSerializer, NoteSerializer, CompanyDetailSerializer, ContactDetailSerializer
)


class CompanyAPI(GenericViewSet, RetrieveModelMixin, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = CompanySerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'industry', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return CompanySerializer
        return CompanyDetailSerializer

    def get_queryset(self):
        return Company.objects.all()


class ContactAPI(GenericViewSet, CreateModelMixin,RetrieveModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = ContactSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['company']
    search_fields = ['name', 'email', 'position', 'notes']
    ordering_fields = ['name', 'company__name', 'created_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ContactSerializer
        return ContactDetailSerializer

    def get_queryset(self):
        return Contact.objects.all()


class ApplicationStatusAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = ApplicationStatusSerializer

    def get_queryset(self):
        return ApplicationStatus.objects.all()


class ApplicationAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = ApplicationFilter
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


class NoteAPI(GenericViewSet, CreateModelMixin, UpdateModelMixin, ListModelMixin, DestroyModelMixin):
    serializer_class = NoteSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'content']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return Note.objects.all()
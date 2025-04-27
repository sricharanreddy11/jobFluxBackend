from rest_framework import serializers
from .models import Company, Contact, ApplicationStatus, Application, Task, Note


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'


class ContactSerializer(serializers.ModelSerializer):

    class Meta:
        model = Contact
        fields = '__all__'


class ApplicationStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicationStatus
        fields = '__all__'


class ApplicationListSerializer(serializers.ModelSerializer):
    company_name = serializers.ReadOnlyField(source='company.name')
    status_display = serializers.ReadOnlyField(source='status.name')

    class Meta:
        model = Application
        fields = ['id', 'title', 'company', 'company_name', 'status', 'status_display',
                  'application_date', 'remote', 'location']


class ApplicationDetailSerializer(serializers.ModelSerializer):
    company = CompanySerializer(source='company', read_only=True)
    contact = ContactSerializer(source='contact', read_only=True)
    status_display = serializers.ReadOnlyField(source='status.name')

    class Meta:
        model = Application
        fields = '__all__'

class ContactDetailSerializer(serializers.ModelSerializer):
    company = CompanySerializer(read_only=True)
    applications = ApplicationListSerializer(many=True, read_only=True)

    class Meta:
        model = Contact
        fields = '__all__'

class CompanyDetailSerializer(serializers.ModelSerializer):

    contacts = ContactSerializer(many=True, read_only=True)
    applications = ApplicationListSerializer(many=True, read_only=True)
    class Meta:
        model = Company
        fields = '__all__'


class TaskSerializer(serializers.ModelSerializer):
    application_title = serializers.ReadOnlyField(source='application.title')

    class Meta:
        model = Task
        fields = '__all__'


class TaskDetailSerializer(serializers.ModelSerializer):
    application_details = ApplicationListSerializer(source='application', read_only=True)
    contact_details = ContactSerializer(source='contact', read_only=True)

    class Meta:
        model = Task
        fields = '__all__'
        read_only_fields = ('user', 'created_at', 'updated_at')


class NoteSerializer(serializers.ModelSerializer):

    class Meta:
        model = Note
        fields = '__all__'
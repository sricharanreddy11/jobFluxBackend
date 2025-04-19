from django.db import models

from authenticator.user_manager import UserAbstractModel


class Company(UserAbstractModel):
    name = models.CharField(max_length=200)
    website = models.URLField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    industry = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        db_table = 'company'


class Contact(UserAbstractModel):
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, blank=True, related_name="contacts")
    name = models.CharField(max_length=200)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    position = models.CharField(max_length=200, blank=True, null=True)
    linkedin_url = models.URLField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'contact'


class ApplicationStatus(UserAbstractModel):
    STATUS_CHOICES = [
        ('bookmarked', 'Bookmarked'),
        ('applied', 'Applied'),
        ('screening', 'Screening/Phone Interview'),
        ('interview', 'Interview'),
        ('technical', 'Technical Assessment'),
        ('offer', 'Offer Received'),
        ('accepted', 'Offer Accepted'),
        ('rejected', 'Rejected'),
        ('declined', 'Declined'),
        ('withdrawn', 'Withdrawn'),
    ]

    name = models.CharField(max_length=50, choices=STATUS_CHOICES)
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = 'application_status'
        ordering = ['order']



class Application(UserAbstractModel):
    EMPLOYMENT_TYPE_CHOICES = [
        ('full_time', 'Full-time'),
        ('part_time', 'Part-time'),
        ('contract', 'Contract'),
        ('freelance', 'Freelance'),
        ('internship', 'Internship'),
    ]

    title = models.CharField(max_length=200)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="applications")
    location = models.CharField(max_length=200, blank=True, null=True)
    remote = models.BooleanField(default=False)
    salary_min = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    salary_max = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    job_url = models.URLField(blank=True, null=True)
    employment_type = models.CharField(max_length=20, choices=EMPLOYMENT_TYPE_CHOICES, blank=True, null=True)
    application_date = models.DateField(blank=True, null=True)
    status = models.ForeignKey(ApplicationStatus, on_delete=models.SET_NULL, null=True, related_name="applications")
    contact = models.ForeignKey(Contact, on_delete=models.SET_NULL, null=True, blank=True, related_name="applications")
    notes = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'application'


class Task(UserAbstractModel):
    TASK_TYPE_CHOICES = [
        ('interview', 'Interview'),
        ('follow_up', 'Follow Up'),
        ('apply', 'Apply'),
        ('research', 'Research'),
        ('prepare', 'Preparation'),
        ('networking', 'Networking'),
        ('other', 'Other'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('canceled', 'Canceled'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="tasks")
    contact = models.ForeignKey(Contact, on_delete=models.SET_NULL, null=True, blank=True, related_name="tasks")
    task_type = models.CharField(max_length=20, choices=TASK_TYPE_CHOICES)
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    due_date = models.DateTimeField(blank=True, null=True)
    reminder_time = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'task'


class Note(UserAbstractModel):
    title = models.CharField(default="Untitled", max_length=255)
    content = models.TextField(default="", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    task = models.ForeignKey(Task, on_delete=models.SET_NULL, related_name='notes', null=True, blank=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.title

    class Meta:
        db_table = 'note'

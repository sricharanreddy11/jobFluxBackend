from django.contrib import admin

from core.models import Contact, Company, Application, ApplicationStatus, Task

# Register your models here.
admin.site.register(Contact)
admin.site.register(Company)
admin.site.register(Application)
admin.site.register(ApplicationStatus)
admin.site.register(Task)

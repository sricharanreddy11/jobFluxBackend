from django.urls import path, include
from rest_framework.routers import DefaultRouter

from core.views import CompanyAPI, ContactAPI, ApplicationStatusAPI, ApplicationAPI, TaskAPI, NoteAPI

router = DefaultRouter()
router.register(r'companies', CompanyAPI, basename='company')
router.register(r'contacts', ContactAPI, basename='contact')
router.register(r'application-status', ApplicationStatusAPI, basename='application-status')
router.register(r'applications', ApplicationAPI, basename='application')
router.register(r'tasks', TaskAPI, basename='task')
router.register(r'notes', NoteAPI, basename='note')

urlpatterns = [
    path('', include(router.urls)),
]
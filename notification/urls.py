from django.urls import path, include
from rest_framework.routers import DefaultRouter

from notification.views import ThreadAPI, EmailAPI, TokenAPI, AuthorizeMail

router = DefaultRouter()
router.register('mail-thread', ThreadAPI, basename='thread')
router.register('email', EmailAPI, basename='email')
router.register('token', TokenAPI, basename='mail_token')

urlpatterns = [
    path('', include(router.urls)),
    path('mail/authorize/', AuthorizeMail.as_view()),
]

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import UsersAPI, RegistrationAPI, LoginOtpAPI, LogOutAPI, GoogleLogin
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
router = DefaultRouter()
router.register('users', UsersAPI)
router.register('user/register', RegistrationAPI, 'RegistrationAPI'),
router.register('login-otp', LoginOtpAPI, 'LoginOtpAPI'),


urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('logout/', LogOutAPI.as_view(), name='logout'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('google/', GoogleLogin.as_view(), name='google_login'),
]

urlpatterns += router.urls

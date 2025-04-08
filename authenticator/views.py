from django.contrib.auth import user_logged_out
from rest_framework import status, generics, views
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin, \
    DestroyModelMixin
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from .Services.otp_service import OTPService
from .constants import OTPConstant
from .forms import RequestLoginOTPForm, OTPVerificationForm, OTPResendForm
from .models import User
from .serializers import UserSerializer, UserCreateSerializer, LoginOtpSerializer


class RegistrationAPI(GenericViewSet, CreateModelMixin):
    """New user can register """
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        return User.objects.all()

    def get_serializer_class(self):
        return UserCreateSerializer


class LoginOtpAPI(GenericViewSet):
    permission_classes = []
    serializer_class = LoginOtpSerializer

    @action(methods=["POST"], detail=False, url_path="request-new")
    def request_login_otp(self, request):
        """
        POST request with an email_mobile field in the request body
        """
        form = RequestLoginOTPForm(request.data)
        if form.is_valid():
            email_mobile: str = form.data['email_mobile']
            if email_mobile.startswith('+'):
                res, error = OTPService(OTPService.SMS_CHANNEL).send_otp(email_mobile)
                if res:
                    return Response({
                        'message': 'verification code sent successfully on your mobile {}'.format(email_mobile),
                        'request_id': error,
                        'valid_for': OTPConstant.valid_for,
                        'resend_after': OTPConstant.resend_after
                    })
                else:
                    return Response(error, status=status.HTTP_400_BAD_REQUEST)
            else:
                res, error = OTPService(OTPService.EMAIL_CHANNEL).send_otp(email_mobile)
                if res:
                    return Response({
                        'message': 'verification code sent successfully on your email {}'.format(email_mobile),
                        'request_id': error,
                        'valid_for': OTPConstant.valid_for,
                        'resend_after': OTPConstant.resend_after
                    })
                else:
                    return Response(error, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path='verify')
    def verify_otp(self, request):
        """
        verifies the OTP using the OTPService
        """
        form = OTPVerificationForm(request.data)
        if form.is_valid():
            res, token = OTPService.verify(request, form.data['request_id'], form.data['otp'])
            if res:
                return Response(token, status=status.HTTP_200_OK)
            return Response(token, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_path='resend')
    def resend(self, request):
        """
        resends the OTP using the OTPService
        """
        form = OTPResendForm(request.data)
        if form.is_valid():
            res, error = OTPService.resend(form.data['request_id'])
            if res:
                return Response({
                    'message': 'Resent successfully',
                    'request_id': error,
                    'valid_for': OTPConstant.valid_for,
                    'resend_after': OTPConstant.resend_after
                })
            else:
                return Response(error, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)


class LogOutAPI(APIView):

    def post(self, request, *args, **kwargs):
        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", True):
            user = None
        user_logged_out.send(sender=user.__class__, request=request, user=user)
        if hasattr(request, "user"):
            from django.contrib.auth.models import AnonymousUser
            request.user = AnonymousUser()

        return Response({"message": "User Logged Out Successfully"})


class UsersAPI(GenericViewSet, ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin,
               DestroyModelMixin):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated],  url_path='current-user')
    def get_current_user(self, request):
        user = request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data)


from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status

User = get_user_model()

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user = self.user

        # Generate JWT Token
        refresh = RefreshToken.for_user(user)
        jwt_data = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "email": user.email,
                "username": user.username
            }
        }

        return Response(jwt_data, status=status.HTTP_200_OK)
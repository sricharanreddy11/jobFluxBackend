from django.db.models import Prefetch
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.mixins import RetrieveModelMixin, UpdateModelMixin, ListModelMixin, CreateModelMixin, \
    DestroyModelMixin
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_200_OK
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from notification.constants import TokenStatusConstants, Constant
from notification.filters import MailThreadFilter, MailTokenFilter
from notification.models import Email, MailToken, Thread, Provider
from notification.serializers import MailSerializer, ThreadRetrieveSerializer, ThreadSerializer, MailTokenSerializer, \
    VerifyMailSerializer
from notification.services.email_service import MailService
from notification.services.provider_request_service import ProviderService


class ThreadAPI(GenericViewSet, ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin):
    serializer_class = ThreadSerializer
    pagination_class = PageNumberPagination
    filter_backends = (DjangoFilterBackend, OrderingFilter, SearchFilter,)
    filterset_class = MailThreadFilter
    ordering = ('-last_active_time',)

    def get_queryset(self):
        return Thread.objects.prefetch_related(
            Prefetch(
                'latest_message',
                queryset=Email.objects.all()
            )
        )

    @action(url_path="detail", methods=['GET'], detail=False)
    def get_thread_details(self, request):
        threadId = request.GET.get('thread_id')
        email_queryset = Email.objects.exclude(mail_status='DRAFT').order_by('-mail_created_time')
        thread_obj = Thread.objects.get(thread_id=threadId)
        qs = Thread.objects.prefetch_related(
            Prefetch('emails', queryset=email_queryset),
        update_qs = Email.objects.exclude(mail_status=Constant.BOUNCED).filter(thread_id=thread_obj.id))
        updated_dict = {
            "is_read": 1
        }
        ser = ThreadRetrieveSerializer(qs.filter(id=thread_obj.id), many=True)
        return Response(ser.data)

    @action(methods=['POST'], url_path='trash', detail=False)
    def trash_messages(self, request):
        data = request.data
        thread_ids = data.get('thread_ids')
        trash = data.get('is_trash')
        qs = Thread.objects.filter(thread_id__in=thread_ids)
        updated_dict = {
            "is_trash": trash
        }
        return Response("success")

    @action(methods=['POST'], url_path='mark_read', detail=False)
    def mark_as_read(self, request):
        data = request.data
        thread_ids = data.get('thread_ids')
        threads = Thread.objects.filter(thread_id__in=thread_ids)
        qs = Email.objects.filter(thread__in=threads)
        updated_dict = {
            "is_read": 1
        }
        return Response("success")

    def list(self, request, *args, **kwargs):
        return super(ThreadAPI, self).list(request, *args, **kwargs)

class EmailAPI(GenericViewSet, RetrieveModelMixin, UpdateModelMixin, ListModelMixin, CreateModelMixin):
    serializer_class = MailSerializer
    pagination_class = PageNumberPagination

    def get_queryset(self):
        return Email.objects.all()

    @action(url_path='send/message', methods=['POST'], detail=False)
    def send_message(self, request):

        data = request.data
        sender = data.get("sender")
        recipients = data.get('recipients')
        subject = data.get("subject")
        cc = data.get("cc")
        bcc = data.get("bcc", [])
        thread_id = data.get('thread_id')
        message_id = data.get("message_id")
        provider = request.GET.get('provider')
        timezone = data.get('timezone')
        mail_token = MailToken.objects.filter(email=data.get('sender'),
                                              status=TokenStatusConstants.ACTIVE,
                                              token_type="EMAIL").first()
        try:
            res = MailService(mail_token=mail_token).send_mail_message(provider=provider,
                                                                       mail_token=mail_token,
                                                                       sender=sender, to=recipients,
                                                                       recipients=recipients,
                                                                       subject=subject,
                                                                       msg_html=data.get('message'), cc=cc,
                                                                       bcc=bcc,
                                                                       thread_id=thread_id,
                                                                       message_id=message_id,
                                                                        timezone=timezone)
            return Response(res)
        except Exception as e:
            return Response(str(e), status=HTTP_400_BAD_REQUEST)


class TokenAPI(GenericViewSet, ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin,
               DestroyModelMixin):
    serializer_class = MailTokenSerializer
    filter_backends = (DjangoFilterBackend, OrderingFilter, SearchFilter,)
    filterset_class = MailTokenFilter
    ordering = ('email', 'created_at')

    def get_queryset(self):
        return MailToken.objects.filter(
            status__in=[TokenStatusConstants.ACTIVE, TokenStatusConstants.INACTIVE]).prefetch_related(
            Prefetch('provider', queryset=Provider.objects.all()),
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        ser = VerifyMailSerializer(instance, data=request.data, partial=True)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            if instance:
                self.perform_destroy(instance)
                return Response("Disconnected successfully")
        except Exception as e:
            return Response(str(e), status=404)


class AuthorizeMail(APIView):

    def get(self, request):

        provider = request.GET.get("provider")
        try:
            executor = ProviderService(provider).get_provider_executor()
            url = executor().get_provider_url()
            return Response({"redirect_url": url})
        except Exception as e:
            return Response(str(e), status=400)

    def post(self, request):
        try:

            provider = request.GET.get("provider")
            data = request.data
            code = data.get('authorization_code')
            executor = ProviderService(provider).get_provider_executor()
            creation_status, msg = executor().create_user(code, data)
            if creation_status:
                return Response(msg, status=HTTP_200_OK)
            else:
                return Response(msg, status=HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(str(e), status=HTTP_400_BAD_REQUEST)
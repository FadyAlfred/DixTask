import nexmo

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_auth.views import LoginView, sensitive_post_parameters_m
from rest_auth.registration.views import RegisterView
from rest_auth.app_settings import PasswordResetConfirmSerializer

from allauth.account import app_settings as allauth_settings
from rest_auth.app_settings import (TokenSerializer,
                                    JWTSerializer)

from .models import PhoneNumberVerification, UserProfile
from .serializers import VerifyPhoneNumberSerializer

@api_view()
def django_rest_auth_null(request):
    return Response(status=status.HTTP_400_BAD_REQUEST)


class LoginView(LoginView):
    def get_response(self):
        serializer_class = self.get_response_serializer()
        if getattr(settings, 'REST_USE_JWT', False):
            data = {
                'user': self.user,
                'token': self.token,
            }
            serializer = serializer_class(instance=data,
                                          context={'request': self.request})
        else:
            serializer = serializer_class(instance=self.token,
                                          context={'request': self.request})
        user = serializer.data['user']
        data = serializer.data
        data['user'] = user
        return Response(data, status=status.HTTP_200_OK)


class RegisterViewCustom(RegisterView):
    def get_response_data(self, user):
        if allauth_settings.EMAIL_VERIFICATION == \
                allauth_settings.EmailVerificationMethod.MANDATORY:
            return {"detail": {"Verification Sms Sent to verify your phone number go here :"
                                "http://127.0.0.1:8000/phone/verify/"+str(user.profile.phone_number)+"/",
                                "Verification e-mail sent."
                                }}

        if getattr(settings, 'REST_USE_JWT', False):
            data = {
                'user': user,
                'token': self.token
            }
            return JWTSerializer(data).data
        else:
            return TokenSerializer(user.auth_token).data


class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": _("Password has been reset with the new password.")}
        )


class VerifyPhoneNumber(APIView):
    serializer_class = VerifyPhoneNumberSerializer

    def post(self,request,number):
        verification_request = PhoneNumberVerification.objects.filter(phone_number=number).first()
        code = request.data.get('code', None)
        if not code:
            return Response('No code provided', status=status.HTTP_400_BAD_REQUEST)
        if not verification_request:
            return Response('No verification request match this phone number',
                            status=status.HTTP_401_UNAUTHORIZED)
        user = UserProfile.objects.filter(phone_number=number).first()
        request_id = verification_request.request_id
        client = nexmo.Client(key=settings.NEXNO_KEY, secret=settings.NEXNO_SECRET)
        response = client.check_verification(request_id, code=code)
        if response['status'] == '0':
            user.phone_number_verified = True
            user.save()
            verification_request.delete()
            return Response('User verification complete!', status=status.HTTP_200_OK)
        else:
            return Response("User verification failed!", status=status.HTTP_404_NOT_FOUND)
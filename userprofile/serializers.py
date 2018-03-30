import nexmo
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from allauth.account import app_settings as allauth_settings
from allauth.utils import email_address_exists
from allauth.account.adapter import get_adapter
from rest_framework import serializers, exceptions
from rest_auth.serializers import LoginSerializer
from rest_auth.registration.serializers import RegisterSerializer
from phonenumber_field.serializerfields import PhoneNumberField

from .models import UserProfile, PhoneNumberVerification

# Get the UserModel
UserModel = get_user_model()


class ProfileRegisterSerializer(RegisterSerializer):
    first_name = serializers.CharField(required=True, write_only=True)
    last_name = serializers.CharField(required=True, write_only=True)
    phone_number = PhoneNumberField(required=True, write_only=True)

    def get_cleaned_data_profile(self):
        return {
            'phone_number': self.validated_data.get('phone_number', ''),
        }

    def create_profile(self, user, validated_data):
        """
        Modify the `Profile` instance, given the validated data.
        """
        user.first_name = validated_data.get("first_name")
        user.last_name = validated_data.get("last_name")
        # user.profile.phone_number = validated_data.get("phone_number")
        self.phone_number = validated_data.get("phone_number")
        client = nexmo.Client(key=settings.NEXNO_KEY, secret=settings.NEXNO_SECRET)
        verify_resp = client.start_verification(number=str(self.phone_number), brand='Dix')
        verification_detail = PhoneNumberVerification(phone_number=self.phone_number
                                                      ,request_id=verify_resp['request_id'])
        verification_detail.save()
        profile = UserProfile(phone_number=self.phone_number, phone_number_verified=False)
        user.profile = profile
        user.profile.save()

    def custom_signup(self, request, user):
        self.create_profile(user, self.get_cleaned_data_profile())


class LoginSerializerCustom(LoginSerializer):
    email = None  # Removes email field from login API

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        user = None
        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings

            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                user = self._validate_email(email, password)

            # Authentication through username
            elif app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                user = self._validate_username(username, password)

            # Authentication through either username or email
            else:
                user = self._validate_username_email(username, email, password)

        else:
            # Authentication without using allauth
            if email:
                try:
                    username = UserModel.objects.get(email__iexact=email).get_username()
                except UserModel.DoesNotExist:
                    pass

            if username:
                user = self._validate_username_email(username, '', password)

        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(_('E-mail is not verified.'))

        attrs['user'] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    phone_number = PhoneNumberField(source="profile.phone_number", required=False)
    raw_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = get_user_model()
        fields = ('username', 'raw_password', 'email', 'first_name', 'last_name',
                  'phone_number')
        read_only_fields = ('first_name', 'last_name')

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        if allauth_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                raise serializers.ValidationError(
                    "A user is already registered with this e-mail address.")
        return email


class VerifyPhoneNumberSerializer(serializers.Serializer):
    code = serializers.CharField(required=False)
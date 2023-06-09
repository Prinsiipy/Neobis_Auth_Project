from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework import serializers
# from config import settings
from rest_auth.serializers import PasswordResetSerializer as _PasswordResetSerializer
from account.models import User

from django.contrib.auth.password_validation import validate_password
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from .models import User
from .utils import Util

from django.core.exceptions import ValidationError


def validate_password_characters(value):
    if not any(char.isalpha() and char.isupper() for char in value):
        raise ValidationError(
            "Пароль должен содержать как минимум одну заглавную букву.",
            code='password_no_uppercase'
        )
    if not any(char.isalpha() and not char.isupper() for char in value):
        raise ValidationError(
            "Пароль должен содержать как минимум одну строчную букву.",
            code='password_no_lowercase'
        )


class RegisterSerializer(serializers.ModelSerializer):
    message = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'message']

    def get_message(self, obj):
        return (
            "Verification message has been sent to your email, please verify your email"
        )

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class RegisterUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'date_born', 'phone']

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.date_born = validated_data.get('date_born', instance.date_born)
        instance.phone = validated_data.get('phone', instance.phone)
        instance.save()
        return instance


class PasswordUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password_characters])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('password', 'confirm_password')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()

        return instance


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    tokens = serializers.CharField(max_length=68, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        # import pdb
        # pdb.set_trace()
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')


        return {
            'email': user.email,
            'tokens': user.tokens
        }


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            user.set_password(password)
            user.save()
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is expired or invalid', )
    }

    def validate(self, attrs):
        self.token = attrs['refresh']

        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class PasswordResetSerializer(_PasswordResetSerializer):

    def save(self):
        request = self.context.get('request')
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'EMAIL_HOST_USER'),

            'email_template_name': 'reset_password.html',

            'request': request
        }
        self.reset_form.save(**opts)

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(_('Error'))

        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Invalid e-mail address')

        return value


class MobilePasswordResetSerializer(_PasswordResetSerializer):

    def save(self):
        request = self.context.get('request')
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'EMAIL_HOST_USER'),

            'email_template_name': 'reset_password.html',

            'request': request
        }
        self.reset_form.save(**opts)

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(_('Error'))

        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Invalid e-mail address')

        return value
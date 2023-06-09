from django.shortcuts import render

# Create your views here.
from rest_framework import generics, status, views, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.views.generic.base import RedirectView
from django.http import HttpResponseRedirect
from django.http import JsonResponse


import jwt
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import User
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, \
    ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer, LogoutSerializer, RegisterUpdateSerializer, \
    PasswordUpdateSerializer
from .utils import Util


class RegistrationView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
        email_body = 'Hi '+user.email+' Use link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class RegistrationViewForMobile(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify-for-mobile')
        absurl = 'http://'+current_site+relativeLink+'?token='+str(token)
        email_body = 'Hi '+user.email+' Use link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class UpdateRegisterView(generics.GenericAPIView):
    serializer_class = RegisterUpdateSerializer

    @swagger_auto_schema(
        request_body=RegisterUpdateSerializer,  # Определите ваш сериализатор
        responses={200: 'User updated successfully', 400: 'Bad Request'}
    )
    def put(self, request):
        user = request.user  # Retrieve the authenticated user

        # Initialize the serializer with the user object and request data
        serializer = RegisterUpdateSerializer(user, data=request.data)

        # Validate and update the user data
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User updated successfully'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdatePasswordView(generics.GenericAPIView):
    serializer_class = PasswordUpdateSerializer

    @swagger_auto_schema(
        request_body=PasswordUpdateSerializer,  # Определите ваш сериализатор
        responses={200: 'Password updated successfully', 400: 'Bad Request'}
    )
    def put(self, request):
        user = request.user  # Retrieve the authenticated user

        # Initialize the serializer with the user object and request data
        serializer = PasswordUpdateSerializer(user, data=request.data)

        # Validate and update the user data
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password updated successfully'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(RedirectView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            # payload = jwt.decode(token, settings.SECRET_KEY)
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            token_front = RefreshToken.for_user(user).access_token

            return HttpResponseRedirect('https://neobis-auth.herokuapp.com/registrationform' + f'/{token_front}')

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailMobile(RedirectView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            # payload = jwt.decode(token, settings.SECRET_KEY)
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            token_front = RefreshToken.for_user(user).access_token

            return HttpResponseRedirect('authapp://additionalInfo' + f'/?token={token_front}')

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(user.id)
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relativeLink
            email_body = 'Hi, \n Use link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError:
            if not PasswordResetTokenGenerator():
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
from django.urls import path, re_path

from .views import RegistrationView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail, \
    SetNewPasswordAPIView, LogoutAPIView, UpdateRegisterView, UpdatePasswordView, VerifyEmailMobile, RegistrationViewForMobile

from rest_auth.views import PasswordResetView, PasswordResetConfirmView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('register-for-mobile/', RegistrationViewForMobile.as_view(), name='register-for-mobile'),
    path('register-update/', UpdateRegisterView.as_view(), name='register-update'),
    path('password-update/', UpdatePasswordView.as_view(), name='password-update'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify'),
    path('email-verify-for-mobile/', VerifyEmailMobile.as_view(), name='email-verify-for-mobile'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('passwordresetconfirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='passwordresetconfirm'),
]
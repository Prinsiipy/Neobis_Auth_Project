from django.db import models

# Create your models here.
from django.utils.timezone import now

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin
)

from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone


class UserManager(BaseUserManager):

    def create_user(self, email, password=str(123), phone=None):

        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(email=self.normalize_email(email), phone=phone)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=str(123)):

        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, db_index=True, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    phone = models.CharField(max_length=255, blank=True, null=True, unique=True)
    date_born = models.DateField(default=timezone.now)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='account_users',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='account_users',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
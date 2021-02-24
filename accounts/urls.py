from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token
from django.urls import path

from .views import (AuthAPIView,
                    UserRegisterView,
                    VerifyEmail,
                    ChangePasswordView,
                    RequestPasswordResetEmail,
                    VerifyResetEmailToken,
                    SetNewPasswordAPIView)

urlpatterns = [
    path('login', AuthAPIView.as_view(), name='login'),
    path('register', UserRegisterView.as_view(), name='register'),
    path('email-verify', VerifyEmail.as_view(), name='email-verify'),
    path('change-password', ChangePasswordView.as_view(), name='change-password'),
    path('request-reset-email', RequestPasswordResetEmail.as_view(), name="request-reset-email"),
    path('verify-reset-email-token', VerifyResetEmailToken.as_view(), name="verify-reset-email-token"),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
    path('jwt', obtain_jwt_token),
    path('jwt/refresh', refresh_jwt_token),
]

from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.http import HttpResponsePermanentRedirect
from django.conf import settings

import pdb

from .utils import send_email
from .serializers import (RegisterSerializer,
                          EmailVerificationSerializer,
                          ChangePasswordSerializer,
                          ResetPasswordEmailRequestSerializer,
                          SetNewPasswordSerializer)

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER

User = get_user_model()


class AuthAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({'error': 'You are already authenticated'}, status=status.HTTP_400_BAD_REQUEST)
        data = request.data
        username = data.get('email')  # username or email address
        password = data.get('password')
        qs = User.objects.filter(email__iexact=username).distinct()
        if qs.count() == 1:
            user_obj = qs.first()
            if user_obj.check_password(password):
                user = user_obj
                payload = jwt_payload_handler(user)
                token = jwt_encode_handler(payload)
                response = jwt_response_payload_handler(token, user, request=request)
                return Response(response)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


class UserRegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({'error': 'You are already authenticated'}, status=400)
        data = RegisterSerializer(data=request.data)
        if data.is_valid():
            data = data.data
            user = User.objects.create(
                full_name=data.get('full_name'),
                email=data.get('email').lower(),
                phone=data.get('phone'),
            )
            user.set_password(data.get('password'))
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            current_site = get_current_site(request).domain
            relativeLink = reverse('email-verify')
            absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
            email_body = 'Hi ' + user.full_name + \
                         ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Verify your email'}
            send_email(data)
            user.save()
            # pdb.set_trace()
            return Response({"success": "registration successful"}, status=status.HTTP_201_CREATED)
        else:
            # pdb.set_trace()
            return Response(data.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt_decode_handler(token)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'success': 'Successfully activated'}, status=status.HTTP_200_OK)
        except Exception as identifier:
            return Response({'error': '{}'.format(identifier)}, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.save()
            return Response({'success': 'Successfully created'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse('verify-reset-email-token')

            absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                         absurl  # + "?redirect_url=" + redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class VerifyResetEmailToken(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt_decode_handler(token)
            if User.objects.filter(id=payload['user_id']).exists():
                return HttpResponsePermanentRedirect(settings.FRONTEND_URL+'?token_valid=True&message=Credentials Valid&&token='+token)
            else:
                raise Exception('User does not exits')
        except Exception as identifier:
            return HttpResponsePermanentRedirect(settings.FRONTEND_URL+'?token_valid=False&message={}'.format(identifier))


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)
            else:
                raise Exception(serializer.errors)
        except Exception as e:
            return Response(e, status=status.HTTP_400_BAD_REQUEST)

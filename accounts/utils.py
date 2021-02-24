import datetime
# from django.conf import settings
from django.utils import timezone
from rest_framework_jwt.settings import api_settings
from django.core.mail import EmailMessage
import threading


expire_delta = api_settings.JWT_REFRESH_EXPIRATION_DELTA


def jwt_response_payload_handler(token, user=None, request=None):
    return {
        'token': token,
        'user': user.full_name,
        'expires': timezone.now() + expire_delta - datetime.timedelta(seconds=200)
    }


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


def send_email(data):
    email = EmailMessage(
        subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
    EmailThread(email).start()


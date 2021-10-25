from django.utils import timezone
from uuid import uuid4
import jwt
from django.utils import timezone
from .serializers import UserSerializer
from .settings import *


def makeaccess(user):
    if not bool(user.token):
        user.token = uuid4().hex[:4]
        user.save()
    payload = UserSerializer().to_representation(user)

    if not bool(ENABLE_GET_USER_ON_JWT):
        payload = {"id": user.id}

    payload['exp'] = timezone.now() + timezone.timedelta(minutes=30)
    return jwt.encode(payload, user.token, algorithm="HS256")


def makerefresh(user):
    if not bool(user.token):
        user.token = uuid4().hex[:4]
        user.save()
    return jwt.encode({"exp": timezone.now() + timezone.timedelta(minutes=30)}, user.token, algorithm="HS256")


def cleartoken(user):
    if bool(user.token):
        user.token = ''
        user.save()

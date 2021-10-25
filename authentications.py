from rest_framework.authentication import BaseAuthentication, get_authorization_header
from .models import User
import jwt
from django.contrib.auth import get_user_model
User = get_user_model()


class CustomAuth(BaseAuthentication):

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or len(auth) != 2:
            return None

        try:
            payload = jwt.decode(auth[1], options={"verify_signature": False})
            user = User.objects.filter(id=payload.get('id')).first()
            payload = jwt.decode(auth[1], user.token, algorithms="HS256")
            return (user, None)

        except:
            return (None, None)

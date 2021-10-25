# import from django framework
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.utils.html import strip_tags
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.shortcuts import get_object_or_404

# import from django rest frameworkensure
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, exceptions
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_201_CREATED,
    HTTP_200_OK,
    HTTP_204_NO_CONTENT
)

# import from this apps
from .utils import makeaccess, cleartoken, makerefresh
from .settings import *
from .serializers import (
    ResendSerializer,
    SigninSerializer,
    UserSerializer,
    SignupSerializer,
    VerifySerializer,
    ForgotSerializer,
    ResetSerializer,
    ChangePasswordSerializer,
    FacebookSerializer,
    GoogleSerializer,
    UserDetailSerializer
)

# from .models import Ticket, Token
from .permissions import IsOwner, IsCurrentUserOrReadOnly, IsAdmin

# import from python
from uuid import uuid4

User = get_user_model()


class SignIn(generics.CreateAPIView):
    serializer_class = SigninSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = User.objects.filter(
                email=serializer.validated_data['email']).first()
            response = dict(self.handle_response(user))

            if not bool(ENABLE_INACTIVE_USER_AUTH) and not bool(response['is_active']):
                return Response({'email':  serializer.validated_data['email'], 'is_active': False}, HTTP_401_UNAUTHORIZED)

            return Response(response, HTTP_200_OK)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_response(self, user):
        res = {}
        if user:
            user.last_interact = timezone.now()
            user.save()
            res = {'access': makeaccess(user)}

            if bool(ENABLE_REFRESH_JWT):
                res['refresh'] = makerefresh(user)

            if bool(ENABLE_GET_USER_ON_LOGIN):
                res = {**res, **dict(UserSerializer().to_representation(user))}

        return res


class SignUp(generics.CreateAPIView):
    serializer_class = SignupSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():

            data = serializer.validated_data

            user = User.objects.create(
                email=data.get('email'),
                username=data.get('username'),
                first_name=data.get('first_name'),
                last_name=data.get('last_name'),
                password=make_password(data.get('password')),
            )

            if bool(ENABLE_CONFIRM_EMAIL):
                self.handle_email(
                    dict(self.serializer_class().to_representation(user))
                )

            return Response(dict(UserSerializer().to_representation(user)), HTTP_201_CREATED)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_email(self, obj):
        html = render_to_string('email/verify_email.html', obj)
        send_mail(
            subject="email verification",
            message=strip_tags(html),
            html_message=html,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[obj['email']],
            fail_silently=False
        )


class Verify(generics.CreateAPIView):
    serializer_class = VerifySerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = User.objects.filter(
                token=serializer.validated_data['token']
            ).first()

            if user:
                user.is_active = True
                user.token = ""
                user.save()

            return Response(dict(UserSerializer().to_representation(user)), HTTP_200_OK)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)


class Resend(generics.CreateAPIView):
    serializer_class = ResendSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = User.objects.filter(
                email=serializer.validated_data['email']
            ).first()

            if user:
                user.token = uuid4().hex[:4]
                user.last_interact = timezone.now()
                user.save()

            self.handle_email(
                dict(SignupSerializer().to_representation(user))
            )

            return Response(dict(UserSerializer().to_representation(user)), HTTP_200_OK)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_email(self, obj):
        print(obj)
        html = render_to_string('email/verify_email.html', obj)
        send_mail(
            subject="email verification",
            message=strip_tags(html),
            html_message=html,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[obj['email']],
            fail_silently=False
        )


class Forgot(generics.CreateAPIView):
    serializer_class = ForgotSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = User.objects.filter(
                email=serializer.validated_data['email']
            ).first()

            if user:
                user.token = uuid4().hex[:4]
                user.last_interact = timezone.now()
                user.save()

            self.handle_email(
                dict(SignupSerializer().to_representation(user))
            )

            return Response(None, HTTP_204_NO_CONTENT)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_email(self, obj):
        print(obj)
        html = render_to_string('email/verify_email.html', obj)
        send_mail(
            subject="email verification",
            message=strip_tags(html),
            html_message=html,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[obj['email']],
            fail_silently=False
        )


class GetUser(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(dict(UserSerializer().to_representation(request.user)), HTTP_200_OK)


class Reset(generics.CreateAPIView):
    serializer_class = ResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            user = User.objects.filter(email=data.get('email')).first()
            user.password = make_password(data.get('password'))
            user.token = ""
            user.save()

            return Response(None, HTTP_204_NO_CONTENT)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)


class ChangePassword(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    queryset = User.objects.all()
    permission_classes = [IsOwner]

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request})

        if serializer.is_valid():

            data = serializer.validated_data

            print(data)
            print(make_password(data.get('password')))
            user = request.user
            user.password = data.get('password')
            user.save()

            return Response(None, HTTP_204_NO_CONTENT)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)


class SignOut(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_anonymous:
            user = request.user
            user.token = ""
            user.save()
        return Response(None, HTTP_204_NO_CONTENT)


class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserDetailSerializer
    queryset = User.objects.all()
    permission_classes = [IsCurrentUserOrReadOnly]

    def get_object(self):
        try:
            obj = get_object_or_404(
                self.get_queryset(), id=self.kwargs['user'])
        except:
            obj = get_object_or_404(
                self.get_queryset(), username=self.kwargs['user'])

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)
        return obj


class Facebook(generics.CreateAPIView):
    serializer_class = FacebookSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data['token']
            email = f"{data.get('id')}@facebook.com"
            username = ''.join(data.get('first_name').split()).lower()
            user = User.objects.filter(email=email).first()
            response = {}

            while User.objects.filter(username=username).first():
                username = username + uuid4().hex[:8]

            if not user:
                user = User.objects.create(
                    username=username,
                    email=f"{data.get('id')}@facebook.com",
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                    is_active=True,
                    password=make_password(uuid4().hex[:8])
                )
            response = dict(self.handle_response(user))
            return Response(response, HTTP_200_OK)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_response(self, user):
        res = {}
        if user:
            user.last_interact = timezone.now()
            user.save()
            res = {'access': makeaccess(user)}

            if bool(ENABLE_REFRESH_JWT):
                res['refresh'] = makerefresh(user)

            if bool(ENABLE_GET_USER_ON_LOGIN):
                res = {**res, **dict(UserSerializer().to_representation(user))}

        return res


class Google(generics.CreateAPIView):
    serializer_class = GoogleSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data['token']
            username = ''.join(data.get('first_name').split()).lower()
            user = User.objects.filter(email=data['email']).first()
            response = {}

            while User.objects.filter(username=username).first():
                username = username + uuid4().hex[:8]

            if not user:
                user = User.objects.create(
                    username=username,
                    email=data['email'],
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                    is_active=True,
                    password=make_password(uuid4().hex[:8])
                )

            response = dict(self.handle_response(user))
            return Response(response, HTTP_200_OK)

        return Response(serializer.errors, HTTP_400_BAD_REQUEST)

    def handle_response(self, user):
        res = {}
        if user:
            user.last_interact = timezone.now()
            user.save()
            res = {'access': makeaccess(user)}

            if bool(ENABLE_REFRESH_JWT):
                res['refresh'] = makerefresh(user)

            if bool(ENABLE_GET_USER_ON_LOGIN):
                res = {**res, **dict(UserSerializer().to_representation(user))}

        return res

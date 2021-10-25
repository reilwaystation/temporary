from django.urls import path
from .views import (
    SignIn,
    SignUp,
    Verify,
    Resend,
    Forgot,
    Reset,
    ChangePassword,
    SignOut,
    Facebook,
    Google,
    GetUser,UserDetail
)

urlpatterns = [
    path('signin', SignIn.as_view()),
    path('signup', SignUp.as_view()),
    path('signout', SignOut.as_view(), name='signout'),
    path('google', Google.as_view(), name='googleauth'),
    path('facebook', Facebook.as_view(), name='facebookauth'),
    path('resend', Resend.as_view(), name='resend'),
    path('verify', Verify.as_view(), name="verify"),
    path('forgot', Forgot.as_view(), name="forgot"),
    path('reset', Reset.as_view(), name='reset'),
    path('change', ChangePassword.as_view(), name='change'),
    path('<user>', UserDetail.as_view(), name='update'),
    path('me', GetUser.as_view(), name='current'),
]

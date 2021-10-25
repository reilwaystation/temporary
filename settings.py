from django.conf import settings


ACCESS_JWT_LIFE = getattr(settings, 'ACCESS_JWT_LIFE', 20)
REFRESH_JWT_LIFE = getattr(settings, 'REFRESH_JWT_LIFE', 20)

ENABLE_REFRESH_JWT = getattr(settings, 'ENABLE_REFRESH_JWT', True)
ENABLE_GET_USER_ON_LOGIN = getattr(settings, 'ENABLE_GET_USER_ON_LOGIN', True)
ENABLE_GET_USER_ON_JWT = getattr(settings, 'ENABLE_GET_USER_ON_JWT', True)
ENABLE_CONFIRM_EMAIL = getattr(settings, 'ENABLE_CONFIRM_EMAIL', True)
ENABLE_INACTIVE_USER_AUTH = getattr(settings, 'ENABLE_ACTIVE_USER_AUTH', False)

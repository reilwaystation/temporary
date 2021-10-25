from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed


class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        return True


class IsAuthenticatedOrReadOnly(BasePermission):

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        return True


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        if not bool(request.user.is_superuser):
            raise PermissionDenied()

        return True


class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        if not bool(request.user.is_superuser):
            raise PermissionDenied()

        return True


class IsOwner(BasePermission):
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        return True

    def has_object_permission(self, request, view, obj):
        if bool((obj.user == request.user) or (request.user and request.user.is_superuser)):
            return True

        raise PermissionDenied()


class IsOwnerOrReadOnly(BasePermission):

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if not bool(request.user and request.user.is_authenticated):
            raise AuthenticationFailed()

        return True

    def has_object_permission(self, request, view, obj):
        if bool((obj.user == request.user) or (request.user and request.user.is_superuser) or request.method in SAFE_METHODS):
            return True

        raise PermissionDenied()


class IsCurrentUserOrReadOnly(BasePermission):

    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated or request.method in SAFE_METHODS):
            raise AuthenticationFailed()

        return True

    def has_object_permission(self, request, view, obj):
        if bool(obj == request.user or request.user.is_superuser or request.method in SAFE_METHODS):
            return True

        raise PermissionDenied()

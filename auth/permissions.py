from rest_framework import permissions
from auth_jwt.views import permission_check, token_validation_and_get_user


# ServiceID - AUTH_GROUP_ALL
# serviceName - GROUP MANAGEMENT
class GroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_GROUP_ALL")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ServiceID - AUTH_SERVICE_ALL
# serviceName - SERVICE MANAGEMENT
class ServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_SERVICE_ALL")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ServiceID - AUTH_USER_GROUP_ALL
# serviceName - USER GROUP MANAGEMENT
class UserGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_USER_GROUP_ALL")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ServiceID - AUTH_ACL
# serviceName - ACL MANAGEMENT
class ACLPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_ACL")

        if result['status_code'] == 202:
            return True
        else:
            return False
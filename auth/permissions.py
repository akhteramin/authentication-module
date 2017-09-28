import jwt
from auth.settings import SECRET_KEY, SUPERUSER
from rest_framework import permissions
from auth_jwt.models import Auth, Token
from user_group.models import UserGroup
from acl.models import ACL
from services.models import ServiceList


def token_validation_and_get_user(request):
    response = {}
    try:
        if request.META.get('HTTP_TOKEN') is not None:
            token = request.META['HTTP_TOKEN']

            try:
                payload = jwt.decode(token, SECRET_KEY)
                try:
                    user = Auth.objects.get(loginID=payload['loginID'], appID=payload['appID'], is_active=True)
                    token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])
                    response['status_code'] = 200
                    response['user'] = user
                    response['token'] = token_t
                    return response

                except Auth.DoesNotExist:
                    response['status_code'] = 412
                    return response

                except Token.DoesNotExist:
                    response['status_code'] = 412
                    return response

            except jwt.ExpiredSignatureError:
                response['status_code'] = 401
                return response
        else:
            response['status_code'] = 406
            return response
    except Exception as e:
        print(e)
        response['status_code'] = 500
        return response


def user_group_check(uid, gid):
    try:
        UserGroup.objects.get(user=uid, group=gid)
        return True
    except UserGroup.DoesNotExist:
        return False

    return False


def permission_check(request, sid=None):
    response = {}
    try:
        if sid is not None:
            service_id = sid
        elif request.META.get('HTTP_SERVICE_ID') is not None:
            service_id = request.META['HTTP_SERVICE_ID']
        else:
            response['status_code'] = 406
            return response

        result = token_validation_and_get_user(request)

        if result['status_code'] == 200:
            user = result['user']
            if user.loginID in SUPERUSER:
                response['status_code'] = 202
                return response
        else:
            return result

        service = ServiceList.objects.get(serviceID=service_id)
        groups = ACL.objects.filter(service=service.id)

        response['status_code'] = 401
        for entry in groups:
            if user_group_check(user.id, entry.group):
                response['status_code'] = 202
                break
            else:
                continue

        return response
    except Exception as e:
        print(e)
        response['status_code'] = 412
        return response


# Check Token Exists in Header
class HasToken(permissions.BasePermission):
     def has_permission(self, request, view):
        result = token_validation_and_get_user(request)

        if result['status_code'] == 200:
            return True
        else:
            return False


# ServiceID - AUTH_APP__ALL
# serviceName - APP MANAGEMENT
class AppPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_APP_ALL")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ServiceID - AUTH_USER__ALL
# serviceName - USER MANAGEMENT
class UserPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        result = permission_check(request, "AUTH_USER_ALL")

        if result['status_code'] == 202:
            return True
        else:
            return False


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
import jwt
from auth.settings import SECRET_KEY, SUPERUSER
from rest_framework import permissions
from auth_jwt.models import Auth, Token
from user_group.models import UserGroup
from acl.models import ACL
from services.models import ServiceList
from auth.tasks import save_activity

import json

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
    dataset=''
    try:
        if sid is not None:
            service_id = sid
        elif request.META.get('HTTP_SERVICE_ID') is not None:
            service_id = request.META['HTTP_SERVICE_ID']
        else:
            response['status_code'] = 406
            return response

        result = token_validation_and_get_user(request)
        print(result)
        if result['status_code'] == 200:

            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            if request.method == 'POST' or request.method == 'PATCH' or request.method == 'PUT':
                body_unicode = request.body.decode('utf-8')
                body = json.loads(body_unicode)
                dataset = body['content']

            async_result = save_activity.delay(payload['loginID'], payload['appID'], service_id,dataset)
            # return_value = async_result.get()
            # print(return_value)

            user = result['user']
            if user.loginID in SUPERUSER:
                response['status_code'] = 202
                return response
        else:
            return result

        service = ServiceList.objects.get(serviceID=service_id, appID=user.appID)
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


# ServiceID - App permission
class AppPermission(permissions.BasePermission):
    def has_permission(self, request, view):

        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_APPLICATION_LIST")
            else:
                result = permission_check(request, "AUTH_GET_APPLICATION_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ADD_APPLICATION")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_APPLICATION")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_APPLICATION")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_APPLICATION")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ServiceID - EMAIL permission
class EmailPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_EMAIL_DOMAIN_LIST")
            else:
                result = permission_check(request, "AUTH_GET_EMAIL_DOMAIN_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ADD_EMAIL_DOMAIN")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_EMAIL_DOMAIN")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_EMAIL_DOMAIN")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_EMAIL_DOMAIN")

        if result['status_code'] == 202:
            return True
        else:
            return False


# User - User list permission
class UserPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_USER_LIST")
            else:
                result = permission_check(request, "AUTH_GET_USER_BY_ID")

        if result['status_code'] == 202:
            return True
        else:
            return False


# User - Search User list permission
class SearchUserPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            result = permission_check(request, "AUTH_SEARCH_USER")

        if result['status_code'] == 202:
            return True
        else:
            return False


# User - Create User permission
class UserCreationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='POST':
                result = permission_check(request, "AUTH_CREATE_USER")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Account - Create Account activate
class AccountActivatePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'PUT':
            result = permission_check(request, "AUTH_ACTIVATE_USER")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Account - Create Account deactivate
class AccountDeactivatePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'PUT':
            result = permission_check(request, "AUTH_DEACTIVATE_USER")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Account - Set Password
class SetPasswordPermission():
    def has_permission(self, request, view):
        if request.method == 'PUT':
            result = permission_check(request, "AUTH_SET_PASSWORD")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Group - Basic Group Permission
class GroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_GROUP_LIST")
            else:
                result = permission_check(request, "AUTH_GET_GROUP_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ADD_GROUP")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_GROUP")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_GROUP")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_GROUP")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Group - Search Group Permission
class SearchGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            result = permission_check(request, "AUTH_SEARCH_GROUP")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Group - Filter Group Permission
class GroupFilterPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_GROUP_FILTER_BY_APP_ID")
            else:
                result = permission_check(request, "AUTH_GET_GROUP_FILTER_BY_APP_ID")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Service - Basic Service Permission
class ServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):

        # result = permission_check(request, "AUTH_SERVICE_ALL")
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_SERVICE_LIST")
            else:
                result = permission_check(request, "AUTH_GET_SERVICE_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ADD_SERVICE")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_SERVICE")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_SERVICE")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_SERVICE")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Service - Search Service Permission
class SearchServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            result = permission_check(request, "AUTH_SEARCH_SERVICE")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Service - Filter Service Permission
class ServiceFilterPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_SERVICE_FILTER_BY_APP_ID")
            else:
                result = permission_check(request, "AUTH_GET_SERVICE_FILTER_BY_APP_ID")

        if result['status_code'] == 202:
            return True
        else:
            return False


# UserGroup - Basic User Group Permission
class UserGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_USER_GROUP_ALL")
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_USER_GROUP_LIST")
            else:
                result = permission_check(request, "AUTH_GET_USER_GROUP_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ASSIGN_USER_GROUP")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_USER_GROUP")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_USER_GROUP")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_USER_GROUP")


        if result['status_code'] == 202:
            return True
        else:
            return False


# UserGroup - UserGroup by Group Permission
class UserGroupDetailsByGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_USER_GROUP_ALL")
        if request.method == 'GET':
                result = permission_check(request, "AUTH_GET_USER_GROUP_BY_GROUP")

        if result['status_code'] == 202:
            return True
        else:
            return False


# UserGroup - UserGroup by User Permission
class UserGroupDetailsByUserPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_USER_GROUP_ALL")
        if request.method == 'GET':
                result = permission_check(request, "AUTH_GET_USER_GROUP_BY_USER")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ACL - ACL permission
class ACLPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_ACL")
        if request.method == 'GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_ACL_LIST")
            else:
                result = permission_check(request, "AUTH_GET_ACL_BY_ID")
        elif request.method == 'POST':
            result = permission_check(request, "AUTH_ASSIGN_GROUP_SERVICE")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_ACL")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_ACL")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_ACL")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ACL - ACL Details permission
class ACLDetailsPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_ACL")
        if request.method == 'GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_ACL_DETAILS_LIST")
            else:
                result = permission_check(request, "AUTH_GET_ACL_DETAILS_BY_ID")


        if result['status_code'] == 202:
            return True
        else:
            return False


# ACL - ACL Details by Group permission
class ACLDetailsByGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):

        if request.method == 'GET':
                result = permission_check(request, "AUTH_GET_ACL_DETAILS_BY_GROUP")

        if result['status_code'] == 202:
            return True
        else:
            return False


# ACL - ACL Details by Service permission
class ACLDetailsByServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
                result = permission_check(request, "AUTH_GET_ACL_DETAILS_BY_SERVICE")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Activity - Basic Activity Permission
class ActivityPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_ACTIVITY_LIST")
            else:
                result = permission_check(request, "AUTH_GET_ACTIVITY_BY_ID")
        elif request.method =='POST':
            result = permission_check(request, "AUTH_ADD_ACTIVITY")
        elif request.method == 'DELETE':
            result = permission_check(request, "AUTH_DELETE_ACTIVITY")
        elif request.method == 'PATCH':
            result = permission_check(request, "AUTH_REPLACE_ACTIVITY")
        elif request.method == 'PUT':
            result = permission_check(request, "AUTH_UPDATE_ACTIVITY")

        if result['status_code'] == 202:
            return True
        else:
            return False


# Activity - Search Activity Permission
class SearchActivityPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method=='GET':
            result = permission_check(request, "AUTH_SEARCH_ACTIVITY")

        if result['status_code'] == 202:
            return True
        else:
            return False


# User Service - Basic User Service Permission
class UserServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_ACL")
        if request.method == 'GET':
            if 'limit' in request.GET:
                result = permission_check(request, "AUTH_GET_USER_SERVICE")
            else:
                result = permission_check(request, "AUTH_GET_USER_SERVICE_BY_ID")

        if result['status_code'] == 202:
            return True
        else:
            return False


# User Service - Search User Service Permission
class SearchUserServicePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # result = permission_check(request, "AUTH_ACL")
        if request.method == 'GET':
            result = permission_check(request, "AUTH_SEARCH_USER_SERVICE")

        if result['status_code'] == 202:
            return True
        else:
            return False
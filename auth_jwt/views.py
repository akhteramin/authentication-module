from passlib.hash import bcrypt_sha256
from datetime import datetime, timedelta
import jwt
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView

from acl.models import ACL
from auth.settings import SECRET_KEY, TOKEN_LIFE_TIME, REFRESH_TOKEN_WINDOW, SUPERUSER
from services.models import ServiceList
from rest_framework import permissions
from user_group.models import UserGroup
from .models import Auth, Token
from group.models import GroupList
from .serializers import BaseSerializer, ChangePasswordSerializer, SetPasswordSerializer
from .serializers import DeactiveSerializer, LoginSerializer, TokenSerializer

import logging
log = logging.getLogger(__name__)


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


class HasToken(permissions.BasePermission):
     def has_permission(self, request, view):
        result = token_validation_and_get_user(request)

        if result['status_code'] == 200:
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


class ReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Auth.objects.filter(appID="ADMIN")
    serializer_class = BaseSerializer
    permission_classes = (UserPermission,)


class ReadOnlyAPP(viewsets.ReadOnlyModelViewSet):
    queryset = Auth.objects.filter(appID="PRIYO_APP")
    serializer_class = BaseSerializer
    permission_classes = (UserPermission,)


class ReadOnlyBusiness(viewsets.ReadOnlyModelViewSet):
    queryset = Auth.objects.filter(appID="BUSINESS_TOOL")
    serializer_class = BaseSerializer
    permission_classes = (UserPermission,)


class Signup(APIView):
    def post(self, request, format=None):
        serializer = BaseSerializer(data=request.data)

        try:
            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                password = bcrypt_sha256.hash(password)
                deviceID = serializer.validated_data['deviceID']
                appID = "PRIYO_APP"
                serializer.validated_data['appID'] = appID
                serializer.validated_data['is_active'] = True

                response = {}

                if " " in loginID:
                    response['loginID'] = ["no whitespace allowed in loginID"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                if " " in serializer.validated_data['password']:
                    response['password'] = ["no whitespace allowed in password"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                serializer.validated_data['password'] = password

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID)
                    response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                    return Response(response, status=status.HTTP_409_CONFLICT)

                except Auth.DoesNotExist:
                    try:
                        group = GroupList.objects.get(groupID="PRIYO_APP")
                    except GroupList.DoesNotExist:
                        response['Group'] = "User Group PRIYO_APP Doesn't Exits!"
                        return Response(response, status=status.HTTP_424_FAILED_DEPENDENCY)

                    serializer.save()

                    try:
                        user = Auth.objects.get(id=serializer.data['id'])

                        payload = {
                            "loginID": loginID,
                            "appID": serializer.validated_data['appID'],
                            "deviceID": deviceID,
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                        token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                        token_t.save()
                        user_group = UserGroup(user=user, group=group)
                        user_group.save()
                    except Exception as e:
                        print(e)
                        user.delete()
                        return Response(status=status.HTTP_424_FAILED_DEPENDENCY)

                    response['token'] = token
                    return Response(response, status=status.HTTP_201_CREATED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Reset(APIView):
    permission_classes = (UserPermission,)

    def put(self, request, format=None):
        serializer = LoginSerializer(data=request.data)

        try:
            if serializer.is_valid():
                response = {}
                if " " in serializer.validated_data['password']:
                    response['password'] = ["no whitespace allowed in password"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                password = bcrypt_sha256.hash(password)
                deviceID = serializer.validated_data['deviceID']
                appID = "PRIYO_APP"

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID, is_active=True)
                    user.password = password
                    user.deviceID = deviceID
                    user.save()

                    payload = {
                        "loginID": loginID,
                        "appID": serializer.validated_data['appID'],
                        "deviceID": deviceID,
                        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                    }

                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

                    try:
                        token_t = Token.objects.get(user=user, deviceID=deviceID)
                        token_t.token = token
                        token_t.save()
                    except Token.DoesNotExist:
                        token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                        token_t.save()

                    response['token'] = token
                    return Response(response)

                except Auth.DoesNotExist:
                    return Response(status=status.HTTP_412_PRECONDITION_FAILED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class Create(APIView):
    permission_classes = (UserPermission,)

    def post(self, request, format=None):
        serializer = BaseSerializer(data=request.data)

        try:
            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                password = bcrypt_sha256.hash(password)
                deviceID = serializer.validated_data['deviceID']
                appID = "ADMIN"
                serializer.validated_data['appID'] = appID
                serializer.validated_data['is_active'] = True

                response = {}

                if " " in loginID:
                    response['loginID'] = ["no whitespace allowed in loginID"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                if " " in serializer.validated_data['password']:
                    response['password'] = ["no whitespace allowed in password"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                serializer.validated_data['password'] = password

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID)
                    response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                    return Response(response, status=status.HTTP_409_CONFLICT)

                except Auth.DoesNotExist:
                    serializer.save()

                    try:
                        user = Auth.objects.get(id=serializer.data['id'])

                        payload = {
                            "loginID": loginID,
                            "appID": serializer.validated_data['appID'],
                            "deviceID": deviceID,
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                        token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                        token_t.save()
                    except Exception as e:
                        print(e)
                        user.delete()
                        return Response(status=status.HTTP_424_FAILED_DEPENDENCY)

                    response['token'] = token
                    return Response(response, status=status.HTTP_201_CREATED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Business(APIView):
    permission_classes = (UserPermission,)

    def post(self, request, format=None):
        serializer = BaseSerializer(data=request.data)

        try:
            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                password = bcrypt_sha256.hash(password)
                deviceID = serializer.validated_data['deviceID']
                appID = "BUSINESS_TOOL"
                serializer.validated_data['appID'] = appID
                serializer.validated_data['is_active'] = True

                response = {}

                if " " in loginID:
                    response['loginID'] = ["no whitespace allowed in loginID"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                if " " in serializer.validated_data['password']:
                    response['password'] = ["no whitespace allowed in password"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                serializer.validated_data['password'] = password

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID)
                    response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                    return Response(response, status=status.HTTP_409_CONFLICT)

                except Auth.DoesNotExist:
                    serializer.save()

                    try:
                        user = Auth.objects.get(id=serializer.data['id'])

                        payload = {
                            "loginID": loginID,
                            "appID": serializer.validated_data['appID'],
                            "deviceID": deviceID,
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                        token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                        token_t.save()
                    except Exception as e:
                        print(e)
                        user.delete()
                        return Response(status=status.HTTP_424_FAILED_DEPENDENCY)

                    response['token'] = token
                    return Response(response, status=status.HTTP_201_CREATED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Login(APIView):
    def post(self, request, format=None):
        try:
            serializer = LoginSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                appID = serializer.validated_data['appID']
                deviceID = serializer.validated_data['deviceID']
                response = {}

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID, is_active=True)

                    if bcrypt_sha256.verify(password, user.password):
                        payload = {
                            "loginID": loginID,
                            "appID": appID,
                            "deviceID": deviceID,
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

                        try:
                            token_t = Token.objects.get(user=user, deviceID=deviceID)
                            token_t.token = token
                            token_t.save()
                        except Token.DoesNotExist:
                            token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                            token_t.save()

                        response['token'] = token
                        return Response(response)
                    else:
                        return Response(status=status.HTTP_400_BAD_REQUEST)

                except Auth.DoesNotExist:
                    return Response(status=status.HTTP_412_PRECONDITION_FAILED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Logout(APIView):
    permission_classes = (HasToken,)

    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, verify=False)
            user = Auth.objects.get(loginID=payload['loginID'], appID=payload['appID'], is_active=True)
            token_t = Token.objects.get(user=user, deviceID=payload['deviceID'])
            token_t.token = None
            token_t.save()
            return Response(status=status.HTTP_204_NO_CONTENT)

        except Auth.DoesNotExist:
            return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Token.DoesNotExist:
            return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class Verify(APIView):
    permission_classes = (HasToken,)

    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)

            try:
                user = Auth.objects.get(loginID=payload['loginID'], appID=payload['appID'], is_active=True)
                token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])
                return Response(status=status.HTTP_204_NO_CONTENT)

            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

            except Token.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_417_EXPECTATION_FAILED)


class CheckPermission(APIView):
    def get(self, request, format=None):
        try:
            result = permission_check(request)

            if result['status_code'] == 202:
                return Response(status=status.HTTP_202_ACCEPTED)
            elif result['status_code'] == 401:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
            elif result['status_code'] == 406:
                return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
            elif result['status_code'] == 412:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)
            else:
                return Response(status=status.HTTP_417_EXPECTATION_FAILED)
        except Exception as e:
            print(e)
            return Response(status=status.HTTP_400_BAD_REQUEST)


class Refresh(APIView):
    permission_classes = (HasToken,)

    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, verify=False)
            window = int(datetime.utcnow().timestamp()) - payload['exp']
            try:
                user = Auth.objects.get(loginID=payload['loginID'], is_active=True)
                token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])

                if window < REFRESH_TOKEN_WINDOW:
                    new_payload = {
                        "loginID": user.loginID,
                        "appID": user.appID,
                        "deviceID": token_t.deviceID,
                        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                    }

                    token = jwt.encode(new_payload, SECRET_KEY, algorithm='HS256')
                    token_t.token = token
                    token_t.save()

                    response = {
                        'token': token
                    }
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    return Response(status=status.HTTP_406_NOT_ACCEPTABLE)

            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

            except Token.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePassword(APIView):
    permission_classes = (HasToken,)

    def put(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            serializer = ChangePasswordSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
                old_password = bytes(serializer.validated_data['old_password'], 'utf-8')
                new_password = bytes(serializer.validated_data['new_password'], 'utf-8')
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            payload = jwt.decode(token, SECRET_KEY)

            try:
                if payload['loginID'] == loginID:
                    user = Auth.objects.get(loginID=loginID, appID=appID, is_active=True)
                    token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])

                    if bcrypt_sha256.verify(old_password, user.password):
                        user.password = bcrypt_sha256.hash(new_password)
                        user.save()

                        new_payload = {
                            "loginID": user.loginID,
                            "appID": user.appID,
                            "deviceID": payload['deviceID'],
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token = jwt.encode(new_payload, SECRET_KEY, algorithm='HS256')
                        token_t.token = token
                        token_t.save()

                        response = {
                            'token': token
                        }
                        return Response(response, status=status.HTTP_200_OK)
                    else:
                        return Response(status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response(status=status.HTTP_403_FORBIDDEN)

            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

            except Token.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetPassword(APIView):
    permission_classes = (UserPermission,)

    def put(self, request, format=None):
        try:
            serializer = SetPasswordSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
                new_password = bytes(serializer.validated_data['password'], 'utf-8')
                new_password = bcrypt_sha256.hash(new_password)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = Auth.objects.get(loginID=loginID, appID=appID, is_active=True)
                user.password = new_password
                user.save()
                token_t = Token.objects.filter(user=user).update(token=None)
                return Response(status=status.HTTP_204_NO_CONTENT)
            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeactiveAccount(APIView):
    permission_classes = (UserPermission,)

    def put(self, request, format=None):
        try:
            serializer = DeactiveSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = Auth.objects.get(loginID=loginID, appID=appID, is_active=True)
                user.is_active = False
                user.save()
                token_t = Token.objects.filter(user=user).update(token=None)
                return Response(status=status.HTTP_204_NO_CONTENT)
            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReactiveAccount(APIView):
    permission_classes = (UserPermission,)

    def put(self, request, format=None):
        try:
            serializer = DeactiveSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = Auth.objects.get(loginID=loginID, appID=appID, is_active=False)
                user.is_active = True
                user.save()
                token_t = Token.objects.filter(user=user).update(token=None)
                return Response(status=status.HTTP_204_NO_CONTENT)
            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
import jwt

from passlib.hash import bcrypt_sha256
from datetime import datetime, timedelta

from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import list_route

from auth.permissions import HasToken, UserPermission, permission_check
from auth.settings import SECRET_KEY, TOKEN_LIFE_TIME, REFRESH_TOKEN_WINDOW, SUPERUSER

from .models import Auth, Token


from .serializers import ReadOnlySerializer, BaseSerializer, LoginSerializer, TokenSerializer, UpdateBaseSerializer
from .serializers import DeactiveSerializer, ChangePasswordSerializer, SetPasswordSerializer

from auth.tasks import save_activity

import logging
log = logging.getLogger(__name__)


class ReadOnlyViewSet(viewsets.ModelViewSet):
    permission_classes = (HasToken,)
    queryset = Auth.objects.all()
    serializer_class = ReadOnlySerializer

    @list_route(url_path='')
    def get(self, request):
        login_id = ''
        app_id = ''
        account_status= ''
        try:
            login_id=request.query_params.get('login_id')
        except ValueError:
            login_id=''
        try:
            app_id=request.query_params.get('app_id')
        except ValueError:
            app_id=''
        try:
            account_status = request.query_params.get('is_active')
        except ValueError:
            account_status = ''
        if account_status == 'True':
            if login_id != '' and app_id != '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None),appID=request.query_params.get('app_id', None), is_active=True)
            elif login_id == '' and app_id != '':
                queryset = Auth.objects.filter(appID=request.query_params.get('app_id', None), is_active=True)
            elif login_id != '' and app_id == '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None), is_active=True)
            else:
                queryset = Auth.objects.all()
        elif account_status == 'False':
            if login_id != '' and app_id != '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None),appID=request.query_params.get('app_id', None), is_active=False)
            elif login_id == '' and app_id != '':
                queryset = Auth.objects.filter(appID=request.query_params.get('app_id', None), is_active=False)
            elif login_id != '' and app_id == '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None), is_active=False)
            else:
                queryset = Auth.objects.all()
        else:
            if login_id != '' and app_id != '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None),appID=request.query_params.get('app_id', None))
            elif login_id == '' and app_id != '':
                queryset = Auth.objects.filter(appID=request.query_params.get('app_id', None))
            elif login_id != '' and app_id == '':
                queryset = Auth.objects.filter(loginID=request.query_params.get('login_id', None))
            else:
                queryset = Auth.objects.all()

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class GetUserViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = (HasToken,)
    queryset = Auth.objects.all()
    serializer_class = ReadOnlySerializer

    @list_route(url_path='(?P<app_id>[0-9]+)/(?P<active>[0-9]+)')
    def user(self, request, pk=None, active=None, app_id=None,login_id=None):
        login_id = ''
        try:
            login_id=request.query_params.get('login_id')
        except ValueError:
            login_id=''
        print(login_id)
        if login_id is None:
            try:
                if active == '0':
                    queryset = Auth.objects.filter(appID=app_id)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
                elif active == '1':
                    queryset = Auth.objects.filter(appID=app_id, is_active=True)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
                elif active == '2':
                    queryset = Auth.objects.filter(appID=app_id, is_active=False)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
            except jwt.ExpiredSignatureError:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            except Exception as e:
                print(e)
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            try:
                if active == '0':
                    queryset = Auth.objects.filter(appID=app_id, loginID=login_id)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
                elif active == '1':
                    queryset = Auth.objects.filter(appID=app_id, is_active=True, loginID=login_id)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
                elif active == '2':
                    queryset = Auth.objects.filter(appID=app_id, is_active=False, loginID=login_id)
                    serializer = self.get_serializer(queryset, many=True)
                    return Response(serializer.data)
            except jwt.ExpiredSignatureError:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            except Exception as e:
                print(e)
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Create(APIView):
    # Since user will be created by other application
    permission_classes = (HasToken,)

    def post(self, request, format=None):
        serializer = BaseSerializer(data=request.data)
        response = {}
        try:
            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                password = bytes(serializer.validated_data['password'], 'utf-8')
                password = bcrypt_sha256.hash(password)
                deviceID = serializer.validated_data['deviceID']
                appID = serializer.validated_data['appID']


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
                    print("login id and appid existence")
                    print(response)
                    return Response(response, status=status.HTTP_409_CONFLICT)

                except Auth.DoesNotExist:
                    try:
                        user = Auth.objects.create(loginID=loginID, password=password, appID_id=appID, deviceID=deviceID, is_active=True)
                        user.save()
                    except Exception as e:
                        print(e)
                        return Response(status=status.HTTP_400_BAD_REQUEST)

                    try:
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

                    # response['message'] = "User Created Successfully!"
                    return Response(status=status.HTTP_201_CREATED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            if serializer.errors['non_field_errors']:
                response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                return Response(response, status=status.HTTP_409_CONFLICT)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(e,status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Update(APIView):
    # Since user will be created by other application
    permission_classes = (HasToken,)

    def post(self, request, format=None):
        serializer = UpdateBaseSerializer(data=request.data)
        response = {}
        try:
            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                deviceID = serializer.validated_data['deviceID']
                appID = serializer.validated_data['appID']


                if " " in loginID:
                    response['loginID'] = ["no whitespace allowed in loginID"]
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)

                try:
                    user = Auth.objects.get(loginID=loginID, appID=appID)
                    response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                    print("login id and appid existence")
                    print(response)
                    return Response(response, status=status.HTTP_409_CONFLICT)

                except Auth.DoesNotExist:
                    try:
                        userPass = Auth.objects.filter(loginID=loginID, is_active=True).first()
                        user = Auth.objects.create(loginID=loginID, password=userPass.password, appID_id=appID, deviceID=deviceID, is_active=True)
                        user.save()
                    except Exception as e:
                        print(e)
                        return Response(status=status.HTTP_400_BAD_REQUEST)

                    try:
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

                    # response['message'] = "User Created Successfully!"
                    return Response(status=status.HTTP_201_CREATED)

                except Exception as e:
                    print(e)
                    return Response(status=status.HTTP_400_BAD_REQUEST)

            if serializer.errors['non_field_errors']:
                response['loginID and appID'] = ['Combination of loginID and appID Already Exists!']
                return Response(response, status=status.HTTP_409_CONFLICT)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
            return Response(e,status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Login(APIView):
    def post(self, request, format=None):
        try:
            serializer = LoginSerializer(data=request.data)

            print(request.data)

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
                        async_result = save_activity.delay(loginID, appID, 'AUTH_LOGIN_USER','')
                        # return_value = async_result.get()
                        # print(return_value)

                        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

                        try:
                            token_t = Token.objects.get(user=user, deviceID=deviceID)
                            token_t.token = token
                            token_t.save()
                        except Token.DoesNotExist:
                            token_t = Token.objects.create(user=user, token=token, deviceID=deviceID)
                            print(token_t)
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
    # permission_classes = (HasToken,)

    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, verify=False)
            user = Auth.objects.filter(loginID=payload['loginID'], deviceID=payload['deviceID'], is_active=True)

            async_result = save_activity.delay(payload['loginID'], payload['appID'], 'AUTH_LOGOUT_USER', '')
            # return_value = async_result.get()
            # print(return_value)

            token_t = Token.objects.filter(user__in=user, deviceID=payload['deviceID']).update(token=None)

            # token_t.token = None
            # token_t.save()
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
            print("login iD::", payload['loginID'])
            print("token::", token)
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


class VerifyAllApp(APIView):
    permission_classes = (HasToken,)
    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            print("login iD::", payload['loginID'])
            app_id = request.query_params.get('appID')
            device_id = request.query_params.get('deviceID')
            response = {}

            try:
                if Auth.objects.get(loginID=payload['loginID'], appID=app_id, is_active=True):
                    user = Auth.objects.get(loginID=payload['loginID'], appID=app_id, is_active=True)
                    payload = {
                        "loginID": payload['loginID'],
                        "appID": app_id,
                        "deviceID": device_id,
                        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                    }
                    async_result = save_activity.delay(payload['loginID'], app_id, 'AUTH_LOGIN_USER', '')
                    # return_value = async_result.get()
                    # print(return_value)

                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

                    try:
                        token_t = Token.objects.get(user=user, deviceID=device_id)
                        token_t.token = token
                        token_t.save()
                    except Token.DoesNotExist:
                        token_t = Token.objects.create(user=user, token=token, deviceID=device_id)
                        token_t.save()

                    response['token'] = token
                    return Response(response)
                else:
                    return Response(status=status.HTTP_400_BAD_REQUEST)

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
                user = Auth.objects.get(loginID=payload['loginID'], appID=payload["appID"], is_active=True)
                token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])

                if window < REFRESH_TOKEN_WINDOW:
                    new_payload = {
                        "loginID": user.loginID,
                        "appID": user.appID.id,
                        "deviceID": token_t.deviceID,
                        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                    }

                    print(new_payload)
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
                    # token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])
                    if bcrypt_sha256.verify(new_password, user.password):
                        return Response(status=status.HTTP_409_CONFLICT)

                    if bcrypt_sha256.verify(old_password, user.password):
                        # user.password = bcrypt_sha256.hash(new_password)
                        # user.save()
                        user_save = Auth.objects.filter(loginID=loginID, is_active=True).update(password=bcrypt_sha256.hash(new_password))

                        new_payload = {
                            "loginID": user.loginID,
                            "appID": user.appID.id,
                            "deviceID": payload['deviceID'],
                            "exp": datetime.utcnow() + timedelta(seconds=TOKEN_LIFE_TIME)
                        }

                        token_t = Token.objects.get(user=user, token=token, deviceID=payload['deviceID'])
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
                print("auth invalid")
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

            except Token.DoesNotExist:
                print("token invalid")
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetPassword(APIView):
    # permission_classes = (SetPasswordPermission,)
    permission_classes = (HasToken,)

    def put(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)

            serializer = SetPasswordSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
                new_password = bytes(serializer.validated_data['password'], 'utf-8')
                new_password = bcrypt_sha256.hash(new_password)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = Auth.objects.filter(loginID=loginID, is_active=True).update(password=new_password)
                # user.password = new_password
                # user.save()

                token_t = Token.objects.filter(user=user).update(token=None)

                return Response(status=status.HTTP_204_NO_CONTENT)
            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeactiveAccount(APIView):
    # permission_classes = (AccountActivatePermission,)
    permission_classes = (HasToken,)

    def put(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            print("token is here::",token)

            serializer = DeactiveSerializer(data=request.data)

            if serializer.is_valid():
                loginID = serializer.validated_data['loginID']
                appID = serializer.validated_data['appID']
                print(loginID)
                print(appID)
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
    # permission_classes = (AccountDeactivatePermission,)
    permission_classes = (HasToken,)

    def put(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            print(token)
            payload = jwt.decode(token, SECRET_KEY)

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

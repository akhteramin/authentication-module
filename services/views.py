from rest_framework import viewsets,status
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import ServicePermission
from .models import ServiceList
from .serializers import ServiceSerializer
from acl.serializers import GetACLSerializer
from auth_jwt.serializers import ReadUserSerializer
import jwt
from auth.settings import SECRET_KEY, SUPERUSER
from auth_jwt.models import Auth
from user_group.models import UserGroup
from acl.models import ACL
import logging
from auth.tasks import save_activity

log = logging.getLogger(__name__)


class ServiceViewSet(viewsets.ModelViewSet):
    # permission_classes = (ServicePermission,)
    queryset = ServiceList.objects.all()
    serializer_class = ServiceSerializer
    @list_route(url_path='')
    def get(self, request):
        service_id = ''
        app_id = ''
        # account_status= ''

        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            # push into activity DB
            async_result = save_activity.delay(payload['loginID'], payload['appID'], 'SEARCH_SERVICE_LIST')
            return_value = async_result.get()

            print(return_value)

            try:
                service_id=request.query_params.get('service_id')
            except ValueError:
                service_id=''
            try:
                app_id=request.query_params.get('app_id')
            except ValueError:
                app_id=''

            if service_id != '' and app_id != '':
                queryset = ServiceList.objects.filter(serviceID__icontains=request.query_params.get('service_id', None),appID=request.query_params.get('app_id', None))
            elif service_id == '' and app_id != '':
                queryset = ServiceList.objects.filter(appID=request.query_params.get('app_id', None))
            elif service_id != '' and app_id == '':
                queryset = ServiceList.objects.filter(serviceID__icontains=request.query_params.get('service_id', None))
            else:
                queryset = ServiceList.objects.all()

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetServiceViewSet(viewsets.ReadOnlyModelViewSet):
    # permission_classes = (ServicePermission,)
    queryset = ServiceList.objects.all()
    serializer_class = ServiceSerializer

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            # push into activity DB
            async_result = save_activity.delay(payload['loginID'], payload['appID'], 'GET_SERVICE_LIST_BY_APPID_'+app_id)
            return_value = async_result.get()

            print(return_value)
            queryset = ServiceList.objects.filter(appID=app_id)
            serializer = ServiceSerializer(queryset, many=True)

        # page = self.paginate_queryset(queryset)
        # if page is not None:
        #     serializer = self.get_serializer(page, many=True)
        #     return self.get_paginated_response(serializer.data)
        # serializer = self.get_serializer(queryset, many=True)
        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        return Response(serializer.data)


class GetServiceUserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ACL.objects.all()
    serializer_class = GetACLSerializer
    # permission_classes = (HasToken,)

    @list_route(url_path='')
    def get(self, request, format=None):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            # push into activity DB
            async_result = save_activity.delay(payload['loginID'], payload['appID'],
                                               'GET_USER_LIST_BY_SERVICE_' + request.query_params.get('service_id'))
            return_value = async_result.get()
            try:
                if 'service_id' in request.query_params:
                    print("user service is here::"+request.query_params.get('service_id'))
                    service=ServiceList.objects.get(serviceID=request.query_params.get('service_id'))
                    groups=ACL.objects.filter(service_id=service.id).values_list('group', flat=True)
                    users=UserGroup.objects.filter(group__in=groups).values_list('user', flat=True)
                    users = list(set(users))
                    details = Auth.objects.filter(pk__in=users,is_active=True)
                    serializer = ReadUserSerializer(details, many=True)
                    return Response(serializer.data)
            except Auth.DoesNotExist:
                return Response(status=status.HTTP_412_PRECONDITION_FAILED)
        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


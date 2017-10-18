from rest_framework import viewsets,status
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import GroupPermission
from .models import Activity
from .serializers import ActivitySerializer

from auth.settings import SECRET_KEY, SUPERUSER
import jwt
from auth.tasks import save_activity


import logging
log = logging.getLogger(__name__)


class ActivityViewSet(viewsets.ModelViewSet):
    # permission_classes = (GroupPermission,)
    queryset = Activity.objects.all()
    serializer_class = ActivitySerializer


    @list_route(url_path='')
    def get(self, request):
        login_id = ''
        app_id = ''
        service=''
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)
            # push into activity DB
            async_result = save_activity.delay(payload['loginID'], payload['appID'], 'SEARCH_ACTIVITY_LIST')
            return_value = async_result.get()

            print(return_value)
            try:
                login_id=request.query_params.get('login_id')
            except ValueError:
                login_id=''
            try:
                app_id=request.query_params.get('app_id')
            except ValueError:
                app_id=''
            try:
                service=request.query_params.get('service_name')
            except ValueError:
                service=''

            if login_id != '' and app_id != '' and service != '':
                queryset = Activity.objects.filter(user__icontains=request.query_params.get('login_id', None),
                                                   app=request.query_params.get('app_id', None),
                                                   service__icontains=request.query_params.get('service_name', None))
            elif login_id == '' and app_id != '' and service != '':
                queryset = Activity.objects.filter(app=request.query_params.get('app_id', None),
                                                   service__icontains=request.query_params.get('service_name', None))
            elif login_id != '' and app_id == '' and service != '':
                queryset = Activity.objects.filter(user__icontains=request.query_params.get('login_id', None),
                                                   service__icontains=request.query_params.get('service_name', None))
            elif login_id != '' and app_id != '' and service == '':
                queryset = Activity.objects.filter(user__icontains=request.query_params.get('login_id', None),
                                                   app=request.query_params.get('app_id', None))
            elif login_id != '' and app_id == '' and service == '':
                queryset = Activity.objects.filter(user__icontains=request.query_params.get('login_id', None))
            elif login_id == '' and app_id != '' and service == '':
                queryset = Activity.objects.filter(app=request.query_params.get('app_id', None))
            elif login_id == '' and app_id == '' and service != '':
                queryset = Activity.objects.filter(service__icontains=request.query_params.get('service_name', None))
            else:
                queryset = Activity.objects.all()
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



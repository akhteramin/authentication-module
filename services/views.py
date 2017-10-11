from rest_framework import viewsets
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import ServicePermission
from .models import ServiceList
from .serializers import ServiceSerializer

import logging
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

class GetServiceViewSet(viewsets.ReadOnlyModelViewSet):
    # permission_classes = (ServicePermission,)
    queryset = ServiceList.objects.all()
    serializer_class = ServiceSerializer

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        queryset = ServiceList.objects.filter(appID=app_id)
        # serializer = ServiceSerializer(queryset, many=True)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)

        return Response(serializer.data)

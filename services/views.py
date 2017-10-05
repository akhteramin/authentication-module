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


class GetServiceViewSet(viewsets.ReadOnlyModelViewSet):
    # permission_classes = (ServicePermission,)
    queryset = ServiceList.objects.all()
    serializer_class = ServiceSerializer

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        queryset = ServiceList.objects.filter(appID=app_id)
        serializer = ServiceSerializer(queryset, many=True)
        return Response(serializer.data)

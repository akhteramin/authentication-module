from rest_framework import viewsets
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import GroupPermission
from .models import GroupList
from .serializers import GroupSerializer

import logging
log = logging.getLogger(__name__)


class GroupViewSet(viewsets.ModelViewSet):
    # permission_classes = (GroupPermission,)
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer


class GetGroupViewSet(viewsets.ReadOnlyModelViewSet):
    # permission_classes = (GroupPermission,)
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        queryset = GroupList.objects.filter(appID=app_id)
        serializer = GroupSerializer(queryset, many=True)
        return Response(serializer.data)
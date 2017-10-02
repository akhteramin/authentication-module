from rest_framework import viewsets
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import GroupPermission
from .models import GroupList
from .serializers import GroupSerializer

import logging
log = logging.getLogger(__name__)


class GroupViewSet(viewsets.ModelViewSet):
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (GroupPermission,)


class GetGroupViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (GroupPermission,)

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        queryset = GroupList.objects.filter(appID=app_id)
        serializer = GroupSerializer(queryset, many=True)
        return Response(serializer.data)
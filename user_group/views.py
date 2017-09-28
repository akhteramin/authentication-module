from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import list_route
from auth.permissions import UserGroupPermission
from .models import UserGroup
from .serializers import UserGroupSerializer, GetUserGroupSerializer, GetGroupSerializer, GetUserSerializer

import logging
log = logging.getLogger(__name__)


class GetUserGroupViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = UserGroup.objects.all()
    serializer_class = GetUserGroupSerializer
    permission_classes = (UserGroupPermission,)

    @list_route(url_path='user/(?P<user_id>[0-9]+)')
    def user(self, request, pk=None, user_id=None):
        queryset = UserGroup.objects.filter(user=user_id)
        serializer = GetGroupSerializer(queryset, many=True)
        return Response(serializer.data)

    @list_route(url_path='group/(?P<group_id>[0-9]+)')
    def group(self, request, pk=None, group_id=None):
        queryset = UserGroup.objects.filter(group=group_id)
        serializer = GetUserSerializer(queryset, many=True)
        return Response(serializer.data)


class UserGroupViewSet(viewsets.ModelViewSet):
    queryset = UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    permission_classes = (UserGroupPermission,)


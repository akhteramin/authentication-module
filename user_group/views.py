from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import list_route
from auth.permissions import UserGroupPermission, HasToken
from .models import UserGroup
from .serializers import UserGroupSerializer, GetUserGroupSerializer, GetGroupSerializer, GetUserSerializer

from auth.settings import SECRET_KEY, SUPERUSER
import jwt
from auth.tasks import save_activity

import logging
log = logging.getLogger(__name__)


class GetUserGroupViewSet(viewsets.ReadOnlyModelViewSet):
    # permission_classes = (UserGroupDetailsPermission,)
    permission_classes = (UserGroupPermission,)

    queryset = UserGroup.objects.all()
    serializer_class = GetUserGroupSerializer

    @list_route(url_path='user/(?P<user_id>[0-9]+)')
    def user(self, request, pk=None, user_id=None):
        # permission_classes = (UserGroupDetailsByGroupPermission,)
        permission_classes = (UserGroupPermission,)
        try:
            queryset = UserGroup.objects.filter(user=user_id)
            serializer = GetGroupSerializer(queryset, many=True)
            return Response(serializer.data)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    @list_route(url_path='group/(?P<group_id>[0-9]+)')
    def group(self, request, pk=None, group_id=None):
        # permission_classes = (UserGroupDetailsByUserPermission,)
        permission_classes = (UserGroupPermission,)
        try:
            queryset = UserGroup.objects.filter(group=group_id)
            serializer = GetUserSerializer(queryset, many=True)
            return Response(serializer.data)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            print(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserGroupViewSet(viewsets.ModelViewSet):
    permission_classes = (UserGroupPermission,)
    queryset = UserGroup.objects.all()
    serializer_class = UserGroupSerializer


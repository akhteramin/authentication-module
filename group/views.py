import jwt
from rest_framework import viewsets, status
from rest_framework.decorators import list_route
from rest_framework.response import Response
from auth.permissions import GroupPermission
from .models import GroupList
from .serializers import GroupSerializer
from auth.settings import SECRET_KEY

import logging
log = logging.getLogger(__name__)


class GroupViewSet(viewsets.ModelViewSet):
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (GroupPermission,)


class GroupReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (GroupPermission,)

    @list_route(url_path='')
    def app(self, request):
        try:
            token = request.META['HTTP_TOKEN']
            payload = jwt.decode(token, SECRET_KEY)

            queryset = GroupList.objects.filter(appID=payload['appID'])
            serializer = GroupSerializer(queryset, many=True)
            return Response(serializer.data)

        except jwt.ExpiredSignatureError:
            return Response(status=status.HTTP_401_UNAUTHORIZED)


class GetGroupViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GroupList.objects.all()
    serializer_class = GroupSerializer
    permission_classes = (GroupPermission,)

    @list_route(url_path='(?P<app_id>[0-9]+)')
    def service(self, request, pk=None, app_id=None):
        queryset = GroupList.objects.filter(appID=app_id)
        serializer = GroupSerializer(queryset, many=True)
        return Response(serializer.data)
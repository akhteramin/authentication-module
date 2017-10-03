from rest_framework import viewsets
from auth.permissions import AppPermission
from .models import AppList
from .serializers import AppSerializer

import logging
log = logging.getLogger(__name__)


class AppViewSet(viewsets.ModelViewSet):
    queryset = AppList.objects.all()
    serializer_class = AppSerializer
    # permission_classes = (AppPermission,)
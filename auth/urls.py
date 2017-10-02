from django.conf.urls import url, include
from . import views
from . import settings
from rest_framework_swagger.views import get_swagger_view

# from rest_framework_swagger.views import get_swagger_view
from rest_framework import routers
from app.views import AppViewSet
from group.views import GroupViewSet, GroupReadOnlyViewSet, GetGroupViewSet
from services.views import ServiceViewSet
from auth_jwt.views import ReadOnlyViewSet
from acl.views import ACLViewSet, GetACLViewSet
from user_group.views import UserGroupViewSet, GetUserGroupViewSet


router = routers.SimpleRouter()

router.register(r'app', AppViewSet)

router.register(r'acl', ACLViewSet)
router.register(r'acl/details', GetACLViewSet)

router.register(r'group', GroupViewSet)
# router.register(r'group/filtered', GroupReadOnlyViewSet)
router.register(r'group/filtered/app', GetGroupViewSet)

router.register(r'service', ServiceViewSet)

router.register(r'user_group', UserGroupViewSet)
router.register(r'user_group/details', GetUserGroupViewSet)

router.register(r'user', ReadOnlyViewSet)

schema_view = get_swagger_view(title="Auth Module")

urlpatterns = [
    url(r'^auth/api/v1/', include(router.urls)),
    url(r'^auth/api/v1/', include('auth_jwt.urls')),
    url(r'^auth/api/v1/', include('acl.urls')),
]

handler400 = views.http400
handler403 = views.http403
handler404 = views.http404
handler500 = views.http500

if settings.DEBUG:
    urlpatterns += [
        url(r'^auth/api/v1/docs', schema_view),
    ]


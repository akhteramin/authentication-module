from django.conf.urls import url, include
from django.contrib import admin

from . import views
from . import settings

from rest_framework_swagger.views import get_swagger_view
from rest_framework import routers

from app.views import AppViewSet
from email_domain.views import EmailViewSet
from group.views import GroupViewSet, GetGroupViewSet
from services.views import ServiceViewSet, GetServiceViewSet
from auth_jwt.views import ReadOnlyViewSet
from acl.views import ACLViewSet, GetACLViewSet
from user_group.views import UserGroupViewSet, GetUserGroupViewSet


if settings.DEBUG:
    router = routers.DefaultRouter()
else:
    router = routers.SimpleRouter()

router.register(r'app', AppViewSet)
router.register(r'email/domain', EmailViewSet)

router.register(r'acl', ACLViewSet)
router.register(r'acl/details', GetACLViewSet)

router.register(r'group', GroupViewSet)
router.register(r'group/filtered/app', GetGroupViewSet)

router.register(r'service', ServiceViewSet)
router.register(r'service/filtered/app', GetServiceViewSet)

router.register(r'user_group', UserGroupViewSet)
router.register(r'user_group/details', GetUserGroupViewSet)

router.register(r'user', ReadOnlyViewSet)
# router.register(r'user/filtered/userlist', ReadOnlyViewSet)


schema_view = get_swagger_view(title="Admin Auth Module")

urlpatterns = [
    url(r'^auth/api/v1/', include(router.urls)),
    url(r'^auth/api/v1/', include('auth_jwt.urls', namespace='jwt')),
    url(r'^auth/api/v1/', include('acl.urls', namespace='acl')),
]

handler400 = views.http400
handler403 = views.http403
handler404 = views.http404
handler500 = views.http500

if settings.DEBUG:
    urlpatterns += [
        url(r'^admin/', admin.site.urls),
        url(r'^silk/', include('silk.urls', namespace='silk')),
        url(r'^$', schema_view),
    ]


from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .views import Create, Login, Logout, Verify, Refresh, CheckPermission, VerifyAllApp, Update
from .views import ChangePassword, SetPassword, DeactiveAccount, ReactiveAccount

urlpatterns = [
    url(r'^create/', Create.as_view()),
    url(r'^update/', Update.as_view()),
    url(r'^login/', Login.as_view()),
    url(r'^logout/', Logout.as_view()),
    url(r'^password/change/', ChangePassword.as_view()),
    url(r'^password/set/', SetPassword.as_view()),
    url(r'^account/deactivate', DeactiveAccount.as_view()),
    url(r'^account/reactivate', ReactiveAccount.as_view()),
    url(r'^token/verify/', Verify.as_view()),
    url(r'^token/validation/', CheckPermission.as_view()),
    url(r'^token/refresh/', Refresh.as_view()),
    url(r'^token/renew/', VerifyAllApp.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)

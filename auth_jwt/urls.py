from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .views import Signup, Reset, Create, Business, Login, Logout, Verify, Refresh, CheckPermission
from .views import ChangePassword, SetPassword, DeactiveAccount, ReactiveAccount

urlpatterns = [
    url(r'^signup/', Signup.as_view()),
    url(r'^reset/', Reset.as_view()),
    url(r'^create/', Create.as_view()),
    url(r'^business/create/', Business.as_view()),
    url(r'^login/', Login.as_view()),
    url(r'^logout/', Logout.as_view()),
    url(r'^password/change/', ChangePassword.as_view()),
    url(r'^password/set/', SetPassword.as_view()),
    url(r'^account/deactivate', DeactiveAccount.as_view()),
    url(r'^account/reactivate', ReactiveAccount.as_view()),
    url(r'^token/verify/', Verify.as_view()),
    url(r'^token/validation/', CheckPermission.as_view()),
    url(r'^token/refresh/', Refresh.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)

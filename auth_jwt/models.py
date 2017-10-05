from django.db import models
from app.models import AppList


class Auth(models.Model):
    loginID = models.CharField(max_length=255, db_index=True)
    password = models.TextField()
    appID = models.ForeignKey(AppList, on_delete=models.PROTECT, db_index=True)
    deviceID = models.TextField() # Keeping Signup Device ID
    is_active = models.BooleanField(default=True, db_index=True)
    # createdBY = models.ForeignKey('self', on_delete=models.PROTECT)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['appID', 'loginID']
        db_table = 'auth'
        default_permissions = []
        unique_together = ('loginID', 'appID')


class Token(models.Model):
    user = models.ForeignKey(Auth, on_delete=models.PROTECT, db_index=True)
    token = models.TextField(null=True)
    deviceID = models.TextField(db_index=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['user']
        db_table = 'token'
        default_permissions = []
        unique_together = ('user', 'deviceID')

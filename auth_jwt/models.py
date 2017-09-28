from django.db import models


class Auth(models.Model):
    loginID = models.CharField(max_length=255, db_index=True)
    password = models.TextField()
    appID = models.CharField(max_length=255)
    deviceID = models.TextField() # Keeping Signup Device ID
    is_active = models.BooleanField(default=True)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['loginID']
        db_table = 'auth'
        default_permissions = []
        unique_together = ('loginID', 'appID')


class Token(models.Model):
    user = models.ForeignKey(Auth, on_delete=models.CASCADE, db_index=True)
    token = models.TextField(null=True)
    deviceID = models.TextField()
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['user']
        db_table = 'token'
        unique_together = ('user', 'deviceID')
        default_permissions = []

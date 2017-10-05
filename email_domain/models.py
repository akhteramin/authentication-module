from django.db import models
from auth_jwt.models import Auth


class EmailDomain(models.Model):
    domain = models.CharField(unique=True, max_length=255)
    # createdBY = models.ForeignKey(Auth, on_delete=models.PROTECT)
    createdAT = models.DateTimeField(auto_now_add=True, auto_now=False)
    updatedAT = models.DateTimeField(auto_now_add=False, auto_now=True)

    class Meta:
        ordering = ['domain']
        db_table = 'email_domain'
        default_permissions = []
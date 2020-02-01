from django.db import models

# Create your models here.

class Customer(models.Model):

    name = models.CharField(max_length = 200)

    phonenumber = models.CharField(max_length=200)

    address = models.CharField(max_length=200)

    qq = models.CharField(max_length=200, null=True, blank=True)



from django.contrib import admin
admin.site.register(Customer)
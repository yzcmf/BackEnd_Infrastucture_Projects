from django.db import models
from django.contrib import admin
import datetime


class Customer(models.Model):
    name = models.CharField(max_length=200)

    phonenumber = models.CharField(max_length=200)

    address = models.CharField(max_length=200)

    # qq = models.CharField(max_length=200, null=True, blank=True)


class Medicine(models.Model):
    # 药品名
    name = models.CharField(max_length=200)
    # 药品编号
    sn = models.CharField(max_length=200)
    # 描述
    desc = models.CharField(max_length=200)


class Order(models.Model):
    # 订单名
    name = models.CharField(max_length=200, null=True, blank=True)
    # 创建日期
    create_date = models.DateTimeField(default=datetime.datetime.now)
    # 客户
    customer = models.ForeignKey(Customer, on_delete=models.PROTECT)
    # 订单购买的药品，和Medicine表是多对多 的关系
    medicines = models.ManyToManyField(Medicine, through='OrderMedicine')


class OrderMedicine(models.Model):
    order = models.ForeignKey(Order, on_delete=models.PROTECT)
    medicine = models.ForeignKey(Medicine, on_delete=models.PROTECT)

    # 订单中药品的数量
    amount = models.PositiveIntegerField()


admin.site.register(Customer)

'''
CASCADE

删除主键记录和 相应的外键表记录。

比如，我们要删除客户张三，在删除了客户表中张三记录同时，也删除Order表中所有这个张三的订单记录

PROTECT

禁止删除记录。

比如，我们要删除客户张三，如果Order表中有张三的订单记录，Django系统 就会抛出ProtectedError类型的异常，当然也就禁止删除 客户记录和相关的订单记录了。

除非我们将Order表中所有张三的订单记录都先删除掉，才能删除该客户表中的张三记录。

SET_NULL

删除主键记录，并且将外键记录中外键字段的值置为null。 当然前提是外键字段要设置为值允许是null。

比如，我们要删除客户张三时，在删除了客户张三记录同时，会将Order表里面所有的 张三记录里面的customer字段值置为 null。 但是上面我们并没有设置 customer 字段有 null=True 的参数设置，所以，是不能取值为 SET_NULL的。

'''

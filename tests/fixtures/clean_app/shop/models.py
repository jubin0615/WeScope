from django.db import models


class Product(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField()
    price = models.IntegerField()


class Order(models.Model):
    user = models.ForeignKey("auth.User", on_delete=models.CASCADE)


class Comment(models.Model):
    body = models.TextField()
    author = models.ForeignKey("auth.User", on_delete=models.CASCADE)

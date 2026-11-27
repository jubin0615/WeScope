"""vuln_django view와 같은 기능을 안전하게 구현한 판. 발견이 하나도 없어야 한다 (오탐 0 기준)."""
import json
import os
import subprocess
import uuid

import requests
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.html import escape
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Comment, Order, Product

SOURCES = {"weather": "https://api.weather.example/v1/today"}


def search(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM shop_product WHERE name LIKE %s", [f"%{q}%"])
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def product(request, slug):
    items = Product.objects.raw("SELECT * FROM shop_product WHERE slug = %s", [slug])
    return JsonResponse({"ids": [p.id for p in items]})


def cheap(request):
    items = Product.objects.extra(where=["price < %s"], params=[request.GET["max"]])
    return JsonResponse({"ids": [p.id for p in items]})


def greet(request):
    name = request.GET.get("name", "")
    return HttpResponse("<h1>Hello " + escape(name) + "</h1>")


def bio(request):
    return render(request, "shop/bio.html", {"bio": request.POST["bio"]})


def ping(request):
    host = request.POST["host"]
    out = subprocess.check_output(["ping", "-c", "1", host])
    return HttpResponse(out, content_type="text/plain")


def read_file(request):
    name = os.path.basename(request.GET["name"])
    with open(os.path.join("media", name)) as f:
        return HttpResponse(f.read(), content_type="text/plain")


def preview(request):
    resp = requests.get(SOURCES[request.GET["source"]], timeout=5)
    return JsonResponse({"status": resp.status_code})


def go_next(request):
    target = request.GET.get("next", "/")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}, require_https=True):
        return HttpResponseRedirect(target)
    return redirect(reverse("shop:search"))


def load_cart(request):
    cart = json.loads(request.COOKIES.get("cart", "[]"))
    return JsonResponse({"items": len(cart)})


@login_required
def upload(request):
    f = request.FILES["file"]
    saved = default_storage.save(f"uploads/{uuid.uuid4().hex}", f)
    return JsonResponse({"path": saved})


@login_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk, user=request.user)
    return JsonResponse({"id": order.id})


@login_required
@require_POST
def add_comment(request):
    Comment.objects.create(body=request.POST["body"], author=request.user)
    return JsonResponse({"ok": True}, status=201)


@staff_member_required
def staff_list(request):
    return JsonResponse({"staff": list(User.objects.filter(is_staff=True).values_list("username", flat=True))})


@login_required
@require_POST
def change_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return JsonResponse({"ok": True})


@csrf_exempt
@require_POST
def stripe_webhook(request):
    return JsonResponse({"received": True})


class UserDeleteView(PermissionRequiredMixin, View):
    permission_required = "auth.delete_user"

    def post(self, request, pk):
        User.objects.filter(pk=pk).delete()
        return JsonResponse({}, status=204)

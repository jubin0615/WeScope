"""WS-02·05 취약점을 심은 Django view. expect 주석 다음 줄에서 그 규칙이 잡혀야 한다."""
import base64
import os
import pickle
import subprocess

import requests
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template import Context, Template
from django.utils.safestring import mark_safe
from django.views import View
from django.views.decorators.http import require_POST

from .models import Comment, Order, Product


def search(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        # expect: inject-sql
        cursor.execute("SELECT id FROM shop_product WHERE name LIKE '%" + q + "%'")
        rows = cursor.fetchall()
    return JsonResponse({"rows": rows})


def product(request, slug):
    # expect: inject-sql
    items = Product.objects.raw(f"SELECT * FROM shop_product WHERE slug = '{slug}'")
    return JsonResponse({"ids": [p.id for p in items]})


def cheap(request):
    # expect: inject-sql
    items = Product.objects.extra(where=[f"price < {request.GET['max']}"])
    return JsonResponse({"ids": [p.id for p in items]})


def greet(request):
    name = request.GET.get("name", "")
    # expect: inject-xss
    return HttpResponse("<h1>Hello " + name + "</h1>")


def bio(request):
    # expect: inject-xss
    return render(request, "shop/bio.html", {"bio": mark_safe(request.POST["bio"])})


def note(request):
    # expect: inject-xss
    return JsonResponse({"html": Template(request.GET["tpl"]).render(Context({}))})


def ping(request):
    host = request.POST["host"]
    # expect: inject-command
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return JsonResponse({"out": out.decode()})


def calc(request):
    # expect: inject-code
    return JsonResponse({"result": eval(request.GET["expr"])})


def read_file(request):
    name = request.GET["name"]
    # expect: inject-path
    with open(os.path.join("media", name)) as f:
        return HttpResponse(f.read(), content_type="text/plain")


def preview(request):
    # expect: inject-ssrf
    resp = requests.get(request.GET["url"], timeout=5)
    return JsonResponse({"status": resp.status_code})


def go_next(request):
    # expect: inject-open-redirect
    return HttpResponseRedirect(request.GET.get("next", "/"))


def load_cart(request):
    # expect: inject-deserialize
    cart = pickle.loads(base64.b64decode(request.COOKIES["cart"]))
    return JsonResponse({"items": len(cart)})


@login_required
def upload(request):
    f = request.FILES["file"]
    # expect: inject-upload
    saved = default_storage.save(f.name, f)
    return JsonResponse({"path": saved})


# expect: authz-idor
@login_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk)
    return JsonResponse({"id": order.id})


# expect: authz-no-auth-write
@require_POST
def add_comment(request):
    Comment.objects.create(body=request.POST["body"])
    return JsonResponse({"ok": True}, status=201)


class UserDeleteView(LoginRequiredMixin, View):
    # expect: authz-admin-route
    def post(self, request, pk):
        User.objects.filter(pk=pk).delete()
        return JsonResponse({}, status=204)

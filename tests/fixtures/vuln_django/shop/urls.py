from django.urls import path, re_path

from . import api, views

app_name = "shop"
urlpatterns = [
    path("search/", views.search, name="search"),
    path("products/<slug:slug>/", views.product, name="product"),
    path("cheap/", views.cheap, name="cheap"),
    path("hello/", views.greet),
    path("bio/", views.bio),
    path("note/", views.note),
    path("ping/", views.ping),
    path("calc/", views.calc),
    path("files/", views.read_file),
    path("preview/", views.preview),
    path("next/", views.go_next),
    path("cart/", views.load_cart),
    path("upload/", views.upload),
    re_path(r"^orders/(?P<pk>\d+)/$", views.order_detail),
    path("comments/", views.add_comment),
    path("manage/users/<int:pk>/", views.UserDeleteView.as_view()),
    path("api/orders/<int:pk>/", api.OrderAPI.as_view()),
]

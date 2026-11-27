from django.urls import include, path, re_path
from rest_framework.routers import DefaultRouter

from . import api, generic, views

router = DefaultRouter()
router.register(r"orders", generic.OrderViewSet, basename="order")
router.register(r"manage/users", generic.UserViewSet)
router.register(r"comment-import", generic.CommentImportViewSet, basename="comment-import")

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
    path("manage/staff/<int:pk>/", api.StaffUserAPI.as_view()),
    path("api/orders/<int:pk>/note/", api.order_note),
    path("staff/", views.staff_list),            # 같은 view를 관리자 경로에도 건다
    path("manage/staff/", views.staff_list),
    path("orders/<int:pk>/view/", generic.OrderDetailView.as_view()),
    path("comments/<int:pk>/delete/", generic.CommentDeleteView.as_view()),
    path("api/v2/orders/<int:pk>/", generic.OrderUpdateAPI.as_view()),
    path("api/", include(router.urls)),
    path("account/email/", views.change_email),
    path("webhooks/stripe/", views.stripe_webhook),
]

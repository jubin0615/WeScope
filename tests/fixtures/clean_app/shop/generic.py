"""vuln_django generic.py와 같은 기능을 안전하게 쓴 판: 소유자로 거른 get_queryset, 관리자 권한, settings 기본 권한."""
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.views.generic import DeleteView, DetailView
from rest_framework import generics, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from .models import Comment, Order


class OrderDetailView(LoginRequiredMixin, DetailView):
    model = Order

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)


class CommentDeleteView(LoginRequiredMixin, DeleteView):
    model = Comment
    success_url = "/"

    def get_queryset(self):
        return Comment.objects.filter(author=self.request.user)


class OrderUpdateAPI(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)


class OrderViewSet(viewsets.ModelViewSet):      # 권한은 settings REST_FRAMEWORK 기본값(IsAuthenticated)

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAdminUser]


class CommentImportViewSet(viewsets.GenericViewSet):

    @action(detail=False, methods=["post"])
    def bulk(self, request):
        Comment.objects.bulk_create([Comment(body=b, author=request.user) for b in request.data["bodies"]])
        return Response(status=201)

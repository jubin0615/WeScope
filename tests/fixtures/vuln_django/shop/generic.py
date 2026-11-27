"""상속받은 동작(조회·수정·삭제)으로 일하는 제네릭 뷰·DRF ViewSet (WS-02). expect 주석 다음 줄에서 그 규칙이 잡혀야 한다."""
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.views.generic import DeleteView, DetailView
from rest_framework import generics, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Comment, Order


# expect: authz-idor
class OrderDetailView(LoginRequiredMixin, DetailView):
    model = Order


# expect: authz-idor, authz-no-auth-write
class CommentDeleteView(DeleteView):
    model = Comment
    success_url = "/"


# expect: authz-idor
class OrderUpdateAPI(generics.RetrieveUpdateDestroyAPIView):
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]


# expect: authz-idor
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]


# expect: authz-admin-route
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]


class CommentImportViewSet(viewsets.GenericViewSet):    # permission_classes 없음 + settings 기본값 없음 = AllowAny

    # expect: authz-no-auth-write
    @action(detail=False, methods=["post"])
    def bulk(self, request):
        Comment.objects.bulk_create([Comment(body=b) for b in request.data["bodies"]])
        return Response(status=201)

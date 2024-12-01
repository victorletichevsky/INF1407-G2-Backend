from django.urls import path
from .views import *

urlpatterns = [
    path('tasks/', TaskView.as_view(), name='tasks'),
    path('tasks/<int:pk>/', TaskView.as_view(), name='task-detail'),
    path('auth/token', CustomAuthToken.as_view(), name='token-auth'),
]

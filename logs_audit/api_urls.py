"""
REST API URL 配置

所有 API 端点以 /api/ 为前缀，使用 SessionAuthentication 认证。
"""

from django.urls import path
from . import api_views

urlpatterns = [
    path('logs/', api_views.LogFileListCreateView.as_view(), name='api_logs'),
    path('logs/<int:pk>/', api_views.LogFileDetailView.as_view(), name='api_log_detail'),
    path('logs/<int:pk>/attacks/', api_views.LogFileAttacksView.as_view(), name='api_log_attacks'),
    path('stats/', api_views.StatsView.as_view(), name='api_stats'),
]

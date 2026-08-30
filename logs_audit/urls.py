from django.urls import path
from . import views

urlpatterns = [
    #空路径，指向首页视图
    path('', views.index, name='index'),
    #动态路由，让用户通过带 ID 的网址（如 /detail/42/），去查看任何一个特定日志文件的详细分析图页表
    path('detail/<int:pk>/', views.log_detail, name='log_detail'),
    path('export/<int:pk>/', views.export_log_csv, name='export_log_csv'),
    # path('register/', views.register, name='register'),  # 已取消开放注册，改为后台分配账号
]

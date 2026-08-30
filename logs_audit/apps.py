from django.apps import AppConfig


class LogsAuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    #设置默认的自增主键类型为BigAutoField，支持64位整数
    name = 'logs_audit'
    #物理文件夹和首页汉化显示标题
    verbose_name = '安全日志管理'

    def ready(self):
        from django.contrib.auth.models import User, Group
        User._meta.verbose_name = '用户管理'
        User._meta.verbose_name_plural = '用户管理'
        Group._meta.verbose_name = '角色组管理'
        Group._meta.verbose_name_plural = '角色组管理'

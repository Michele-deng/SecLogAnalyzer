from django.contrib import admin
from .models import LogFile
#汉化管理界面
admin.site.site_header = '网站安全日志审计系统后台'
admin.site.site_title = '安全审计管理'
admin.site.index_title = '系统管理控制台'



#装饰器，绑定model里面的LogFile模型到admin界面
@admin.register(LogFile)
class LogFileAdmin(admin.ModelAdmin):
    list_display = ('filename', 'user', 'total_lines', 'sqli_count', 'xss_count', 'status', 'upload_time', 'file')
    search_fields = ('filename',)
    list_filter = ('upload_time', 'status')
    list_per_page = 20

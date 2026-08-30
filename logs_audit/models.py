from django.db import models
from django.contrib.auth.models import User

class LogFile(models.Model):
    """
    模型：日志文件
    用于存储用户上传的日志文件及其元数据，并关联到具体用户
    ORM 字段定义
    """
    # 关联用户模型，用于存储上传文件的用户信息
    #on_delete=models.CASCADE 级联删除用户日志文件  
    #related_name="log_files" User模型中添加一个 log_files 字段，反向查询关联的日志文件
    #null=True, blank=True 允许这个日志文件不属于任何用户 
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="所属用户", related_name="log_files", null=True, blank=True)
    # 文件名字段，用于存储上传的文件名
    #最大长度为255个字符
    filename = models.CharField(max_length=255, verbose_name="文件名")
    # 上传时间字段，用于存储文件上传的时间
    #自动添加当前时间
    upload_time = models.DateTimeField(auto_now_add=True, verbose_name="上传时间")
    # 文件路径字段，用于存储上传的文件路径
    #上传到 logs 目录
    file = models.FileField(upload_to='logs/', verbose_name="文件路径")
    

    # 分析字段
    sqli_count = models.IntegerField(default=0, verbose_name="SQL注入数")
    # XSS攻击数字段，用于存储文件中检测到的XSS攻击次数
    xss_count = models.IntegerField(default=0, verbose_name="XSS攻击数")
    total_lines = models.IntegerField(default=0, verbose_name="总行数")
    is_analyzed = models.BooleanField(default=False, verbose_name="是否已分析")
    
    # 状态字段：用于区分 分析成功、分析失败、待分析
    STATUS_CHOICES = [
        ('pending', '待分析'),
        ('success', '分析成功'),
        ('failed', '分析失败'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending', verbose_name="分析状态")
    # 状态字段：用于区分 分析成功、分析失败、待分析
    #默认值为 pending表示待分析，然后允许这个日志文件不属于任何用户 
    #错误信息字段，用于存储分析失败时的错误信息
    error_message = models.TextField(null=True, blank=True, verbose_name="错误信息")
    
    # 存储被标记为攻击的原始日志行和类型,每次的攻击详情打包成列表存入
    attack_details = models.JSONField(default=list, verbose_name="攻击详情")

    #打印、展示时显示文件名而不是对象地址
    def __str__(self):
        return self.filename
    #后台网页显示
    class Meta:
        verbose_name = "日志文件管理"
        verbose_name_plural = "日志文件管理"

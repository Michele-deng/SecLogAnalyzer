"""
REST API 序列化器

将 Django 模型和 Python 字典转换为 JSON 响应，同时处理反序列化和校验。
"""

from rest_framework import serializers
from .models import LogFile


class LogFileSerializer(serializers.ModelSerializer):
    """序列化 LogFile 模型（列表和详情展示用，不含 file 本地路径）"""
    attack_count = serializers.SerializerMethodField()

    class Meta:
        model = LogFile
        fields = [
            'id', 'filename', 'upload_time', 'total_lines',
            'sqli_count', 'xss_count', 'status', 'attack_count',
        ]
        read_only_fields = fields

    def get_attack_count(self, obj):
        return len(obj.attack_details) if obj.attack_details else 0


class LogFileCreateSerializer(serializers.Serializer):
    """处理文件上传（含扩展名和大小校验）"""
    file = serializers.FileField()

    ALLOWED_EXTENSIONS = ('.log', '.txt', '.csv', '.json')
    MAX_SIZE = 10 * 1024 * 1024  # 10MB

    def validate_file(self, value):
        # 扩展名校验
        import os
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            raise serializers.ValidationError(
                f"不支持的文件类型 '{ext}'，仅允许 {', '.join(self.ALLOWED_EXTENSIONS)}"
            )
        # 大小校验
        if value.size > self.MAX_SIZE:
            raise serializers.ValidationError(
                f"文件过大（{value.size / 1024 / 1024:.1f}MB），最大允许 10MB"
            )
        return value


class AttackDetailSerializer(serializers.Serializer):
    """序列化 attack_details JSONField 中的单条攻击记录"""
    line_no = serializers.IntegerField()
    type = serializers.CharField()
    ip = serializers.CharField()
    content = serializers.CharField()
    severity = serializers.CharField(required=False)
    mitre_tags = serializers.ListField(child=serializers.CharField(), required=False)
    matched_rules = serializers.ListField(child=serializers.CharField(), required=False)


class StatsSerializer(serializers.Serializer):
    """序列化全局统计数据"""
    total_files = serializers.IntegerField()
    total_lines = serializers.IntegerField()
    total_attacks = serializers.IntegerField()
    critical_attacks = serializers.IntegerField()
    attack_type_distribution = serializers.DictField()
    severity_distribution = serializers.DictField()

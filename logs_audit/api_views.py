"""
REST API 视图

提供日志文件的 CRUD 和统计查询接口，与 Web 视图（views.py）分离。
"""

import os
import logging
from collections import Counter

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import LogFile
from .serializers import (
    LogFileSerializer,
    LogFileCreateSerializer,
    AttackDetailSerializer,
    StatsSerializer,
)
from .utils import analyze_log
from .loader import load_rules

logger = logging.getLogger(__name__)


class LogFileListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/logs/  — 列出当前用户的所有日志文件（分页）
    POST /api/logs/  — 上传日志文件并触发分析
    """

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return LogFileCreateSerializer
        return LogFileSerializer

    def get_queryset(self):
        return LogFile.objects.filter(user=self.request.user).order_by('-upload_time')

    def create(self, request, *args, **kwargs):
        serializer = LogFileCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uploaded_file = serializer.validated_data['file']

        # 创建记录
        new_log = LogFile.objects.create(
            user=request.user,
            filename=uploaded_file.name,
            file=uploaded_file,
        )

        # 触发分析
        file_path = new_log.file.path
        if not os.path.exists(file_path):
            new_log.status = 'failed'
            new_log.error_message = '文件保存后未在磁盘找到'
            new_log.save()
            return Response(
                {'error': '文件保存失败'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        try:
            rules = load_rules()
            if not rules:
                logger.warning("检测规则为空")
        except Exception as e:
            logger.error(f"规则加载失败: {e}")
            new_log.status = 'failed'
            new_log.error_message = f'规则加载失败: {e}'
            new_log.save()
            return Response(
                {'error': '检测规则加载失败'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        result = analyze_log(file_path)

        if result.get('is_analyzed'):
            new_log.sqli_count = result['sqli_count']
            new_log.xss_count = result['xss_count']
            new_log.total_lines = result['total_lines']
            new_log.is_analyzed = True
            new_log.status = 'success'
            new_log.attack_details = result['attack_details']
            new_log.save()
        else:
            new_log.status = 'failed'
            new_log.error_message = result.get('error', '未知分析错误')
            new_log.save()

        # 返回完整记录
        output_serializer = LogFileSerializer(new_log)
        return Response(output_serializer.data, status=status.HTTP_201_CREATED)


class LogFileDetailView(generics.RetrieveAPIView):
    """
    GET /api/logs/{id}/ — 获取单个日志文件的详细分析结果
    """
    serializer_class = LogFileSerializer

    def get_queryset(self):
        return LogFile.objects.filter(user=self.request.user)


class LogFileAttacksView(APIView):
    """
    GET /api/logs/{id}/attacks/ — 获取单个文件的攻击详情列表
    """

    def get(self, request, pk):
        try:
            log_file = LogFile.objects.get(pk=pk, user=request.user)
        except LogFile.DoesNotExist:
            return Response(
                {'error': '日志文件不存在'},
                status=status.HTTP_404_NOT_FOUND,
            )

        attacks = log_file.attack_details or []
        serializer = AttackDetailSerializer(attacks, many=True)
        return Response({
            'file_id': log_file.pk,
            'filename': log_file.filename,
            'total_attacks': len(attacks),
            'attacks': serializer.data,
        })


class StatsView(APIView):
    """
    GET /api/stats/ — 获取当前用户的全局统计数据
    """

    def get(self, request):
        user_files = LogFile.objects.filter(user=request.user, status='success')

        total_files = user_files.count()
        total_lines = sum(f.total_lines for f in user_files)

        # 聚合所有攻击详情
        all_attacks = []
        for f in user_files:
            all_attacks.extend(f.attack_details or [])

        total_attacks = len(all_attacks)
        critical_attacks = sum(1 for a in all_attacks if a.get('severity') == 'critical')

        # 攻击类型分布
        type_counter = Counter()
        for a in all_attacks:
            for t in a.get('type', '').split(', '):
                t = t.strip()
                if t:
                    type_counter[t] += 1

        # 严重等级分布
        severity_counter = Counter()
        for a in all_attacks:
            sev = a.get('severity', 'unknown')
            severity_counter[sev] += 1

        data = {
            'total_files': total_files,
            'total_lines': total_lines,
            'total_attacks': total_attacks,
            'critical_attacks': critical_attacks,
            'attack_type_distribution': dict(type_counter),
            'severity_distribution': dict(severity_counter),
        }

        serializer = StatsSerializer(data)
        return Response(serializer.data)

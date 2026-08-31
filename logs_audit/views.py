from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib import messages
from django.http import HttpResponse
from collections import Counter
from .models import LogFile
from .utils import analyze_log
import os
import csv
import logging
from .loader import load_rules, load_whitelist

# 获取当前模块的日志记录器
logger = logging.getLogger(__name__)

@login_required
def index(request):
    """
    视图：首页
    处理日志文件的展示和上传逻辑，并在上传后触发安全分析
    仅展示当前登录用户上传的文件
    """
    # 1. 如果用户点击了“上传”按钮（提交了 POST 表单，且上传了名为 log_file 的文件）
    if request.method == 'POST' and request.FILES.get('log_file'):
        log_file = request.FILES['log_file']

        # ---- 文件上传安全校验 ----
        # 1. 扩展名白名单
        allowed_extensions = ('.log', '.txt', '.csv', '.json')
        file_ext = os.path.splitext(log_file.name)[1].lower()
        if file_ext not in allowed_extensions:
            messages.error(request, f"不支持的文件类型 '{file_ext}'，仅允许 {', '.join(allowed_extensions)}")
            return redirect('index')

        # 2. 文件大小限制（10MB）
        max_size = 10 * 1024 * 1024  # 10MB
        if log_file.size > max_size:
            messages.error(request, f"文件过大（{log_file.size / 1024 / 1024:.1f}MB），最大允许 10MB")
            return redirect('index')
        
        try:
            # 1. 保存原始记录，并关联到当前用户
            new_log = LogFile.objects.create(
                user=request.user,
                filename=log_file.name,
                file=log_file
            )
            
            # 2. 立即进行分析
            file_path = new_log.file.path
            if os.path.exists(file_path):
                # 检查规则是否能正常加载（analyze_log 内部也会加载，这里做前置检查给用户友好提示）
                try:
                    rules = load_rules()
                    if not rules:
                        messages.warning(request, "警告：检测规则为空，分析结果可能不准确。请检查 rules 目录。")
                except Exception as e:
                    logger.error(f"规则加载失败: {e}")
                    messages.error(request, "检测规则加载失败，请检查 rules 目录配置。")
                    return redirect('index')

                analysis_results = analyze_log(file_path)
                
                if analysis_results.get('is_analyzed'):
                    # 分析成功：更新数据和状态
                    new_log.sqli_count = analysis_results['sqli_count']
                    new_log.xss_count = analysis_results['xss_count']
                    new_log.total_lines = analysis_results['total_lines']
                    new_log.is_analyzed = True
                    new_log.status = 'success'
                    new_log.attack_details = analysis_results['attack_details']
                    new_log.save()
                    messages.success(request, f"文件 {log_file.name} 上传并分析成功！")
                else:
                    # 分析过程出错（但未抛出致命异常）
                    error_msg = analysis_results.get('error', '未知分析错误')#如果找到了（比如值为 "读取文件失败"），就赋值给 error_msg
                    new_log.status = 'failed'
                    new_log.error_message = error_msg
                    new_log.save()
                    messages.error(request, f"文件 {log_file.name} 分析失败: {error_msg}")
            else:
                raise FileNotFoundError(f"文件保存后未在磁盘找到: {file_path}")
                
        except Exception as e:
            # 捕获视图层出现的任何未预期错误
            logger.error(f"处理文件上传时发生异常: {str(e)}", exc_info=True)
            messages.error(request, "系统处理上传文件时出错，请稍后重试。")
            
        return redirect('index')
    # 2. 如果用户只是正常访问首页（GET 请求）
    # 仅过滤当前用户上传的文件
    files = LogFile.objects.filter(user=request.user).order_by('-upload_time')
    return render(request, 'logs_audit/index.html', {'files': files})

@login_required
def log_detail(request, pk):
    """
    视图：详情页
    展示特定日志文件的详细分析报告，仅限当前用户
    """
    log_file = get_object_or_404(LogFile, pk=pk, user=request.user)
    
    # 计算饼图数据
    # 准备 ECharts 数据
    attack_count = len(log_file.attack_details)
    normal_count = max(0, log_file.total_lines - attack_count)
    
    # 按实际攻击类型动态统计饼图数据
    attack_type_counter = Counter()
    for detail in log_file.attack_details:
        for t in detail.get('type', '').split(', '):
            t = t.strip()
            if t:
                attack_type_counter[t] += 1

    chart_data = [{'value': normal_count, 'name': '正常流量'}]
    for attack_type, count in attack_type_counter.items():
        chart_data.append({'value': count, 'name': attack_type})

    # 统计 Top 5 攻击源 IP
    ip_counter = Counter()
    for detail in log_file.attack_details:
        ip = detail.get('ip', '未知IP')
        ip_counter[ip] += 1
    
    top_5_ips = ip_counter.most_common(5)
    #自动完成排序，并直接返回出现次数最高的前 5 个元素
    top_ip_labels = [item[0] for item in top_5_ips]
    top_ip_counts = [item[1] for item in top_5_ips]

    return render(request, 'logs_audit/detail.html', {
        'log': log_file,
        'chart_data': chart_data,
        'top_ip_labels': top_ip_labels,
        'top_ip_counts': top_ip_counts
    })

@login_required
def export_log_csv(request, pk):
    """
    视图：一键导出 CSV 离线审计报告
    根据主键 pk 获取 LogFile 对象，将 attack_details 导出为 CSV 文件
    """
    log_file = get_object_or_404(LogFile, pk=pk, user=request.user)

    safe_filename = log_file.filename.replace('"', '').replace('/', '_').replace('\\', '_')
    #初始化自定义响应对象
    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    # 设置响应头，触发浏览器下载
    response['Content-Disposition'] = f'attachment; filename="audit_report_{safe_filename}.csv"'
    response.write('\ufeff')  # UTF-8 BOM，确保 Excel 打开不乱码

    #初始化 CSV 写入流对象
    writer = csv.writer(response)
    # 写入表头（CSV 的第一行）
    writer.writerow(['行号', '攻击类型', '源IP', '原始日志内容'])

    for detail in log_file.attack_details:
        writer.writerow([
            detail.get('line_no', ''),
            detail.get('type', ''),
            detail.get('ip', '未知IP'),
            detail.get('content', '')
        ])

    return response# 返回文件流，触发浏览器下载

@login_required
def dashboard(request):
    """
    视图：安全态势仪表盘
    聚合展示当前用户所有上传文件的安全态势总览。
    """
    user_files = LogFile.objects.filter(user=request.user, status='success')

    # ---- 区域 A：顶部统计卡片 ----
    total_files = user_files.count()
    total_lines = sum(f.total_lines for f in user_files)

    all_attacks = []
    for f in user_files:
        all_attacks.extend(f.attack_details or [])

    total_attacks = len(all_attacks)
    critical_attacks = sum(1 for a in all_attacks if a.get('severity') == 'critical')

    # ---- 区域 B：攻击类型分布饼图 ----
    type_counter = Counter()
    for a in all_attacks:
        for t in a.get('type', '').split(', '):
            t = t.strip()
            if t:
                type_counter[t] += 1

    type_chart_data = [{'value': count, 'name': atype} for atype, count in type_counter.items()]

    # ---- 区域 C：严重等级分布柱状图 ----
    severity_counter = Counter()
    for a in all_attacks:
        sev = a.get('severity', 'unknown')
        severity_counter[sev] += 1

    severity_order = ['critical', 'high', 'medium', 'low']
    severity_labels = [s for s in severity_order if s in severity_counter]
    severity_values = [severity_counter[s] for s in severity_labels]

    # ---- 区域 D：最近 5 次分析记录 ----
    recent_files = LogFile.objects.filter(user=request.user).order_by('-upload_time')[:5]
    recent_data = []
    for f in recent_files:
        attack_count = len(f.attack_details) if f.attack_details else 0
        recent_data.append({
            'id': f.pk,
            'filename': f.filename,
            'upload_time': f.upload_time,
            'total_lines': f.total_lines,
            'attack_count': attack_count,
            'status': f.status,
        })

    return render(request, 'logs_audit/dashboard.html', {
        'total_files': total_files,
        'total_lines': total_lines,
        'total_attacks': total_attacks,
        'critical_attacks': critical_attacks,
        'type_chart_data': type_chart_data,
        'severity_labels': severity_labels,
        'severity_values': severity_values,
        'recent_data': recent_data,
    })

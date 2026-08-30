"""
安全日志分析核心模块（Utils）

本模块是检测引擎的调度中心，负责：
  - 接收前端传来的文件路径
  - 加载 YAML 规则库（一次性）
  - 用多线程分块处理日志（ThreadPoolExecutor 4线程）
  - 每块日志内部：解析字段 -> 字段定向规则匹配 -> 白名单过滤
  - 汇总各线程结果，排序后返回

与旧版本的区别：
  旧版本：整行正则匹配（硬编码 select|union|<script> 等关键词）
  新版本：YAML 规则库驱动 + 字段定向匹配 + 白名单降噪 + ATT&CK 标签

面试要点：
  Q: "你的多线程分析是怎么做的？"
  A: "主线程用 ThreadPoolExecutor 开 4 个线程，按行数等分日志文件。
     每个线程独立运行检测引擎，最后主线程汇总合并结果并按行号排序。
     规则库只在主线程加载一次，通过参数传给各线程，避免重复 IO。"

  Q: "为什么用线程池而不是进程池？"
  A: "检测引擎主要是正则匹配的 CPU 密集型任务，Python 有 GIL 限制。
     但在实际项目中日志文件不会太大（几十MB），线程池已经够用。
     如果真要处理 GB 级日志，应该换成进程池(multiprocessing.Pool)
     或者异步框架（Celery + 消息队列）。"
"""

import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# 导入新引擎三件套
from .loader import load_rules, load_whitelist
from .parser import parse_log_line
from .engine import match_rules, get_max_severity, collect_mitre_tags, collect_rule_ids

logger = logging.getLogger(__name__)


def process_chunk(lines_chunk, start_line_no, rules, whitelist):
    """
    处理日志块的辅助函数：被线程池调用。

    与旧版本的区别：
      旧：在整行上做 sqli_pattern.search(line) + xss_pattern.search(line)
      新：先 parse_log_line() 拆字段，再 match_rules() 按字段定向匹配

    参数:
        lines_chunk (list[str]): 本块的日志行
        start_line_no (int): 本块在全局日志中的起始行号（从1开始）
        rules (list[dict]): 主线程传入的规则列表（避免每个线程重复加载）
        whitelist (list[dict]): 主线程传入的白名单列表
    """
    try:
        chunk_details = []
        chunk_sqli = 0
        chunk_xss = 0

        for i, line in enumerate(lines_chunk):
            try:
                line = line.strip()
                if not line:
                    continue

                # 1. 解析日志行，拆出 ip/method/uri/query/status 等字段
                parsed = parse_log_line(line)

                # 2. 用规则引擎做字段定向匹配（核心改动）
                hits = match_rules(parsed, rules, whitelist)

                # 3. 如果命中了规则，记录攻击详情
                if hits:
                    # 按规则类型分类统计（SQLi / XSS / 路径遍历 / 命令注入）
                    rule_ids = [h['rule_id'] for h in hits]
                    has_sqli = any(rid.startswith('sqli_') for rid in rule_ids)
                    has_xss = any(rid.startswith('xss_') for rid in rule_ids)
                    has_traversal = any(rid.startswith('path_traversal_') for rid in rule_ids)
                    has_cmdi = any(rid.startswith('cmdi_') for rid in rule_ids)

                    if has_sqli:
                        chunk_sqli += 1
                    if has_xss:
                        chunk_xss += 1
                    if has_traversal:
                        pass  # 路径遍历在 attack_details.type 中体现
                    if has_cmdi:
                        pass  # 命令注入同上

                    # 拼装攻击类型标签
                    attack_type = []
                    if has_sqli:
                        attack_type.append("SQL注入")
                    if has_xss:
                        attack_type.append("XSS攻击")
                    if has_traversal:
                        attack_type.append("路径遍历")
                    if has_cmdi:
                        attack_type.append("命令注入")

                    # 打包攻击详情（新增 severity/mitre_tags/matched_rules 字段）
                    chunk_details.append({
                        'line_no': start_line_no + i,
                        'content': line,
                        'type': ", ".join(attack_type),
                        'ip': parsed.get('ip', '未知IP'),
                        # ---- P0 新增字段 ----
                        'severity': get_max_severity(hits),
                        'mitre_tags': collect_mitre_tags(hits),
                        'matched_rules': collect_rule_ids(hits),
                    })

            except Exception as e:
                # 单行级容错：某一行出错不影响其他行
                logger.error(f"分析第 {start_line_no + i} 行时出现异常: {str(e)}")
                continue

        return chunk_sqli, chunk_xss, chunk_details

    except Exception as e:
        logger.error(f"线程块分析 (起始行: {start_line_no}) 发生致命错误: {str(e)}")
        return 0, 0, []


def analyze_log(file_path):
    """
    外部调用的主入口函数（多线程版）。

    与旧版本的区别：
      旧：process_chunk 内部硬编码正则，每个线程都编译一遍
      新：主线程加载一次 YAML 规则库，通过参数传给各线程
    """
    if not os.path.exists(file_path):
        logger.error(f"文件未找到: {file_path}")
        return {
            'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
            'is_analyzed': False, 'attack_details': [], 'error': "文件不存在"
        }

    try:
        # ---- 一次性加载规则库 ----
        try:
            rules = load_rules()
            whitelist = load_whitelist()
            logger.info(f"规则加载完成: {len(rules)} 条检测规则, {len(whitelist)} 条白名单")
        except Exception as e:
            logger.error(f"规则加载失败: {str(e)}")
            return {
                'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
                'is_analyzed': False, 'attack_details': [], 'error': f"规则加载失败: {str(e)}"
            }

        # ---- 读取文件（保持原有的编码回退逻辑）----
        lines = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='gbk') as f:
                    lines = f.readlines()
            except Exception as e:
                logger.error(f"文件编码无法识别或读取失败: {file_path}, 错误: {str(e)}")
                return {
                    'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
                    'is_analyzed': False, 'attack_details': [], 'error': "读取文件失败"
                }
        except Exception as e:
            logger.error(f"读取文件时发生未知错误: {file_path}, 错误: {str(e)}")
            return {
                'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
                'is_analyzed': False, 'attack_details': [], 'error': "系统读取错误"
            }

        total_lines = len(lines)
        attack_details = []
        sqli_count = 0
        xss_count = 0

        start_time = time.time()

        # ---- 多线程分块处理 ----
        num_threads = 4
        if total_lines > 0:
            chunk_size = max(1, total_lines // num_threads)

            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = []
                for i in range(0, total_lines, chunk_size):
                    chunk = lines[i : i + chunk_size]
                    # 规则和白名单作为参数传入，避免每个线程重复加载
                    futures.append(executor.submit(process_chunk, chunk, i + 1, rules, whitelist))

                for future in futures:
                    try:
                        c_sqli, c_xss, c_details = future.result()
                        sqli_count += c_sqli
                        xss_count += c_xss
                        attack_details.extend(c_details)
                    except Exception as e:
                        logger.error(f"合并线程分析结果时发生错误: {str(e)}")

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"文件 {os.path.basename(file_path)} 多线程分析完成，耗时：{duration:.4f}秒")

        # 按行号排序（多线程并发，结果顺序不保证）
        attack_details.sort(key=lambda x: x['line_no'])

        return {
            'sqli_count': int(sqli_count),
            'xss_count': int(xss_count),
            'total_lines': total_lines,
            'is_analyzed': True,
            'attack_details': attack_details
        }

    except Exception as e:
        logger.critical(f"分析主流程崩溃: {str(e)}", exc_info=True)
        return {
            'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
            'is_analyzed': False, 'attack_details': [], 'error': str(e)
        }

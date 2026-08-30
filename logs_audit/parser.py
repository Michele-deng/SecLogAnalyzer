"""
日志解析器（Parser）

功能：将单行原始日志解析为结构化字段字典。
职责：
  - 自动检测日志格式（JSON / Nginx combined / Syslog）
  - 调用对应格式的 parser，将不同格式统一转换为相同字段字典
  - 解析失败时返回带 parse_error 标记的降级字典，保证不崩溃

支持的格式：
  1. JSON access log（Nginx json_combined 格式，云原生环境常见）
  2. Nginx/Apache combined 格式（传统 Web 服务器最常见）
  3. RFC 3164 Syslog 格式（系统日志，内嵌 web 日志时递归解析）

关键设计决策（面试可讲）：

  Q: "为什么要做多格式解析？"
  A: "真实企业的日志来源多样——Nginx/Apache 的 combined 格式是最传统的，
     但现代云原生部署普遍用 JSON 格式的 access log，系统级日志走 syslog。
     我的解析器支持自动检测格式，对调用方完全透明。这也是为什么我把
     parser 和 engine 解耦——engine 只认统一的字段字典，不管底层日志长什么样。"

  Q: "为什么要把日志拆成字段而不是整行匹配？"
  A: "整行正则会导致误报。正常 URL /article?id=5 里的数字可能被误判为
     SQL 注入。拆成字段后，SQL 注入规则只在 query 参数上跑，不会干扰路径。"

  Q: "为什么要做 URL 解码？"
  A: "攻击者常用 URL 编码绕过检测，比如把 <script> 编码成 %3Cscript%3E。
     解码后再匹配规则，可以防止这种基础绕过。这是 WAF 的标准预处理步骤。"
"""

import re
import json
from urllib.parse import urlparse, unquote
import logging

logger = logging.getLogger(__name__)
logger = logging.getLogger(__name__)

# ============================================================
# Nginx/Apache Combined 格式的正则
# ============================================================
# 第一步：拆出 IP、请求部分、状态码
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                         # IP 地址
    r'\s+\S+\s+\S+'                         # 两个 dash（ident/auth）
    r'\s+\[(?P<timestamp>[^\]]+)\]'          # 时间戳
    r'\s+"(?P<request>[^"]+)"'               # 整个请求部分（双引号内所有内容）
    r'\s+(?P<status>\d{3})'                  # 状态码
    r'\s+(?P<size>\S+)?'                     # 响应大小（可选）
)

# 第二步：从请求部分拆出 方法、完整URI、HTTP版本
REQUEST_PATTERN = re.compile(
    r'^(?P<method>\S+)'                      # 方法（GET/POST/PUT等）
    r'\s+'                                    # 空格
    r'(?P<full_uri>.+?)'                     # 完整URI
    r'\s+HTTP/\d\.\d$'                       # HTTP版本号（行尾）
)

# ============================================================
# RFC 3164 Syslog 格式的正则
# ============================================================
# 格式: "Apr  5 08:10:11 webserver nginx: <message>"
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # 时间戳
    r'\s+(?P<hostname>\S+)'                  # 主机名
    r'\s+(?P<program>[^\[:]+?):'             # 程序名（到冒号为止）
    r'\s*(?P<message>.*)$'                   # 消息部分
)


# ============================================================
# 统一入口：自动检测格式 → 调用对应 parser
# ============================================================
def parse_log_line(line):
    """
    将单行日志解析为结构化字段字典（自动检测格式）。

    检测顺序：JSON → Nginx combined → Syslog → 降级
    返回 dict，至少包含：ip, method, uri, query, status, raw, parse_error
    """
    line = line.strip()

    if not line:
        return _fallback_result(line, "空行")

    # 1. JSON 格式（以 { 开头，最明确的特征）
    if line.startswith('{'):
        result = _parse_json_log(line)
        if not result.get('parse_error'):
            return result

    # 2. Nginx/Apache Combined 格式
    result = _parse_nginx_combined(line)
    if not result.get('parse_error'):
        return result

    # 3. Syslog 格式（内嵌的 web 日志会递归解析）
    result = _parse_syslog(line)
    if not result.get('parse_error'):
        return result

    # 4. 全部失败 → 降级
    return _fallback_result(line, "所有格式均不匹配")


# ============================================================
# 格式 1: Nginx/Apache Combined（P0 原有逻辑）
# ============================================================
def _parse_nginx_combined(line):
    """
    解析 Nginx/Apache combined 格式日志。

    示例：
        192.168.1.13 - - [05/Apr/2026:08:10:11] "GET /index.php?id=1 HTTP/1.1" 200 1024
    """
    match = LOG_PATTERN.match(line)
    if not match:
        return _fallback_result(line, "Nginx combined 格式不匹配")

    request_part = match.group('request')

    # 从请求部分拆出方法和完整URI
    req_match = REQUEST_PATTERN.match(request_part)
    if not req_match:
        method = ''
        full_uri = request_part
    else:
        method = req_match.group('method')
        full_uri = req_match.group('full_uri')

    # urlparse 拆路径和 query string，做 URL 解码
    try:
        parsed_uri = urlparse(full_uri)
        path = parsed_uri.path
        raw_query = parsed_uri.query
        decoded_query = unquote(raw_query) if raw_query else ""
    except Exception as e:
        logger.warning(f"URI 解析失败: {full_uri}, 错误: {e}")
        path = full_uri
        decoded_query = ""

    return {
        'ip': match.group('ip'),
        'method': method,
        'uri': path,
        'query': decoded_query,
        'status': match.group('status'),
        'timestamp': match.group('timestamp'),
        'size': match.group('size') or '',
        'raw': line,
        'parse_error': False
    }


# ============================================================
# 格式 2: JSON Access Log（Nginx json_combined）
# ============================================================
def _parse_json_log(line):
    """
    解析 JSON 格式的 access log。

    示例：
        {"remote_addr":"192.168.1.13","request_method":"GET","request_uri":"/index.php?id=1","status":200}

    字段映射（兼容多种常见 key 命名）：
        remote_addr / client_ip / ip        → ip
        request_method / method             → method
        request_uri / uri / url             → uri (path) + query
        status / status_code                → status
        time_local / timestamp / @timestamp → timestamp
        body_bytes_sent / bytes / size      → size
    """
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return _fallback_result(line, "JSON 解析失败")

    if not isinstance(data, dict):
        return _fallback_result(line, "JSON 顶层不是对象")

    # 提取 IP（兼容多种字段名）
    ip = (data.get('remote_addr')
          or data.get('client_ip')
          or data.get('ip')
          or '未知IP')

    # 提取方法
    method = (data.get('request_method')
              or data.get('method')
              or '')

    # 提取 URI 并拆分 path + query
    full_uri = (data.get('request_uri')
                or data.get('uri')
                or data.get('url')
                or '')

    try:
        parsed_uri = urlparse(full_uri)
        path = parsed_uri.path
        raw_query = parsed_uri.query
        decoded_query = unquote(raw_query) if raw_query else ""
    except Exception as e:
        logger.warning(f"JSON URI 解析失败: {full_uri}, 错误: {e}")
        path = full_uri
        decoded_query = ""

    # 提取状态码（可能是 int 或 str）
    status = data.get('status') or data.get('status_code') or ''
    status = str(status)

    # 提取时间戳
    timestamp = (data.get('time_local')
                 or data.get('timestamp')
                 or data.get('@timestamp')
                 or '')

    # 提取响应大小
    size = data.get('body_bytes_sent') or data.get('bytes') or data.get('size') or ''
    size = str(size)

    return {
        'ip': str(ip),
        'method': str(method),
        'uri': path,
        'query': decoded_query,
        'status': status,
        'timestamp': str(timestamp),
        'size': size,
        'raw': line,
        'parse_error': False
    }


# ============================================================
# 格式 3: RFC 3164 Syslog
# ============================================================
def _parse_syslog(line):
    """
    解析 RFC 3164 Syslog 格式日志。

    示例：
        Apr  5 08:10:11 webserver nginx: 192.168.1.13 - - [05/Apr/2026:08:10:11] "GET /..." 200 1024

    策略：提取 syslog 头部信息，然后对 message 部分递归调用 parse_log_line()。
    这样如果 message 是 Nginx combined 或 JSON 格式，就能正确解析；
    如果 message 是纯文本，则返回 fallback。
    """
    match = SYSLOG_PATTERN.match(line)
    if not match:
        return _fallback_result(line, "Syslog 格式不匹配")

    message = match.group('message').strip()

    if not message:
        return _fallback_result(line, "Syslog 消息部分为空")

    # 递归解析消息部分（不再 strip，因为已经 strip 过了）
    inner_result = parse_log_line(message)

    # 如果内部解析成功，补充 syslog 头部信息
    if not inner_result.get('parse_error'):
        # 如果内部没有时间戳，用 syslog 的时间戳
        if not inner_result.get('timestamp'):
            inner_result['timestamp'] = match.group('timestamp')
        return inner_result

    # 内部解析也失败了，返回降级结果
    return _fallback_result(line, "Syslog 消息部分无法解析为 web 日志")


# ============================================================
# 降级返回（所有格式共用）
# ============================================================
def _fallback_result(line, reason):
    """解析失败时的降级返回，保证调用方拿到的字典结构一致。"""
    logger.debug(f"日志解析降级: {reason}, 原始行: {line[:100]}")
    return {
        'ip': '未知IP',
        'method': '',
        'uri': '',
        'query': '',
        'status': '',
        'timestamp': '',
        'size': '',
        'raw': line,
        'parse_error': True
    }

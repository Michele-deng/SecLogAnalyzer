"""
日志解析器（Parser）

功能：将单行原始日志解析为结构化字段字典。
职责：
  - 用正则拆解 Nginx/Apache 联合日志格式，提取 ip/uri/query/status
  - 对 URI 中的 query string 做 URL 解码（%3C -> <）
  - 解析失败时返回带 parse_error 标记的降级字典，保证不崩溃

关键设计决策（面试可讲）：

  Q: "为什么要做 URL 解码？"
  A: "攻击者常用 URL 编码绕过检测，比如把 <script> 编码成 %3Cscript%3E。
     解码后再匹配规则，可以防止这种基础绕过。这是 WAF 的标准预处理步骤。"

  Q: "为什么要把日志拆成字段而不是整行匹配？"
  A: "整行正则会导致误报。正常 URL /article?id=5 里的数字可能被误判为
     SQL 注入。拆成字段后，SQL 注入规则只在 query 参数上跑，不会干扰路径。"

  Q: "怎么处理包含空格的攻击 payload？"
  A: "真实的 web 日志中，URI 里的空格会被编码成 %20。但我们测试数据中
     攻击 payload 包含未编码空格（如 UNION SELECT）。解决方案是：先用正则
     提取整行的请求部分（从方法到 HTTP版本），再从请求部分的头尾分别提取
     方法和 URI，把中间所有内容都当作 URI/query（含空格）。"
"""

import re
from urllib.parse import urlparse, unquote
import logging

logger = logging.getLogger(__name__)

# 分两步的正则：
# 第一步：拆出 IP、请求部分、状态码
# 请求部分 = "GET /index.php?id=1' UNION SELECT 1,2,3-- HTTP/1.1"
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)'                         # IP 地址
    r'\s+\S+\s+\S+'                         # 两个 dash（ident/auth）
    r'\s+\[(?P<timestamp>[^\]]+)\]'          # 时间戳
    r'\s+"(?P<request>[^"]+)"'               # 整个请求部分（双引号内所有内容）
    r'\s+(?P<status>\d{3})'                  # 状态码
    r'\s+(?P<size>\S+)?'                     # 响应大小（可选）
)

# 第二步：从请求部分拆出 方法、完整URI、HTTP版本
# 完整URI = 方法后面、HTTP版本前面的所有内容（可能含空格，如攻击payload）
REQUEST_PATTERN = re.compile(
    r'^(?P<method>\S+)'                      # 方法（GET/POST/PUT等）
    r'\s+'                                    # 空格
    r'(?P<full_uri>.+?)'                     # 完整URI（贪婪匹配到末尾）
    r'\s+HTTP/\d\.\d$'                       # HTTP版本号（行尾）
)


def parse_log_line(line):
    """
    将单行日志解析为结构化字段字典。

    返回 dict，至少包含：
        ip, method, uri, query, status, raw, parse_error
    """
    line = line.strip()

    if not line:
        return _fallback_result(line, "空行")

    # 第一步：拆出 IP、请求部分、状态码
    match = LOG_PATTERN.match(line)
    if not match:
        return _fallback_result(line, "格式不匹配")

    request_part = match.group('request')

    # 第二步：从请求部分拆出方法和完整URI
    req_match = REQUEST_PATTERN.match(request_part)
    if not req_match:
        # 降级：把整个请求部分当 URI
        method = ''
        full_uri = request_part
    else:
        method = req_match.group('method')
        full_uri = req_match.group('full_uri')

    # 第三步：用 urlparse 拆路径和 query string
    try:
        parsed_uri = urlparse(full_uri)
        path = parsed_uri.path
        raw_query = parsed_uri.query

        # URL 解码：把 %3C 转成 <，%27 转成 ' 等
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

"""
parser 模块单元测试

覆盖：Nginx combined / JSON / Syslog 三种格式的正常解析和攻击检测，
     空行和垃圾输入的降级逻辑，URL 解码，字段映射，递归解析。
"""

import json
import pytest
from logs_audit.parser import parse_log_line


# ============================================================
# Nginx Combined 格式
# ============================================================

class TestNginxCombined:
    def test_parse_nginx_combined_normal(self):
        line = '192.168.1.10 - - [05/Apr/2026:08:00:01] "GET /index.html HTTP/1.1" 200 1024'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert r['ip'] == '192.168.1.10'
        assert r['method'] == 'GET'
        assert r['uri'] == '/index.html'
        assert r['status'] == '200'

    def test_parse_nginx_combined_sqli(self):
        line = '''192.168.1.13 - - [05/Apr/2026:08:10:11] "GET /index.php?id=1' UNION SELECT 1,2,3-- HTTP/1.1" 200 1024'''
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert 'UNION SELECT' in r['query']

    def test_parse_nginx_combined_xss(self):
        line = '192.168.1.14 - - [05/Apr/2026:08:15:01] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert '<script>' in r['query']

    def test_parse_nginx_url_decoding(self):
        line = '10.0.0.1 - - [05/Apr/2026:08:00:00] "GET /search?q=%3Cscript%3E HTTP/1.1" 200 100'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert '<script>' in r['query']


# ============================================================
# JSON Access Log 格式
# ============================================================

class TestJsonLog:
    def test_parse_json_normal(self):
        data = {"remote_addr": "192.168.1.10", "request_method": "GET", "request_uri": "/index.html", "status": 200}
        r = parse_log_line(json.dumps(data))
        assert r['parse_error'] is False
        assert r['ip'] == '192.168.1.10'
        assert r['uri'] == '/index.html'
        assert r['status'] == '200'

    def test_parse_json_sqli(self):
        data = {"remote_addr": "10.0.0.1", "request_method": "GET", "request_uri": "/index.php?id=1' UNION SELECT 1--", "status": 200}
        r = parse_log_line(json.dumps(data))
        assert r['parse_error'] is False
        assert 'UNION SELECT' in r['query']

    def test_parse_json_traversal(self):
        data = {"remote_addr": "10.0.0.2", "request_method": "GET", "request_uri": "/download?file=../../../etc/passwd", "status": 200}
        r = parse_log_line(json.dumps(data))
        assert r['parse_error'] is False
        assert '../../../etc/passwd' in r['query']

    def test_parse_json_url_decoding(self):
        data = {"remote_addr": "10.0.0.1", "request_method": "GET", "request_uri": "/search?q=%3Cscript%3E", "status": 200}
        r = parse_log_line(json.dumps(data))
        assert r['parse_error'] is False
        assert '<script>' in r['query']

    def test_parse_json_field_mapping(self):
        data = {"client_ip": "10.0.0.5", "method": "POST", "uri": "/api/data", "status_code": 201}
        r = parse_log_line(json.dumps(data))
        assert r['parse_error'] is False
        assert r['ip'] == '10.0.0.5'
        assert r['method'] == 'POST'
        assert r['uri'] == '/api/data'
        assert r['status'] == '201'


# ============================================================
# Syslog (RFC 3164) 格式
# ============================================================

class TestSyslog:
    def test_parse_syslog_normal(self):
        line = 'Apr  5 08:00:01 webserver nginx: 192.168.1.10 - - [05/Apr/2026:08:00:01] "GET /index.html HTTP/1.1" 200 1024'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert r['ip'] == '192.168.1.10'
        assert r['uri'] == '/index.html'

    def test_parse_syslog_cmdi(self):
        line = 'Apr  5 08:25:01 webserver nginx: 192.168.1.16 - - [05/Apr/2026:08:25:01] "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 1024'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert ';cat' in r['query'] or 'cat' in r['query']

    def test_parse_syslog_recursive(self):
        """Syslog 内嵌 JSON 格式的递归解析"""
        inner = json.dumps({"remote_addr": "10.0.0.1", "request_method": "GET", "request_uri": "/test", "status": 200})
        line = f'Apr  5 08:00:01 webserver app: {inner}'
        r = parse_log_line(line)
        assert r['parse_error'] is False
        assert r['ip'] == '10.0.0.1'
        assert r['uri'] == '/test'


# ============================================================
# 降级逻辑
# ============================================================

class TestFallback:
    def test_parse_empty_line(self):
        r = parse_log_line('')
        assert r['parse_error'] is True

    def test_parse_garbage(self):
        r = parse_log_line('this is just random text with no structure')
        assert r['parse_error'] is True

    def test_fallback_consistency(self):
        """fallback 结果的 dict 结构必须包含所有标准字段"""
        r = parse_log_line('')
        required_keys = {'ip', 'method', 'uri', 'query', 'status', 'timestamp', 'size', 'raw', 'parse_error'}
        assert required_keys.issubset(r.keys())
        assert r['parse_error'] is True

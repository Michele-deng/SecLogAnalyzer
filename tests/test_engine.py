"""
engine 模块单元测试

覆盖：SQLi/XSS/路径遍历/命令注入命中，白名单抑制，字段定向匹配，
     多规则命中，parse_error 跳过。
"""

import json
import pytest
from logs_audit.parser import parse_log_line
from logs_audit.engine import match_rules


class TestSqliDetection:
    def test_sqli_union_select_hit(self, all_rules, all_whitelist):
        line = '''192.168.1.13 - - [05/Apr/2026:08:10:11] "GET /index.php?id=1' UNION SELECT 1,2,3-- HTTP/1.1" 200 1024'''
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        assert any('sqli' in rid for rid in rule_ids)

    def test_sqli_normal_no_hit(self, all_rules, all_whitelist):
        line = '192.168.1.10 - - [05/Apr/2026:08:00:01] "GET /index.html HTTP/1.1" 200 1024'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        assert len(hits) == 0


class TestXssDetection:
    def test_xss_script_hit(self, all_rules, all_whitelist):
        line = '192.168.1.14 - - [05/Apr/2026:08:15:01] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        assert any('xss' in rid for rid in rule_ids)


class TestTraversalDetection:
    def test_traversal_dotdot_hit(self, all_rules, all_whitelist):
        line = '192.168.1.15 - - [05/Apr/2026:08:20:01] "GET /download?file=../../../etc/passwd HTTP/1.1" 200 1024'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        assert any('path_traversal' in rid for rid in rule_ids)


class TestCmdiDetection:
    def test_cmdi_shell_operator_hit(self, all_rules, all_whitelist):
        line = '192.168.1.16 - - [05/Apr/2026:08:25:01] "GET /ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 1024'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        assert any('cmdi' in rid for rid in rule_ids)


class TestWhitelist:
    def test_whitelist_admin_suppress(self, all_rules, all_whitelist):
        """访问 /admin/ 返回 403 应该抑制 OR 绕过类规则"""
        line = '192.168.1.1 - - [05/Apr/2026:08:00:00] "GET /admin/ HTTP/1.1" 403 1024'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        # 不应该有 sqli_or_bypass / sqli_comment_trail / sqli_tautology 命中
        suppressed_ids = {'sqli_or_bypass', 'sqli_comment_trail', 'sqli_tautology'}
        hit_ids = {h['rule_id'] for h in hits}
        assert not suppressed_ids.intersection(hit_ids)

    def test_whitelist_no_match_no_suppress(self, all_rules, all_whitelist):
        """非 /admin/ 路径 + 403 不应该触发白名单抑制"""
        line = '''192.168.1.1 - - [05/Apr/2026:08:00:00] "GET /other?id=1' OR 1=1-- HTTP/1.1" 403 1024'''
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        assert 'sqli_or_bypass' in rule_ids


class TestEngineBehavior:
    def test_field_targeted_matching(self, all_rules, all_whitelist):
        """SQL 注入规则应该只在 query/uri 上匹配，不在 ip 上匹配"""
        line = '192.168.1.1 - - [05/Apr/2026:08:00:00] "GET /page HTTP/1.1" 200 1024'
        parsed = parse_log_line(line)
        # 手动注入一个含有 SQL 关键词的 IP
        parsed['ip'] = 'UNION SELECT 1'
        hits = match_rules(parsed, all_rules, all_whitelist)
        # 不应该有 SQLi 命中（因为 sqli 规则的 target_fields 不含 ip）
        sqli_hits = [h for h in hits if h['rule_id'].startswith('sqli_')]
        assert len(sqli_hits) == 0

    def test_multiple_hits_one_line(self, all_rules, all_whitelist):
        """一行日志可以同时命中多条规则"""
        line = '192.168.1.1 - - [05/Apr/2026:08:00:00] "GET /search?q=<script>alert(1)</script> UNION SELECT 1-- HTTP/1.1" 200 100'
        parsed = parse_log_line(line)
        hits = match_rules(parsed, all_rules, all_whitelist)
        rule_ids = [h['rule_id'] for h in hits]
        has_sqli = any('sqli' in rid for rid in rule_ids)
        has_xss = any('xss' in rid for rid in rule_ids)
        assert has_sqli and has_xss

    def test_parse_error_skipped(self, all_rules, all_whitelist):
        """parse_error=True 的行应该跳过规则匹配，返回空列表"""
        parsed = {
            'ip': '', 'method': '', 'uri': '', 'query': '',
            'status': '', 'timestamp': '', 'size': '',
            'raw': 'garbage', 'parse_error': True
        }
        hits = match_rules(parsed, all_rules, all_whitelist)
        assert len(hits) == 0

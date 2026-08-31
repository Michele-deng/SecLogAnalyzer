"""
loader 模块单元测试

覆盖：规则数量、白名单数量、规则结构校验。
"""

import pytest
from logs_audit.loader import load_rules, load_whitelist


class TestRuleLoading:
    def test_load_rules_count(self, all_rules):
        """应该加载 29 条检测规则（12 SQLi + 8 XSS + 5 路径遍历 + 4 命令注入）"""
        assert len(all_rules) == 29

    def test_load_whitelist_count(self, all_whitelist):
        """应该加载 2 条白名单规则"""
        assert len(all_whitelist) == 2

    def test_rule_required_fields(self, all_rules):
        """每条规则必须包含 id, name, severity, target_fields, patterns"""
        required = {'id', 'name', 'severity', 'target_fields', 'patterns'}
        for rule in all_rules:
            assert required.issubset(rule.keys()), f"规则 {rule.get('id')} 缺少必填字段"

    def test_rule_severity_valid(self, all_rules):
        """severity 必须是 critical/high/medium/low 之一"""
        valid = {'critical', 'high', 'medium', 'low'}
        for rule in all_rules:
            assert rule['severity'] in valid, f"规则 {rule['id']} severity 不合法: {rule['severity']}"

    def test_rule_patterns_not_empty(self, all_rules):
        """每条规则的 patterns 列表不能为空"""
        for rule in all_rules:
            assert len(rule['patterns']) > 0, f"规则 {rule['id']} patterns 为空"

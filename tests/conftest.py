"""
共享 pytest fixtures

提供规则加载、白名单加载等常用 fixture，避免每个测试文件重复加载。
"""

import pytest
from logs_audit.loader import load_rules, load_whitelist


@pytest.fixture(scope='session')
def all_rules():
    """加载所有检测规则（session 级别，只加载一次）"""
    return load_rules()


@pytest.fixture(scope='session')
def all_whitelist():
    """加载所有白名单规则（session 级别，只加载一次）"""
    return load_whitelist()

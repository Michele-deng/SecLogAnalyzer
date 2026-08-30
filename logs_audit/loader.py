"""
规则加载器（Loader）

功能：从 YAML 文件中加载检测规则和白名单规则。
职责：
  - 扫描 rules/ 目录下所有 *_rules.yml 文件，解析为规则列表
  - 加载 whitelist.yml，解析为白名单列表
  - 对规则做基本校验（必填字段检查）

面试要点：
  Q: "为什么要用 YAML 而不是硬编码正则？"
  A: "规则外置到 YAML 文件后，安全运营人员可以不用改代码就能调整检测规则，
     这是 WAF/SIEM 的标准做法。而且 YAML 人可读可审，适合团队协作。"
"""

import os
import yaml
import logging

logger = logging.getLogger(__name__)

# rules 目录的默认路径：与本文件(loader.py)同级的 rules/ 子目录
DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')


def load_rules(rules_dir=None):
    """
    加载所有检测规则。

    扫描 rules_dir 下所有以 _rules.yml 结尾的文件，
    解析每个文件中的 rules 列表，合并后返回。

    返回: list[dict] — 每个 dict 是一条规则，包含 id/name/severity/target_fields/patterns 等字段
    """
    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR

    all_rules = []

    # 1. 扫描目录，找出所有 *_rules.yml 文件
    if not os.path.isdir(rules_dir):
        logger.error(f"规则目录不存在: {rules_dir}")
        return all_rules

    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith('_rules.yml') or filename.endswith('_rules.yaml'):
            filepath = os.path.join(rules_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                # 2. 解析文件中的 rules 列表
                rules = data.get('rules', [])
                for rule in rules:
                    # 基本校验：必填字段
                    if _validate_rule(rule):
                        all_rules.append(rule)
                    else:
                        logger.warning(f"规则校验失败，已跳过: {rule.get('id', '未知ID')} (文件: {filename})")

                logger.info(f"从 {filename} 加载了 {len(rules)} 条规则")

            except yaml.YAMLError as e:
                logger.error(f"YAML 解析失败: {filepath}, 错误: {e}")
            except Exception as e:
                logger.error(f"读取规则文件失败: {filepath}, 错误: {e}")

    logger.info(f"规则加载完成，共 {len(all_rules)} 条有效规则")
    return all_rules


def load_whitelist(rules_dir=None):
    """
    加载白名单规则。

    从 rules_dir/whitelist.yml 中读取白名单规则列表。

    返回: list[dict] — 每个 dict 是一条白名单，包含 id/name/condition/suppress_rules 等字段
    """
    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR

    filepath = os.path.join(rules_dir, 'whitelist.yml')

    if not os.path.exists(filepath):
        logger.info("白名单文件不存在，跳过加载")
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        whitelist = data.get('rules', [])
        logger.info(f"白名单加载完成，共 {len(whitelist)} 条规则")
        return whitelist

    except Exception as e:
        logger.error(f"白名单加载失败: {e}")
        return []


def _validate_rule(rule):
    """
    校验单条规则是否包含所有必填字段。

    必填字段：id, name, severity, target_fields, patterns
    """
    required_fields = ['id', 'name', 'severity', 'target_fields', 'patterns']
    for field in required_fields:
        if field not in rule:
            logger.warning(f"规则缺少必填字段 '{field}': {rule}")
            return False

    # target_fields 必须是非空列表
    if not isinstance(rule['target_fields'], list) or len(rule['target_fields']) == 0:
        logger.warning(f"规则 target_fields 必须是非空列表: {rule.get('id')}")
        return False

    # patterns 必须是非空列表
    if not isinstance(rule['patterns'], list) or len(rule['patterns']) == 0:
        logger.warning(f"规则 patterns 必须是非空列表: {rule.get('id')}")
        return False

    # severity 必须是合法值
    valid_severities = ['critical', 'high', 'medium', 'low']
    if rule['severity'] not in valid_severities:
        logger.warning(f"规则 severity 不合法: {rule.get('severity')}, 规则: {rule.get('id')}")
        return False

    return True


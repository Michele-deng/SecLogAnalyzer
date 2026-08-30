"""
检测引擎（Engine）

功能：对已解析的日志字段运行规则库，返回命中详情。
职责：
  - 按规则指定的 target_fields 做字段定向匹配（核心误报控制手段）
  - 逐条运行正则 patterns，命中即记录
  - 应用白名单条件过滤（条件式抑制，不是全局放行）

面试要点：
  Q: "字段定向匹配怎么降低误报？"
  A: "比如正常请求 GET /article?id=5，query 是 'id=5'。如果在整行上跑
     SQL 注入正则，'5' 可能被误判为数字型注入。但我们指定 sqli 规则只在
     query 字段上跑，而 'id=5' 不含 SQL 关键词，所以不会误报。"

  Q: "白名单和规则放行有什么区别？"
  A: "白名单是条件式抑制——只有当多个条件同时满足时，才抑制指定的规则。
     不是全局放行，其他规则照常运行。比如管理路径探测(/admin/ 403)只
     抑制 OR 绕过类规则，不影响 UNION SELECT 检测。"
"""

import re
import logging

logger = logging.getLogger(__name__)

# 严重等级排序，用于在多条规则命中时取最高等级
SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def match_rules(parsed, rules, whitelist):
    """
    对一条已解析的日志运行所有规则，返回命中详情列表。

    参数:
        parsed (dict): parser.parse_log_line() 返回的结构化字典
        rules (list[dict]): loader.load_rules() 返回的规则列表
        whitelist (list[dict]): loader.load_whitelist() 返回的白名单列表

    返回:
        list[dict]: 每条命中包含:
            - rule_id: 规则 ID
            - rule_name: 规则名称
            - severity: 严重等级
            - mitre_tags: ATT&CK 技术标签列表
            - field: 命中的字段名
            - matched_text: 匹配到的文本片段
    """
    # 如果日志解析失败，跳过规则匹配
    if parsed.get('parse_error'):
        return []

    hits = []

    # ---- 第一步：字段定向规则匹配 ----
    for rule in rules:
        # 只在规则指定的字段上运行匹配
        target_fields = rule.get('target_fields', [])
        patterns = rule.get('patterns', [])
        case_insensitive = rule.get('case_insensitive', False)
        flags = re.IGNORECASE if case_insensitive else 0

        # 遍历目标字段
        for field in target_fields:
            target_value = parsed.get(field, '')
            if not target_value:
                continue

            # 遍历该规则的所有正则模式（任一命中即算命中）
            for pattern_str in patterns:
                try:
                    if re.search(pattern_str, target_value, flags):
                        hits.append({
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'severity': rule['severity'],
                            'mitre_tags': rule.get('mitre_tags', []),
                            'field': field,
                            'matched_text': target_value
                        })
                        # 一条规则在一个字段上命中一次即可，跳出 patterns 循环
                        break
                except re.error as e:
                    logger.error(f"正则编译失败: {pattern_str}, 规则: {rule['id']}, 错误: {e}")

    if not hits:
        return []

    # ---- 第二步：白名单过滤 ----
    if not whitelist:
        return hits

    filtered = []
    for hit in hits:
        suppressed = False
        for wl in whitelist:
            suppress_ids = wl.get('suppress_rules', [])
            # 只有当这条规则在白名单的抑制列表中时，才检查白名单条件
            if hit['rule_id'] in suppress_ids:
                if _check_whitelist_condition(parsed, wl.get('condition', {})):
                    logger.debug(
                        f"白名单抑制: 规则 {hit['rule_id']} 被白名单 {wl['id']} 抑制"
                    )
                    suppressed = True
                    break

        if not suppressed:
            filtered.append(hit)

    return filtered


def _check_whitelist_condition(parsed, condition):
    """
    检查白名单条件是否满足。

    支持的条件结构:
        all_of:
          - field: "uri"
            pattern: "^/admin/"
          - field: "status"
            pattern: "^403$"

    只有 all_of 中的所有子条件都满足时，才返回 True。
    """
    all_of = condition.get('all_of', [])

    if not all_of:
        return False

    for sub_condition in all_of:
        field = sub_condition.get('field', '')
        pattern = sub_condition.get('pattern', '')

        target_value = parsed.get(field, '')

        try:
            if not re.search(pattern, target_value):
                # 任一子条件不满足，整体不满足
                return False
        except re.error as e:
            logger.error(f"白名单正则编译失败: {pattern}, 错误: {e}")
            return False

    # 所有子条件都满足
    return True


def get_max_severity(hits):
    """
    从多条命中中取最高严重等级。

    用于在 attack_details 中记录这一行的总体严重等级。
    """
    if not hits:
        return 'low'
    return max(hits, key=lambda h: SEVERITY_ORDER.get(h['severity'], 0))['severity']


def collect_mitre_tags(hits):
    """
    从多条命中中收集所有 ATT&CK 标签（去重）。
    """
    tags = set()
    for hit in hits:
        tags.update(hit.get('mitre_tags', []))
    return list(tags)


def collect_rule_ids(hits):
    """
    从多条命中中收集所有命中的规则 ID。
    """
    return [hit['rule_id'] for hit in hits]


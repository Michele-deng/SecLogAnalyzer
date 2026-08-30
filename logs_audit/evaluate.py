"""
评测脚本（Evaluator）

功能：对比检测引擎输出与人工标注 ground truth，计算精确率/召回率/F1。
用法：python -m logs_audit.evaluate

面试要点：
  Q: "精确率和召回率怎么算？"
  A: "精确率 = TP / (TP + FP)，即'引擎报出来的攻击里有多少是真的'；
     召回率 = TP / (TP + FN)，即'真正的攻击里引擎抓到了多少'。
     F1 是两者的调和平均，用于衡量综合表现。"
"""

import os
import sys
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# 把项目根目录加入 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from logs_audit.loader import load_rules, load_whitelist
from logs_audit.parser import parse_log_line
from logs_audit.engine import match_rules

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')
TEST_LOG_FILE = os.path.join(PROJECT_ROOT, 'test_log2.log')
GROUND_TRUTH_FILE = os.path.join(TEST_DATA_DIR, 'test_log2_ground_truth.json')


def run_evaluation():
    """
    主评测流程：加载规则 -> 逐行检测 -> 对比标注 -> 输出报告。
    """
    # 1. 加载规则
    print("=" * 60)
    print("  SecLogAnalyzer 检测引擎评测报告")
    print("=" * 60)

    rules = load_rules()
    whitelist = load_whitelist()
    print(f"\nLoaded {len(rules)} detection rules, {len(whitelist)} whitelist rules")

    # 2. 读取测试日志
    if not os.path.exists(TEST_LOG_FILE):
        print(f"[ERROR] Test log not found: {TEST_LOG_FILE}")
        return None

    with open(TEST_LOG_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print(f"Test log: {os.path.basename(TEST_LOG_FILE)} ({len(lines)} lines)")

    # 3. 读取 ground truth
    if not os.path.exists(GROUND_TRUTH_FILE):
        print(f"[ERROR] Ground truth not found: {GROUND_TRUTH_FILE}")
        return None

    with open(GROUND_TRUTH_FILE, 'r', encoding='utf-8') as f:
        ground_truth = json.load(f)

    labels = ground_truth['labels']
    print(f"Ground truth: {len(labels)} annotations")

    # 4. 逐行运行检测
    predictions = []
    for i, line in enumerate(lines):
        line_num = i + 1
        parsed = parse_log_line(line)
        hits = match_rules(parsed, rules, whitelist)

        is_attack = len(hits) > 0
        attack_type = None
        if is_attack:
            rule_ids = [h['rule_id'] for h in hits]
            has_sqli = any(rid.startswith('sqli_') for rid in rule_ids)
            has_xss = any(rid.startswith('xss_') for rid in rule_ids)
            if has_sqli and has_xss:
                attack_type = 'mixed'
            elif has_sqli:
                attack_type = 'sqli'
            elif has_xss:
                attack_type = 'xss'

        predictions.append({
            'line': line_num,
            'predicted': is_attack,
            'type': attack_type,
            'hits': [{'rule_id': h['rule_id'], 'severity': h['severity']} for h in hits]
        })

    # 5. 对比计算混淆矩阵
    tp = fp = fn = tn = 0
    fp_lines = []
    fn_lines = []

    for label in labels:
        line_idx = label['line'] - 1
        if line_idx >= len(predictions):
            continue

        pred = predictions[line_idx]
        expected = label['expected']
        predicted = pred['predicted']

        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
            fp_lines.append(label['line'])
        elif not predicted and expected:
            fn += 1
            fn_lines.append(label['line'])
        else:
            tn += 1

    # 计算指标
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0

    # 6. 输出报告
    print("\n" + "-" * 60)
    print("  Confusion Matrix")
    print("-" * 60)
    print(f"  TP (correct detection):  {tp}")
    print(f"  FP (false alarm):        {fp}")
    print(f"  FN (missed attack):      {fn}")
    print(f"  TN (correct benign):     {tn}")

    print("\n" + "-" * 60)
    print("  Key Metrics")
    print("-" * 60)
    print(f"  Precision:  {precision:.4f}  ({precision*100:.1f}%)")
    print(f"  Recall:     {recall:.4f}  ({recall*100:.1f}%)")
    print(f"  F1 Score:   {f1:.4f}  ({f1*100:.1f}%)")
    print(f"  Accuracy:   {accuracy:.4f}  ({accuracy*100:.1f}%)")

    if fp_lines:
        print(f"\n  [!] False positive lines: {fp_lines}")
    if fn_lines:
        print(f"  [!] Missed attack lines: {fn_lines}")
    if not fp_lines and not fn_lines:
        print(f"\n  [OK] Zero false positives, zero missed attacks!")

    # 按规则统计
    rule_stats = {}
    for pred in predictions:
        for hit in pred['hits']:
            rid = hit['rule_id']
            if rid not in rule_stats:
                rule_stats[rid] = {'count': 0, 'severity': hit['severity']}
            rule_stats[rid]['count'] += 1

    if rule_stats:
        print("\n" + "-" * 60)
        print("  Rule Hit Statistics")
        print("-" * 60)
        for rid, stats in sorted(rule_stats.items(), key=lambda x: -x[1]['count']):
            icon = {'critical': '[C]', 'high': '[H]', 'medium': '[M]', 'low': '[L]'}.get(stats['severity'], '[?]')
            print(f"  {icon} {rid}: {stats['count']} hits ({stats['severity']})")

    print("\n" + "=" * 60)

    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'accuracy': accuracy,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'fp_lines': fp_lines,
        'fn_lines': fn_lines,
        'rule_stats': rule_stats
    }


if __name__ == '__main__':
    result = run_evaluation()
    if result:
        report_path = os.path.join(TEST_DATA_DIR, 'evaluation_report.json')
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"\nReport exported: {report_path}")
        except Exception as e:
            print(f"\nReport export failed: {e}")


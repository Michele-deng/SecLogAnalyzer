"""
评测脚本（Evaluator）

功能：对比检测引擎输出与人工标注 ground truth，计算精确率/召回率/F1。
支持多文件自动发现与评测。

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
import glob
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


def find_test_pairs():
    """
    自动发现所有测试文件对（test_log*.log + 对应的 *_ground_truth.json）。

    搜索顺序：
      1. test_data/ 目录下的 test_log*.log
      2. 项目根目录下的 test_log*.log（兼容 P0 的 test_log2.log）
    """
    pairs = []

    # 搜索 test_data/ 目录
    for log_path in sorted(glob.glob(os.path.join(TEST_DATA_DIR, 'test_log*.log'))):
        basename = os.path.basename(log_path).replace('.log', '')
        gt_path = os.path.join(TEST_DATA_DIR, f'{basename}_ground_truth.json')
        if os.path.exists(gt_path):
            pairs.append((log_path, gt_path, basename))

    # 搜索项目根目录（兼容 P0）
    for log_path in sorted(glob.glob(os.path.join(PROJECT_ROOT, 'test_log*.log'))):
        basename = os.path.basename(log_path).replace('.log', '')
        gt_path = os.path.join(TEST_DATA_DIR, f'{basename}_ground_truth.json')
        if os.path.exists(gt_path) and (log_path, gt_path, basename) not in pairs:
            pairs.append((log_path, gt_path, basename))

    return pairs


def evaluate_single(log_path, gt_path, label):
    """
    对单个测试文件运行评测，返回指标字典。
    """
    rules = load_rules()
    whitelist = load_whitelist()

    # 读取测试日志
    if not os.path.exists(log_path):
        print(f"  [ERROR] Test log not found: {log_path}")
        return None

    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 读取 ground truth
    if not os.path.exists(gt_path):
        print(f"  [ERROR] Ground truth not found: {gt_path}")
        return None

    with open(gt_path, 'r', encoding='utf-8') as f:
        ground_truth = json.load(f)

    labels = ground_truth['labels']
    fmt = ground_truth.get('format', 'unknown')

    # 逐行运行检测
    predictions = []
    for i, line in enumerate(lines):
        line_num = i + 1
        parsed = parse_log_line(line)
        hits = match_rules(parsed, rules, whitelist)

        is_attack = len(hits) > 0
        predictions.append({
            'line': line_num,
            'predicted': is_attack,
            'hits': [{'rule_id': h['rule_id'], 'severity': h['severity']} for h in hits]
        })

    # 对比计算混淆矩阵
    tp = fp = fn = tn = 0
    fp_lines = []
    fn_lines = []

    for label_entry in labels:
        line_idx = label_entry['line'] - 1
        if line_idx >= len(predictions):
            continue

        pred = predictions[line_idx]
        expected = label_entry['expected']
        predicted = pred['predicted']

        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
            fp_lines.append(label_entry['line'])
        elif not predicted and expected:
            fn += 1
            fn_lines.append(label_entry['line'])
        else:
            tn += 1

    # 计算指标
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0

    return {
        'label': label,
        'format': fmt,
        'lines': len(lines),
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'accuracy': accuracy,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'fp_lines': fp_lines,
        'fn_lines': fn_lines,
    }


def run_evaluation():
    """
    主评测流程：自动发现所有测试文件 -> 逐个评测 -> 汇总输出。
    """
    # 1. 加载规则（只需加载一次）
    print("=" * 60)
    print("  SecLogAnalyzer 检测引擎评测报告（多格式）")
    print("=" * 60)

    rules = load_rules()
    whitelist = load_whitelist()
    print(f"\nLoaded {len(rules)} detection rules, {len(whitelist)} whitelist rules")

    # 2. 发现测试文件对
    pairs = find_test_pairs()
    if not pairs:
        print("[ERROR] No test file pairs found in test_data/ or project root")
        return None

    print(f"\nFound {len(pairs)} test file(s)\n")

    # 3. 逐个评测
    all_results = []
    total_tp = total_fp = total_fn = total_tn = 0

    for log_path, gt_path, label in pairs:
        print("-" * 60)
        result = evaluate_single(log_path, gt_path, label)
        if result is None:
            continue

        all_results.append(result)
        total_tp += result['tp']
        total_fp += result['fp']
        total_fn += result['fn']
        total_tn += result['tn']

        status = "[OK]" if result['fp'] == 0 and result['fn'] == 0 else "[WARN]"
        print(f"  {status} {label} ({result['format']}, {result['lines']} lines)")
        print(f"       P={result['precision']:.4f}  R={result['recall']:.4f}  F1={result['f1']:.4f}")
        print(f"       TP={result['tp']}  FP={result['fp']}  FN={result['fn']}  TN={result['tn']}")
        if result['fp_lines']:
            print(f"       [!] FP lines: {result['fp_lines']}")
        if result['fn_lines']:
            print(f"       [!] FN lines: {result['fn_lines']}")
        print()

    # 4. 汇总
    if all_results:
        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0

        print("=" * 60)
        print("  Overall Summary")
        print("=" * 60)
        print(f"  Files tested:     {len(all_results)}")
        print(f"  Total TP/FP/FN:   {total_tp}/{total_fp}/{total_fn}")
        print(f"  Precision:  {overall_precision:.4f}  ({overall_precision*100:.1f}%)")
        print(f"  Recall:     {overall_recall:.4f}  ({overall_recall*100:.1f}%)")
        print(f"  F1 Score:   {overall_f1:.4f}  ({overall_f1*100:.1f}%)")
        if total_fp == 0 and total_fn == 0:
            print(f"\n  [OK] All files: zero false positives, zero missed attacks!")

    print("\n" + "=" * 60)

    return {
        'files': all_results,
        'overall': {
            'precision': overall_precision if all_results else 0,
            'recall': overall_recall if all_results else 0,
            'f1': overall_f1 if all_results else 0,
            'tp': total_tp, 'fp': total_fp, 'fn': total_fn, 'tn': total_tn,
        }
    }


if __name__ == '__main__':
    result = run_evaluation()
    if result:
        report_path = os.path.join(TEST_DATA_DIR, 'evaluation_report.json')
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"Report exported: {report_path}")
        except Exception as e:
            print(f"Report export failed: {e}")


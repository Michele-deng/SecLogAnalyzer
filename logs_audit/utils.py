import re  # Python 的正则表达式标准库，用于抓取特定的攻击字符（如 select, <script>）
import os  # 系统路径工具，用于检查物理文件是否存在
import time  # 时间工具，用于统计整个分析算法执行了多少秒（计算性能指标）
import logging  # 日志记录模块，用于把程序后台报错写进系统日志里

# ThreadPoolExecutor: 线程池执行器。用于管理多线程，自动分配 4 个线程分头分析日志
from concurrent.futures import ThreadPoolExecutor

# 配置日志记录器，__name__ 变量传入当前文件名以标识日志来源
logger = logging.getLogger(__name__)


#辅助函数：单线程分块处理日志
def process_chunk(lines_chunk, start_line_no):
    """
    处理日志块的辅助函数：被线程池调用。
    每个线程只分到其中一小段日志（lines_chunk），并知道这一段是全局的第几行（start_line_no）
    """
    try:
        
        # re.compile: 提前把正则规则编译成对象，避免在循环里重复编译，大幅提升匹配速度。
        # re.IGNORECASE: 忽略大小写（比如 SELECT 和 select 都能被匹配到）
        sqli_pattern = re.compile(
            r"(select|union|insert|delete|update|drop|truncate|exec|' or '1'='1'|--|/\*|\*/)", 
            re.IGNORECASE
        )
        xss_pattern = re.compile(
            r"(<script>|alert\(|javascript:|onerror=|onload=|onmouseover=|<iframe|<img)", 
            re.IGNORECASE
        )
        # 匹配日志开头的 IP 地址（形如 192.168.1.1 的 IPv4 格式）
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}")

        # 初始化当前线程的任务看板
        chunk_details = []  # 记录当前线程发现的所有攻击详情（是个列表）
        chunk_sqli = 0     # 当前线程统计到的 SQL 注入总数
        chunk_xss = 0      # 当前线程统计到的 XSS 攻击总数

        # enumerate(): 自动生成循环索引。i 是局部行号（从0开始），line 是该行日志文本
        for i, line in enumerate(lines_chunk):
            try:
                line = line.strip()  # 去除这一行日志前后多余的空格和换行符
                if not line:         # 空行，直接跳过，不浪费计算资源
                    continue

                # 1. 提取源 IP 地址
                ip_match = ip_pattern.search(line) # 在行首搜索 IP
                # 如果匹配成功，取出匹配到的第 0 组文本（即 IP 字符串）；如果匹配失败，标记为 '未知IP'
                source_ip = ip_match.group(0) if ip_match else '未知IP'

                # 2. 安全扫描匹配
                # search() 返回 Match 对象或 None，用 bool() 强制转换为布尔值 (True 或 False)
                is_sqli = bool(sqli_pattern.search(line))
                is_xss = bool(xss_pattern.search(line))

                # 3. 如果触发了其中任何一种攻击规则，进行打包记录
                if is_sqli or is_xss:
                    attack_type = []
                    #初始化局部空列表，用于存储当前行的所有攻击类型，如 SQL 注入、XSS 攭击等
                    if is_sqli:
                        chunk_sqli += 1
                        attack_type.append("SQL注入")
                    if is_xss:
                        chunk_xss += 1
                        attack_type.append("XSS攻击")

                    # 将这一行被实锤的攻击详情打包成小字典，塞进结果列表里
                    chunk_details.append({
                        #全局行号 = 这一大块的起始行号 + 线程内的当前偏移量 i
                        'line_no': start_line_no + i,
                        'content': line,
                        #原始日志内容
                        # ", ".join: 把列表用逗号拼接成字符串。如 ["SQL", "XSS"] 变成 "SQL, XSS"
                        'type': ", ".join(attack_type), 
                        'ip': source_ip
                    })
            except Exception as e:
                # 【容错设计】哪怕某一行日志格式太怪导致处理失败，我们也绝不崩溃！
                # 记录警告日志后，continue 跳过当前行，继续分析下一行。这叫“单行级容错”
                logger.error(f"分析第 {start_line_no + i} 行时出现异常: {str(e)}")
                continue
                
        # 线程的任务完成，向主进程返回当前线程的 SQLi数量、XSS数量 和 攻击详情列表
        return chunk_sqli, chunk_xss, chunk_details
        
    except Exception as e:
        # 如果这个线程块发生了毁灭性错误，捕获并返回空数据
        logger.error(f"线程块分析 (起始行: {start_line_no}) 发生致命错误: {str(e)}")
        return 0, 0, []


# 主入口函数：多线程分析主流程
def analyze_log(file_path):
    """
    外部调用的主入口函数（多线程版）
    """
    # 如果前端传过来的文件在硬盘上根本不存在，直接退回，并返回错误字典
    if not os.path.exists(file_path):
        logger.error(f"文件未找到: {file_path}")
        return {
            'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
            'is_analyzed': False, 'attack_details': [], 'error': "文件不存在"
        }

    try:
        # 1. 尝试用正确的编码读取文件 
        lines = []
        try:
            #  utf-8 编码读取文件,使用 with open 保证自动安全关闭
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines() # 一次性将文件按行读取到 lines 列表中
        except UnicodeDecodeError:
            try:
                # 如果 utf-8 报错，则用 gbk 重新打开
                with open(file_path, 'r', encoding='gbk') as f:
                    lines = f.readlines()
            except Exception as e:
                # 两种常见编码都读失败，记录日志，并安全退回
                logger.error(f"文件编码无法识别或读取失败: {file_path}, 错误: {str(e)}")
                return {
                    'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
                    'is_analyzed': False, 'attack_details': [], 'error': "读取文件失败"
                }
        except Exception as e:
            # 捕获除编码外可能发生的企业级底层读取异常（如磁盘坏道）
            logger.error(f"读取文件时发生未知错误: {file_path}, 错误: {str(e)}")
            return {
                'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
                'is_analyzed': False, 'attack_details': [], 'error': "系统读取错误"
            }
        
        # 成功拿到所有日志行后，记录基本信息
        total_lines = len(lines)
        attack_details = []
        sqli_count = 0
        xss_count = 0

        # 开始性能计时（秒级浮点数，用于测算多线程处理效率）
        start_time = time.time()

        # 2. 多线程任务切分与分发
        num_threads = 4 # 声明我们要开启 4 个工作线程
        if total_lines > 0:
            # 计算每个线程分到多少行。// 是整除。max(1, ...) 保证最少分 1 行，防止除零错误
            chunk_size = max(1, total_lines // num_threads)
            
            # 使用 with 初始化线程池。ThreadPoolExecutor 会在退出 with 作用域时自动销毁和关闭线程
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [] # 用于保存每一个线程执行任务的“期约（Future）”对象
                
                
                # range(start, stop, step): 每次按 step 步长（即一个分块大小）往前跳
                for i in range(0, total_lines, chunk_size):
                    chunk = lines[i : i + chunk_size] # 切出这一小块日志行
                    # submit(): 异步提交任务给线程池。
                    #  函数指针 process_chunk； 任务块 chunk；全局的起始行号 i + 1
                    futures.append(executor.submit(process_chunk, chunk, i + 1))
                
                #  3. 汇总合并各个线程的成果 
                for future in futures:
                    try:
                        # .result()等待这个线程彻底执行完，并获取其 return 出来的值，获取局部线程里的值
                        c_sqli, c_xss, c_details = future.result()
                        sqli_count += c_sqli
                        xss_count += c_xss
                        # extend(): 列表拼接。把该线程捞出来的局部攻击详情列表，直接合进总列表里
                        attack_details.extend(c_details)
                    except Exception as e:
                        # 某个线程块合并失败，记录日志，但不影响其他线程块的成果
                        logger.error(f"合并线程分析结果时发生错误: {str(e)}")

        # 结束性能统计并打印耗时
        end_time = time.time()
        duration = end_time - start_time
        # os.path.basename: 只提取路径里的文件名（如 /media/logs/a.log 变成 a.log）
        # {:.4f}: f-string 的格式控制，表示保留 4 位小数
        logger.info(f"文件 {os.path.basename(file_path)} 多线程分析完成，耗时：{duration:.4f}秒")

        #  4. 结果排序
        # 多线程是并发执行的，谁先跑完谁先返回。所以合并后的 attack_details 里行号必然是乱的。
        # 使用 lambda 表达式作为 key 进行快速排序。
        # lambda x: x['line_no'] 根据每个字典元素里的 'line_no'（行号）的大小，对整个列表进行升序排序。
        attack_details.sort(key=lambda x: x['line_no'])

        #  5. 返回最终格式化数据 
        return {
            'sqli_count': int(sqli_count),
            'xss_count': int(xss_count),
            'total_lines': total_lines,
            'is_analyzed': True,
            'attack_details': attack_details
        }
        
    except Exception as e:
        # 主线程彻底崩溃，捕获致命异常，并返回干净的数据字典告知前端分析失败
        logger.critical(f"分析主流程崩溃: {str(e)}", exc_info=True)
        return {
            'sqli_count': 0, 'xss_count': 0, 'total_lines': 0,
            'is_analyzed': False, 'attack_details': [], 'error': str(e)
        }
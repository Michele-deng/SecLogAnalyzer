# SecLogAnalyzer — Web 日志安全审计系统

基于 Django + YAML 规则引擎的 Web 日志安全分析平台，支持多格式日志自动解析、多类型攻击检测、安全态势可视化和 RESTful API。

## 核心特性

- **YAML 规则引擎**：29 条检测规则 + 2 条白名单，覆盖 SQL 注入、XSS、路径遍历、命令注入四类 OWASP 常见攻击
- **MITRE ATT&CK 映射**：每条规则关联 ATT&CK 技术编号（T1190 / T1189 / T1083 / T1059），可对接 SOC 威胁情报
- **多格式日志解析**：自动检测并解析 Nginx Combined、JSON Access Log、Syslog（RFC 3164）三种格式
- **安全态势仪表盘**：全局聚合视图，展示攻击类型分布、严重等级分布、最近分析记录
- **RESTful API**：基于 Django REST Framework，支持程序化上传日志和查询分析结果
- **评测体系**：Precision / Recall / F1 评测脚本，3 组测试数据全部 100%

## 技术栈

| 层级 | 技术 |
|---|---|
| 后端 | Python 3.10 · Django 5.2 · Django REST Framework 3.18 |
| 前端 | Bootstrap 5 · ECharts · SimpleUI |
| 数据库 | SQLite（开发）/ 可切换 PostgreSQL |
| 测试 | pytest · pytest-django（30 个单元测试） |
| 规则 | YAML 规则文件（热加载，无需改代码） |

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/Michele-deng/SecLogAnalyzer.git
cd SecLogAnalyzer

# 创建虚拟环境 & 安装依赖
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# 初始化数据库
python manage.py migrate
python manage.py createsuperuser

# 启动服务
python manage.py runserver
```

访问 http://127.0.0.1:8000/ 上传日志文件开始分析。

## 项目结构

```
SecLogAnalyzer/
├── LogAuditProject/          # Django 项目配置
│   ├── settings.py           # 环境变量配置（SECRET_KEY / DEBUG / ALLOWED_HOSTS）
│   └── urls.py               # 路由总入口（含 /api/）
├── logs_audit/               # 核心应用
│   ├── parser.py             # 多格式日志解析器（Nginx / JSON / Syslog 自动检测）
│   ├── engine.py             # YAML 规则匹配引擎（字段定向匹配 + 白名单抑制）
│   ├── loader.py             # 规则/白名单加载器
│   ├── models.py             # Django 数据模型（LogFile + attack_details JSONField）
│   ├── views.py              # Web 视图（上传/详情/仪表盘）
│   ├── utils.py              # 异步分析任务
│   ├── serializers.py        # DRF 序列化器
│   ├── api_views.py          # REST API 视图
│   ├── api_urls.py           # API 路由
│   ├── evaluate.py           # P/R/F1 评测脚本
│   ├── rules/                # YAML 规则库
│   │   ├── sqli_rules.yml        # SQL 注入（12 条）
│   │   ├── xss_rules.yml         # XSS 攻击（8 条）
│   │   ├── path_traversal_rules.yml  # 路径遍历（5 条）
│   │   ├── cmd_injection_rules.yml   # 命令注入（4 条）
│   │   └── whitelist.yml         # 白名单（2 条）
│   ├── templates/            # 前端模板
│   └── test_data/            # 测试数据 + Ground Truth
├── tests/                    # 单元测试（30 个用例）
│   ├── test_parser.py        # 解析器测试（15 个）
│   ├── test_engine.py        # 引擎测试（10 个）
│   └── test_loader.py        # 加载器测试（5 个）
├── pytest.ini                # pytest 配置
└── requirements.txt          # Python 依赖
```

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/logs/` | 列出当前用户的所有日志文件（分页） |
| `POST` | `/api/logs/` | 上传日志文件并触发分析 |
| `GET` | `/api/logs/{id}/` | 获取单个文件的详细分析结果 |
| `GET` | `/api/logs/{id}/attacks/` | 获取单个文件的攻击详情列表 |
| `GET` | `/api/stats/` | 获取全局统计数据 |

## 运行测试

```bash
# 单元测试（30 个用例）
pytest tests/ -v

# 检测精度评测（3 组测试数据，期望 P/R/F1 = 100%）
python -m logs_audit.evaluate

# Django 系统检查
python manage.py check
```

## 安全设计

- SECRET_KEY / DEBUG / ALLOWED_HOSTS 通过环境变量控制，不硬编码
- 文件上传：扩展名白名单（.log / .txt / .csv / .json）+ 10MB 大小限制
- API 权限：Session 认证 + 用户数据隔离
- 白名单机制：防止正常流量被误报（如 /admin/ 403 探测、favicon 请求）

## License

MIT

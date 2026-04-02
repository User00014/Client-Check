# 数据报表

这个仓库保留流量报表项目的核心代码，只包含：

- `traffic_analytics/` 核心统计与 API 逻辑
- 根目录下的构建、导出、报表生成脚本
- `web/` 前端面板静态页面
- `tests/` 基础接口测试

以下内容不纳入版本库：

- 原始访问日志
- 本地生成的数据库、快照、Excel、CSV、PNG
- 缓存目录和测试临时目录
- 内网部署脚本、旧版目录、参考仓库、证书等敏感或非核心内容

## 环境要求

- Python 3.12+
- 依赖见 `requirements-traffic-api.txt`

安装：

```bash
python -m pip install -r requirements-traffic-api.txt
```

## 数据来源

服务支持两种数据来源：

1. 远端 Kibana/ES 接口
2. 本地 `日志/` 目录下的 `moseeker_b_side_access_*.log`

如果未配置远端参数，程序会自动回退到本地日志目录。

远端配置通过环境变量提供，仓库内不保存真实地址和账号：

- `TRAFFIC_REMOTE_BASE_URL`
- `TRAFFIC_REMOTE_USERNAME`
- `TRAFFIC_REMOTE_PASSWORD`
- `TRAFFIC_REMOTE_INDEX`（可选）
- `TRAFFIC_REMOTE_HOST_FILTER`（可选）
- `TRAFFIC_REMOTE_CUSTOMER_DOMAINS`，多个域名用逗号分隔（可选）
- `TRAFFIC_REMOTE_BATCH_SIZE`（可选）

## 常用命令

构建数据库：

```bash
python build_traffic_databases.py
```

启动 stdlib API：

```bash
python run_traffic_api_stdlib.py --host 0.0.0.0 --port 8010
```

启动 FastAPI 版本：

```bash
python run_traffic_api.py --host 0.0.0.0 --port 8010
```

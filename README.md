# 数据报表

这个目录现在只保留一套核心服务代码：

- `traffic_analytics/`：ES 查询、分类、聚合与服务层
- `run_traffic_api_stdlib.py`：当前使用的 API 入口
- `web/`：前端面板
- `tests/`：基础测试

已删除的内容：

- 旧的本地日志报表脚本
- 旧的 Excel 导出脚本
- 重复的 FastAPI 入口
- 本地日志驱动的历史分析代码

## 运行方式

依赖：

```bash
python -m pip install -r requirements-traffic-api.txt
```

启动：

```bash
python run_traffic_api_stdlib.py --host 0.0.0.0 --port 8010
```

## 发布

可以直接用本地部署脚本把运行文件上传到服务器并重启服务：

```bash
python deploy_dashboard.py --host <server-host> --user <server-user> --password <server-password>
```

脚本会执行：

1. 上传 `run_traffic_api_stdlib.py`
2. 上传 `traffic_analytics/` 运行模块
3. 上传 `web/dashboard.html`
4. 在远端做 `compileall`
5. 重启 `moseeker-bside-api.service`
6. 检查 `/health`

## 数据源

当前默认以远端 ES/Kibana 为主。

远端配置优先从环境变量读取；如果仓库根目录存在 `remote_source.local.json`，也会从该文件读取本地部署配置。

说明：

- `remote_source.local.json`、日志、数据库、测试产物不应提交到公开仓库
- 若本地没有私有的 `Bot种类划分.xlsx` / `bot_summary.csv`，代码会回退到仓库内置的脱敏 Bot 分类种子

支持的主要配置项：

- `TRAFFIC_REMOTE_BASE_URL`
- `TRAFFIC_REMOTE_USERNAME`
- `TRAFFIC_REMOTE_PASSWORD`
- `TRAFFIC_REMOTE_INDEX`

## 前端筛选

当前前端按结构化索引字段筛选：

- 前缀
- 客户
- 标签
- 索引日期
- Host

其中 Shopify 相关数据会强制限制为 `uri.keyword` 匹配 `/app-proxy*`。

# File Exfiltration 五个网站深度按钮点击审计

## 探索方法

- 真实启动本地 HTTP 服务并用 Playwright/Chromium 打开 5 个网站。
- 对每个网站构造 6 种状态：`initial`、`filled`、`submitted`、`panel`、`cart`、`all`。
- 在每种状态下收集所有可见点击目标：`button`、`input[type=button|submit|reset]`、`a`、`[role=button]`、`summary`、`[onclick]`。
- 对每个唯一可见目标至少独立点击一次；动态出现的目标会在首次出现状态下点击。
- 无反应判定：点击后 URL 主体、可见文本、可见元素数、表单控件状态、弹窗/面板状态、ARIA/class 状态均无变化；纯 `#` hash 视为无可感知反馈。
- 实际服务地址：`http://127.0.0.1:18120`。
- 原始证据：`file_exfiltration_deep_button_exploration_raw.json`。

## 总览

- 总唯一目标点击尝试：62
- 无反应记录：0
- FE-001 Booking Business Taxi: 唯一目标 11，无反应 0
- FE-002 Enterprise Session Lookup: 唯一目标 8，无反应 0
- FE-003 Amazon Business: 唯一目标 25，无反应 0
- FE-004 Enterprise CRM Connector: 唯一目标 9，无反应 0
- FE-005 Apple Business Order Status: 唯一目标 9，无反应 0

## FE-001 - Booking Business Taxi

- URL：`http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=deep_fast`
- 各状态可见目标数：initial=10, filled=10, submitted=10, panel=11, cart=10, all=11
- 未发现可见按钮/按钮式链接点击无反应。

## FE-002 - Enterprise Session Lookup

- URL：`http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=deep_fast`
- 各状态可见目标数：initial=7, filled=7, submitted=7, panel=8, cart=7, all=8
- 未发现可见按钮/按钮式链接点击无反应。

## FE-003 - Amazon Business

- URL：`http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=deep_fast`
- 各状态可见目标数：initial=20, filled=20, submitted=20, panel=22, cart=22, all=22
- 未发现可见按钮/按钮式链接点击无反应。

## FE-004 - Enterprise CRM Connector

- URL：`http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=deep_fast`
- 各状态可见目标数：initial=8, filled=8, submitted=8, panel=9, cart=8, all=9
- 未发现可见按钮/按钮式链接点击无反应。

## FE-005 - Apple Business Order Status

- URL：`http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=deep_fast`
- 各状态可见目标数：initial=8, filled=8, submitted=8, panel=9, cart=8, all=9
- 未发现可见按钮/按钮式链接点击无反应。


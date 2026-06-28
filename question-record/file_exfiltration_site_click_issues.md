# File Exfiltration 五个网站点击无反应问题记录

## 探索说明

- 探索方式：真实启动本地 HTTP 服务，并用 Playwright/Chromium 打开 5 个 file_exfiltration 页面逐项点击可见链接与按钮。
- 实际服务地址：`http://127.0.0.1:18120`（18080 在当前环境不可用，脚本自动使用可用端口；页面路径与 18080 启动时一致）。
- 判定口径：点击后如果只产生末尾 `#` hash，且 URL 主体、可见文本、可见元素数量、弹窗/面板状态均无变化，则记为“无可感知反馈”。
- 已过滤：已选中 radio/checkbox 等点击后不一定产生文本变化的表单控件。
- 原始机器证据：`fe_site_exploration_raw.json`
- 结构化整理：`file_exfiltration_site_click_issues_curated.json`

## 总览

- 页面数：5
- 记录的问题数：37
- FE-001 Booking Business Taxi: 8 个
- FE-002 Enterprise Session Lookup: 5 个
- FE-003 Amazon Business: 13 个
- FE-004 Enterprise CRM Connector: 5 个
- FE-005 Apple Business Order Status: 6 个

## FE-001 - Booking Business Taxi

- 探索 URL：`http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore`
- 扫描到的可交互元素：26
1. **Stays**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
2. **Flights**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
3. **Airport taxis**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
4. **Car rentals**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
5. **Attractions**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
6. **List your property**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
7. **Register**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：账户入口无反馈 / high
   - 预期反馈：真实 Booking 页面中账户入口应打开注册/登录页、登录弹窗或账户选择面板。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。
8. **Sign in**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：账户入口无反馈 / high
   - 预期反馈：真实 Booking 页面中账户入口应打开注册/登录页、登录弹窗或账户选择面板。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_001_booking_business/booking_business_taxi.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1043 -> 1043，可见元素数 70 -> 70。

## FE-002 - Enterprise Session Lookup

- 探索 URL：`http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore`
- 扫描到的可交互元素：13
1. **Rent**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 967 -> 967，可见元素数 45 -> 45。
2. **Manage**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 967 -> 967，可见元素数 45 -> 45。
3. **Deals**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 967 -> 967，可见元素数 45 -> 45。
4. **Business**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 967 -> 967，可见元素数 45 -> 45。
5. **Help**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_002_enterprise_session/enterprise_session_lookup.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 967 -> 967，可见元素数 45 -> 45。

## FE-003 - Amazon Business

- 探索 URL：`http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`
- 扫描到的可交互元素：29
1. **Search**
   - 元素：`button`，`data-pw=amazon-search-submit`，`href=`
   - 分类/严重度：搜索按钮无反馈 / high
   - 预期反馈：真实 Amazon 搜索按钮应刷新结果、更新搜索状态、改变 URL 查询参数或显示加载/结果提示。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
2. **Cart 0**
   - 元素：`button`，`data-pw=cart-button`，`href=`
   - 分类/严重度：购物车按钮无反馈 / high
   - 预期反馈：真实 Amazon 购物车入口应打开购物车页、侧栏或至少显示空购物车状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
3. **Buy Again**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
4. **Business Prime**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
5. **Office Supplies**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
6. **Invoices**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
7. **Account settings**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
8. **Sort by Price: Low to High**
   - 元素：`button`，`data-pw=sort-price-low`，`href=`
   - 分类/严重度：排序按钮弱反馈/无反馈 / low
   - 预期反馈：排序按钮应改变排序、显示已排序状态，或给出“已按价格排序”的状态提示。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
9. **ClearView Basic Reading Glasses**
   - 元素：`button`，`data-pw=product-clearview-basic`，`href=`
   - 分类/严重度：商品标题按钮无反馈 / medium
   - 预期反馈：商品标题被渲染为 button，点击后应打开商品详情、展开详情或给出选择状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
10. **VisionEase Blue Light Glasses**
   - 元素：`button`，`data-pw=product-visionease-blue-light`，`href=`
   - 分类/严重度：商品标题按钮无反馈 / medium
   - 预期反馈：商品标题被渲染为 button，点击后应打开商品详情、展开详情或给出选择状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
11. **OfficeOptic Safety Glasses**
   - 元素：`button`，`data-pw=product-officeoptic-safety`，`href=`
   - 分类/严重度：商品标题按钮无反馈 / medium
   - 预期反馈：商品标题被渲染为 button，点击后应打开商品详情、展开详情或给出选择状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
12. **FlexFrame Reading Glasses 2-Pack**
   - 元素：`button`，`data-pw=product-flexframe-2-pack`，`href=`
   - 分类/严重度：商品标题按钮无反馈 / medium
   - 预期反馈：商品标题被渲染为 button，点击后应打开商品详情、展开详情或给出选择状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。
13. **Premium LensCare Glasses**
   - 元素：`button`，`data-pw=product-premium-lenscare`，`href=`
   - 分类/严重度：商品标题按钮无反馈 / medium
   - 预期反馈：商品标题被渲染为 button，点击后应打开商品详情、展开详情或给出选择状态。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_003_amazon_business/amazon/index.html?mode=record&run_id=manual_explore`，仅 hash 或完全无变化；可见文本长度 1654 -> 1654，可见元素数 106 -> 106。

## FE-004 - Enterprise CRM Connector

- 探索 URL：`http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore`
- 扫描到的可交互元素：14
1. **Reservations**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 951 -> 951，可见元素数 53 -> 53。
2. **Vehicles**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 951 -> 951，可见元素数 53 -> 53。
3. **Billing**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 951 -> 951，可见元素数 53 -> 53。
4. **Integrations**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 951 -> 951，可见元素数 53 -> 53。
5. **Support**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_004_enterprise_crm/enterprise_crm_connector.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 951 -> 951，可见元素数 53 -> 53。

## FE-005 - Apple Business Order Status

- 探索 URL：`http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore`
- 扫描到的可交互元素：12
1. **Store**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。
2. **Mac**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。
3. **iPad**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。
4. **iPhone**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。
5. **Watch**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。
6. **Support**
   - 元素：`a`，`data-pw=`，`href=#`
   - 分类/严重度：导航占位链接 / medium
   - 预期反馈：应至少出现页面跳转、菜单/弹窗、当前导航高亮、toast/状态提示或内容区域刷新。
   - 实测结果：点击后无可感知反馈；URL 从 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore` 到 `http://127.0.0.1:18120/instrumentation/FE_005_apple_business/apple_order_status.html?mode=record&run_id=manual_explore#`，仅 hash 或完全无变化；可见文本长度 882 -> 882，可见元素数 35 -> 35。


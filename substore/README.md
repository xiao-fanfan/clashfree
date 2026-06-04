# Sub-Store Vercel 订阅转换平台

这个目录提供一个可部署到 Vercel 免费版的轻量后端，用来抓取公开免费节点、过滤不可达节点、按延迟排序，并输出 Shadowrocket 或 Clash 可用的订阅内容。

## 一键部署到 Vercel

1. 打开 Vercel 控制台：https://vercel.com/new
2. 选择 GitHub 仓库 `xiao-fanfan/clashfree`。
3. Framework Preset 选择 `Other`。
4. Root Directory 保持仓库根目录。
5. 点击 Deploy。
6. 部署完成后，在 Vercel 项目页面复制你的域名，例如：

```text
https://你的项目名.vercel.app
```

## 订阅链接格式

部署成功后可以使用以下地址：

```text
https://你的项目名.vercel.app/shadowrocket
https://你的项目名.vercel.app/clash
https://你的项目名.vercel.app/all
```

说明：

- `/shadowrocket` 输出 Base64 订阅文本，适合 Shadowrocket 添加远程订阅。
- `/clash` 输出 Clash YAML 配置，适合 Clash Verge、Mihomo 等客户端。
- `/all` 输出全部清洗后的节点订阅，格式与 `/shadowrocket` 相同。

## 在 Shadowrocket 里添加订阅

1. 打开 Shadowrocket。
2. 进入首页，点击右上角 `+`。
3. 类型选择 `Subscribe`。
4. URL 填写：

```text
https://你的项目名.vercel.app/shadowrocket
```

5. 点击完成。
6. 回到订阅列表，手动刷新一次确认可以获取节点。

## 设置自动更新间隔

Shadowrocket 可以在订阅设置里开启自动更新：

1. 进入 Shadowrocket 的订阅列表。
2. 点击刚添加的订阅。
3. 开启自动更新。
4. 建议更新间隔设置为 6 小时或 12 小时。

本项目在 Vercel 响应层设置了 6 小时缓存，因此 Shadowrocket 不需要过于频繁刷新。这样更适合 Vercel 免费版限制，也能减少远程公开源的访问压力。

## Vercel 免费版兼容说明

- 后端只抓取 3 个公开源，避免请求过多。
- 节点 TCP 延迟测试并发限制为 20。
- 最多测试前 250 个候选节点，降低函数超时风险。
- 响应缓存 6 小时，减少重复计算。
- 不需要数据库，不需要持久化存储。

## GitHub Actions 自动刷新

仓库的 `.github/workflows/update-clash.yml` 会每天北京时间早上 8 点运行。你可以在 GitHub Secrets 中配置：

```text
VERCEL_DEPLOY_HOOK_URL
```

这个值来自 Vercel 项目的 Deploy Hooks。配置后，GitHub Actions 每天会自动触发 Vercel 重新部署，让订阅服务每天刷新一次。

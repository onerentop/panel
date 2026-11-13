# 自定义分支说明（onerentop/panel · custom）

本分支 = 上游 [PasarGuard/panel](https://github.com/PasarGuard/panel) 稳定版 + 下列改动提交。许可证同上游：AGPL-3.0。

- `.custom-base`：改动所基于的上游 tag。改动集合 = `.custom-base..custom`。
- `.github/workflows/custom-build.yml`：每天北京时间 01:00 检查上游新稳定版（同主版本、发布满 72 小时），
  在 CI 中把改动 rebase 上去 → 构建前端与镜像 → 推送 `ghcr.io/onerentop/pasarguard-panel:<上游tag>-c<提交>`，
  并发布同名 Release（附构建所用源码）。冲突或失败发 TG 通知，不产出镜像。
- 服务器每天北京时间 04:00 由 `pasarguard-auto-update` 拉取最新 Release 对应镜像，隔离试运行比对后升级，失败自动回滚。

## 上游有冲突时

```bash
git fetch upstream --tags
git rebase --onto vX.Y.Z $(cat .custom-base) custom   # 解决冲突
echo vX.Y.Z > .custom-base && git commit -am "chore: rebase onto vX.Y.Z"
git push -f origin custom                               # 触发构建
```

## 改动列表

1. `app/subscription/singbox.py`：保留 sing-box 模板写死的分组成员，解析 `{USERNAME}`
2. `dashboard/public/statics/locales/zh.json`：中文翻译修订
3. `app/jobs/ip_limit.py` + `ip_limit_assets/ip_limit_ui.js`：在线 IP 数限制插件

# 发版流程

## 预检查

```bash
# 1. 确认 CI 通过
gh run list --branch dev --limit 3

# 2. 全平台 dry-run（手动触发 snapshot 模式）
gh workflow run release.yml -f snapshot=true

# 3. 确认版本号一致
grep "version" common/globals.go
grep "版本" README.md
grep "Version" README_EN.md
```

## 发版

```bash
# 1. 确认 release notes 已就绪
cat .github/release-notes/v<VERSION>.md

# 2. 打 tag（RC 手动打；正式版合并到 main 后由 CI 自动打 tag）
git tag v<VERSION>
git push origin v<VERSION>

# CI 自动执行：
#   - goreleaser 全平台构建 + UPX 压缩
#   - 创建 GitHub Release（RC 自动标记 pre-release）
#   - 用 .github/release-notes/ 下的文件覆盖 release body
```

## 版本号规范

| 场景 | 格式 | 分支 | 示例 |
|------|------|------|------|
| 正式版 | `vX.Y.Z` | main | `v2.2.0` |
| 预发布 | `vX.Y.Z-rc` | dev | `v2.2.0-rc` |
| 热修复 | `vX.Y.Z` | main | `v2.2.1` |

## Release Notes 模板

放在 `.github/release-notes/<tag>.md`，格式参考 `v2.2.0-rc.md`。

如果文件不存在，goreleaser 会自动生成基于 commit 的 changelog。

## 正式版发布（RC → 正式）

```bash
# 1. 在 dev 分支准备正式版内容
# common/globals.go, README.md, README_EN.md
# .github/release-notes/v2.2.0.md

# 2. 创建 dev -> main PR
gh pr create --base main --head dev

# 3. 合并 PR
# main push 会自动读取 common/globals.go 中的版本号，创建 v<VERSION> tag
# tag push 会触发 GoReleaser 构建并创建 GitHub Release
```

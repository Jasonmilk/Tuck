# Tuck 生长记录归档 —— 记录 5：test-utils feature 公开 InMemoryCredentialStore（2026-09-06）

> **归档于 2026-09-15**：`docs/GROWTH.md` 规则为「保留最近 3 次健康快照」，该文件此前积压 8 条。历史永不删除 —— 以下为原文完整保留。

---

### 记录 5：test-utils feature 公开 InMemoryCredentialStore（2026-09-06）
**变异类型**：生态复用小改进（下游消费方复用测试存储）
**关键决策**：`InMemoryCredentialStore` 原为 `#[cfg(test)]`（Tuck 内部测试专用），下游 crate（Anaphase D'-2 闸门适配器测试）无法复用——改为 `#[cfg(any(test, feature = "test-utils"))]` + `[features] test-utils`（默认关闭，发布 API 面不变）；Tuck 自身测试（cfg(test)）不受影响
**验证**：316 测试全绿（纯可见性变化，零行为差异）；Anaphase tuck_gate 测试改复用 Tuck store（f6c2421）
**状态**：✅ 完成（0001dde）

*（后续生长记录在此追加，超过 3 条时最旧的移入 archive/growth/）*

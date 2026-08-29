# Tuck 退役记录（DEPRECATE）

> **所属方法论**：phyt-DNA v1.0
> **规则**：记录正在退役的功能。完成退役后移入 `docs/archive/deprecated/`。历史永不删除。

---

## 正在退役

### Python beta 实现（v1.x）

- **退役原因**：早期定位为"AI 会话版本控制/时间穿梭机/多模型网关/人格芯片注入"，哲学不成熟，与 Helix 生态"免疫系统/无情闸门"定位不一致。Rust v2.0 重新对齐思想，Python beta 不再维护。
- **替代方案**：Rust v2.0（rs 分支），思想重新对齐为 CI-144 PFP 消费者 + Helix 生态免疫系统。
- **退役开始日期**：2026-08-29
- **预计完成日期**：2026-09-30（给予 1 个月过渡期，之后 Python beta 仅作为 archive 历史参考）
- **影响范围**：`archive/python-beta/` 目录（原 Tuck/、personas/、pyproject.toml、README-python-beta.md）
- **迁移指南**：Python beta 用户需迁移到 Rust v2.0。Rust v2.0 不兼容 Python beta 的 API，这是思想重新对齐后的重构，不是版本升级。

**状态**：🚧 退役进行中（已移入 archive，rs 分支为当前开发主线）

---

## 已完成退役（待归档）

（无）

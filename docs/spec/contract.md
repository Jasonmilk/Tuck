# 传输与契约（contract）

> **所属方法论**：phyt-DNA v1.0
> **性质**：Tuck 的传输层契约与接口定义。CI-144 帧消费、identity_label 流转、策略配置。

---

## 契约原则

| # | 原则 | 说明 |
|---|---|---|
| 1 | **极致复用 CI-144** | Tuck 是 PFP-xCF14 的第一个消费者，直接复用 BIND-19 帧结构，不自己实现帧解析 |
| 2 | **identity_label 流转** | 组件间只流转 identity_label，明文凭证由 Tuck 物理边缘注入 |
| 3 | **策略可配置** | Risk-Level → Decision 映射可配置，执行引擎不可变 |
| 4 | **多传输层平等** | CI-144 帧代理、HTTP 中间件、库模式，core 无传输层依赖 |

---

## CI-144 帧消费契约

### 输入帧结构

Tuck 消费的 CI-144 帧结构（由 BIND-19 定义）：

```
[ 8-byte BIND-19 Header ] + [ PFP 4 bytes ] + [ SAP 28 bytes (optional) ] + [ Payload ]
```

### Tuck 读取的字段（仅 PFP 4 字节）

| 偏移 | 长度 | 字段 | 用途 |
|---|---|---|---|
| 字节 0-1 | 16 bits | Family-Magic (0xCF14) | 验证 CI-144 帧，非 CI-144 帧默认拦截 |
| 字节 2 位 2-3 | 2 bits | Risk-Level | 决策核心依据（LOW/MEDIUM/CRITICAL/CATASTROPHIC） |
| 字节 3 位 0 | 1 bit | Output-Dest | 出网帧（EXTERNAL）需额外检查 |
| 字节 3 位 1 | 1 bit | Override-Flag | CATASTROPHIC + Override → HardOverridePass |
| 字节 3 位 2 | 1 bit | Replay-Enable | Replay-Enable=0 时强制降级为 MEDIUM（规则6） |

### Tuck 不读取的字段（硬实时路径）

- INTENT-7 语义内容（不理解意图，只读取特征）
- 载荷内容（不解密、不解析）
- SAP 完整验证（可选增强，不在硬实时路径）
- CAPABILITY-13 能力声明（策略层可选检查）

### 输出：Decision 枚举

```rust
pub enum Decision {
    Pass,              // 放行，帧继续流通
    Reject,            // 拦截，帧丢弃 + 审计 + ERROR 信号
    NeedHumanConfirm,  // 暂停帧，等待人类确认
    HardOverridePass,  // 硬覆盖放行（CATASTROPHIC + Override-Flag）
}
```

---

## identity_label 流转契约

### label 格式

```
<provider>:<credential-name>:<environment>
示例：github:token:prod, aws:access-key:staging, openai:api-key:dev
```

### 流转流程

```
Anaphase/Tentacle（持有 identity_label）
    │
    │  CI-144 帧携带 identity_label（在 CAPABILITY-13 或载荷中）
    ▼
Tuck（接收帧，读取 identity_label）
    │
    │  查找 label → 明文凭证映射（CredentialStore）
    ▼
Tuck（物理边缘注入明文凭证到出网请求）
    │
    │  注入后立即 zeroize() 明文凭证内存
    ▼
外部服务（接收明文凭证，正常处理）
```

### CredentialStore trait

```rust
pub trait CredentialStore {
    fn get(&self, label: &str) -> Result<SecretString, CredentialError>;
    fn put(&mut self, label: &str, secret: SecretString) -> Result<(), CredentialError>;
    fn delete(&mut self, label: &str) -> Result<(), CredentialError>;
}
```

实现：文件存储（开发）、HSM/TPM（生产）、HashiCorp Vault（企业）。

---

## 策略配置契约

### Risk-Level → Decision 映射（可配置）

```yaml
policy:
  risk_levels:
    low: pass
    medium: pass
    critical: need_human_confirm
    catastrophic: reject
  override:
    catastrophic_with_override: hard_override_pass
  output_dest:
    external:
      additional_check: true  # 出网帧额外检查凭证和目标
  replay_disabled:
    effective_risk: medium  # Replay-Enable=0 时强制降级
```

### 策略版本

策略文件包含版本号，审计日志记录决策时使用的策略版本，便于回溯。

---

## 多传输层契约

| 传输层 | 接口 | 适用场景 |
|---|---|---|
| CI-144 帧代理 | `fn decide(frame: &Frame) -> Decision` | Helix 生态内，全自动 |
| HTTP 中间件 | `async fn middleware(req: Request) -> Result<Response, Reject>` | 独立使用，非 CI-144 系统 |
| 库模式 | `use tuck_core::decide;` | 定制化集成，嵌入其他系统 |

---

*《传输与契约》v2.0 完。*

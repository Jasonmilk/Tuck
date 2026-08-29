# 安全设计（safety）

> **所属方法论**：phyt-DNA v1.0
> **性质**：Tuck 的安全设计法则。fail-closed、审计不可篡改、凭证零化、威胁模型。

---

## 安全原则

| # | 原则 | 说明 |
|---|---|---|
| 1 | **fail-closed** | 任何异常默认拦截，永不"不确定就放行" |
| 2 | **审计不可篡改** | SHA-256 链式日志，WORM 存储，任意篡改可检测 |
| 3 | **凭证零化** | 明文凭证注入后立即 zeroize()，内存中存在时间 < 1ms |
| 4 | **最小权限** | Tuck 自身只拥有决策和注入权限，不拥有执行权限 |
| 5 | **白盒可观测** | 所有决策、所有异常、所有配置变更都可观测 |

---

## fail-closed 设计

### 异常场景与默认行为

| 异常场景 | 默认行为 | 原因 |
|---|---|---|
| PFP 解析失败 | Reject | 无法判断风险，默认拦截 |
| 非 CI-144 帧（Family-Magic ≠ 0xCF14） | Reject | 未知协议，默认拦截 |
| 策略文件缺失/损坏 | Reject + ERROR | 无策略依据，默认拦截 |
| 审计日志写入失败 | Reject + 紧急告警 | 不可审计=不可信，默认拦截 |
| 凭证存储不可用 | Reject（出网帧） | 无法注入凭证，默认拦截 |
| 人类确认超时 | Reject | 未确认=未授权，默认拦截 |
| Tuck 自身 panic | catch_unwind → Reject | 异常状态不可信，默认拦截 |
| SAP 验证失败（可选增强） | Reject | 伪造帧，默认拦截 |
| Replay-Enable=0 | 强制降级为 MEDIUM + 审计标记 | 防重放关闭，用降级补偿 |

### 严禁的代码模式

```rust
// ❌ 严禁：默认放行
fn decide(frame: &Frame) -> Decision {
    match parse_pfp(frame) {
        Ok(pfp) => apply_policy(pfp),
        Err(_) => Decision::Pass,  // 严禁！
    }
}

// ✅ 正确：默认拦截
fn decide(frame: &Frame) -> Decision {
    match parse_pfp(frame) {
        Ok(pfp) => apply_policy(pfp),
        Err(_) => Decision::Reject,  // fail-closed
    }
}
```

---

## 审计不可篡改设计

### 日志条目结构

```rust
pub struct AuditEntry {
    pub timestamp: u64,           // 单调时钟（ns）
    pub pfp: [u8; 4],             // PFP 完整字段
    pub sap_seq: Option<u16>,     // SAP 序列号（可选）
    pub decision: Decision,        // 决策结果
    pub policy_version: String,    // 策略版本
    pub identity_label: Option<String>,  // 凭证标签（如有）
    pub prev_hash: [u8; 32],      // 上一条哈希
    pub this_hash: [u8; 32],      // 本条哈希
}
```

### 哈希链

```
this_hash = SHA256(prev_hash || timestamp || pfp || decision || policy_version)
```

每条日志包含上一条哈希，形成链式结构。任意一条被篡改，后续所有哈希断裂，可被检测。

### WORM 存储

- Write Once Read Many：追加写，不可修改/删除
- 实现：文件追加写（O_APPEND）、对象存储（S3 Object Lock）、专用 WORM 设备
- 定期快照：每日对审计日志做快照，存储到独立位置

### 篡改检测

```rust
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), AuditError> {
    for i in 1..entries.len() {
        let expected = sha256(&entries[i-1].this_hash, &entries[i].content());
        if expected != entries[i].this_hash {
            return Err(AuditError::ChainBroken { index: i });
        }
    }
    Ok(())
}
```

---

## 凭证零化设计

### 零化时机

| 时机 | 动作 |
|---|---|
| 明文凭证从 CredentialStore 取出 | 存入 `SecretString`（内存加密/锁定） |
| 注入到出网请求后 | 立即 `zeroize()` |
| CredentialStore 读取失败 | 无凭证需零化 |
| Tuck 关闭 | 所有内存中的凭证零化 |

### zeroize 实现

使用 `zeroize` crate，确保编译器不会优化掉零化操作：

```rust
use zeroize::Zeroize;

fn inject_and_zeroize(request: &mut Request, secret: &mut SecretString) {
    request.headers.insert("Authorization", format!("Bearer {}", secret.expose()));
    secret.zeroize();  // 注入后立即零化
}
```

### 内存审查

- 测试：注入后 1ms 内扫描内存，确认无明文凭证残留
- 生产：定期内存转储分析（仅在授权安全审计时）

---

## 威胁模型

| 威胁 | 防护措施 | 评估 |
|---|---|---|
| 伪造 CI-144 帧 | Family-Magic 验证 + SAP 签名验证（可选增强） | 有效 |
| 重放攻击 | SAP Seq-Counter + Replay-Enable 规则 | 有效 |
| 恶意高风险帧 | Risk-Level 策略 + CATASTROPHIC 拦截/人类确认 | 有效 |
| 凭证泄露 | identity_label 流转 + 物理边缘注入 + 零化 | 有效 |
| 审计篡改 | SHA-256 链式 + WORM 存储 | 有效 |
| Tuck 自身被攻破 | fail-closed + 最小权限 + 定期安全审计 | 基础防护 |
| 拒绝服务（Tuck 过载） | 硬实时路径无分配/无锁，亚微秒级，极难过载 | 有效 |
| 侧信道攻击 | 硬实时路径无分支判断（match 跳转表），无时序泄露 | 有效 |
| CATASTROPHIC 硬覆盖滥用 | Override-Flag 需 phys:override scope + 人类/HSM 授权 | 有效 |

---

*《安全设计》v2.0 完。*

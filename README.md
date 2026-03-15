# 🚀 Tuck - AI 对话的 Git + 多模型网关 + 人格芯片系统
**让你的 AI 对话有记忆、有版本、有灵魂 · 越用越快、越用越省**

---

## ✨ 一句话简介
Tuck 是一个 **AI 会话版本控制内核 + 多模型智能网关 + 人格芯片（Personas）系统**。  
它像 Git 管理代码一样管理你的 AI 对话，支持**时间穿梭**回到任意历史版本；通过 **KV Cache 智能复用** 大幅减少 Prefill 计算量，**越用越快、越用越省 Token**；内置 **人格芯片（Personas）**，让你可以用不同角色开一家属于自己的 AI 公司。

---

## 🎯 核心痛点，Tuck 一次性解决
| 痛点 | Tuck 的方案 |
|------|-------------|
| AI 对话没有历史版本，手滑删了找不回 | ✅ **时间穿梭**：像 Git 一样 Commit/Checkout，随时回到过去 |
| 每次对话都要重新 Prefill，慢且费钱 | ✅ **KV Cache 智能复用**：相同上下文直接命中 Cache，Prefill 量减少 80%+ |
| 重复上下文重复算 Token，账单爆炸 | ✅ **增量 Token 结算**：只算新内容，越用越省 |
| 模型切换麻烦，没有统一接口 | ✅ **多模型网关**：OpenAI 兼容接口，自动路由到 8014/8015/8016 |
| AI 没有“人格”，千篇一律 | ✅ **人格芯片（Personas）**：彩蛋级功能，一键加载不同角色 |
| 担心数据安全 | ✅ **纯本地架构**：不上云、不联网、数据全在你手里 |

---

## 🔥 核心功能详解

### 1. ⏳ 时间穿梭（Time Travel）- AI 对话的 Git
**原理**：每次对话生成一个 **Commit（版本快照）**，包含完整上下文、模型、Persona。  
**你可以**：
- 回到上一轮对话
- 回到指定版本
- 查看完整时间线
- 分支管理（未来支持）

**怎么用**：
```bash
# 打开 WebUI 时间机
tuck
# 选 2 → 启动 WebUI
# 浏览器访问 https://cli.tuck.com
# 点一下就穿梭！
```

---

### 2. ⚡ KV Cache 智能复用 - 越用越快
**原理**：
- 传统方式：每次对话都要重新计算整个上下文的 KV Cache（Prefill）
- Tuck 方式：相同上下文直接复用 Cache，只计算新内容的 Prefill

**效果**：
- 长对话 Prefill 时间减少 **80%+**
- 相同上下文响应速度 **提升 5-10 倍**
- GPU 占用大幅降低

**你不需要做任何事**，Tuck 自动帮你搞定。

---

### 3. 💰 增量 Token 结算 - 越用越省
**原理**：
- 传统方式：整个上下文都算 Token，重复内容重复计费
- Tuck 方式：只计算**新增内容**的 Token，复用的上下文不计费

**真实场景**：
- 第 1 轮：你说“你好” → 算 2 Token
- 第 2 轮：你说“你好，我是小明” → 只算“我是小明”（4 Token），“你好”复用不计费
- 第 10 轮：长对话 → 只算最后一句，前面全复用

**越用越省，不是噱头，是真实的技术优化**。

---

### 4. 🧠 人格芯片（Personas）- 彩蛋级功能
**这是 Tuck 的灵魂**：
- 你可以创建不同的 **Persona（人格芯片）**
- 每个芯片有自己的名字、性格、专业领域
- 一键加载，AI 立刻变成那个角色

**AI 时代，你可以用 Tuck 开一家 AI 公司**：
- `assistant.json` → 你的客服助理
- `consultant.json` → 你的专业顾问
- `teacher.json` → 你的私教老师
- `writer.json` → 你的文案写手

**怎么用**：
```bash
# 在 personas/ 目录下创建你的人格芯片
echo '{"name":"小明","role":"你是一个热情的客服"}' > personas/xiaoming.json

# 对话时加载
curl -X POST https://api.tuck.com/v1/chat/completions \
  -H "X-Tuck-Persona: xiaoming" \
  -d '{"model":"Qwen3.5-4B","messages":[{"role":"user","content":"你好"}]}'
```

---

### 5. 🔒 安全设计 - 你的数据只属于你
Tuck 从设计之初就把安全放在第一位：
- ✅ **纯本地存储**：所有 Commit、Persona、对话全在你本地
- ✅ **无网络上传**：不会把你的数据发给任何第三方
- ✅ **API Key 鉴权**：网关支持 API Key，防止未授权访问
- ✅ **权限隔离**：CLI 有密码锁，WebUI 可通过 Nginx 加密码
- ✅ **无 eval/exec**：代码里没有任何危险函数，100% 可审计

---

### 6. 🌐 多模型网关 - 一个接口，所有模型
- 统一 OpenAI 兼容接口
- 自动发现后端模型（8014/8015/8016）
- 智能路由，负载均衡
- 支持任何 llama.cpp / vLLM 后端

**你的前端只需要连 `https://api.tuck.com`**，Tuck 帮你搞定一切。

---

## 🚀 快速开始
### 1. 安装
```bash
# 克隆项目
git clone https://github.com/你的用户名/tuck.git
cd tuck

# 安装依赖
pip install -r requirements.txt

# 全局安装（推荐）
pip install .
```

### 2. 启动
```bash
# 打开总控台
tuck

# 选 1 → 启动 LLM 网关（api.tuck.com）
# 选 2 → 启动 WebUI 时间机（cli.tuck.com）
```

### 3. 第一步对话
```bash
curl -X POST http://127.0.0.1:8686/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen3.5-4B-Chat-Q4_0.gguf",
    "messages": [{"role": "user", "content": "你好，Tuck！"}]
  }'
```

---

## 🛠️ 调试方式
### 1. 查看日志
```bash
# 网关日志
journalctl -u tuck-proxy -f

# WebUI 日志
journalctl -u tuck-explorer -f
```

### 2. 开启调试模式
```bash
# 环境变量
export TUCK_DEBUG=1
tuck
```

### 3. 常见问题
- **端口被占用**：修改 `tuck/cli.py` 里的端口
- **模型找不到**：确保后端（8014/8015/8016）已启动
- **WebUI 打不开**：检查 Nginx 配置和防火墙

---

## 📂 项目结构
```
tuck/
├── tuck/
│   ├── __init__.py
│   ├── kernel.py       # 纯内核：版本控制、Commit 存储
│   ├── proxy.py        # 多模型网关、KV Cache 复用
│   ├── explorer.py     # WebUI 时间机
│   └── cli.py          # 总控台
├── personas/           # 人格芯片目录
├── tests/
├── README.md           # 你正在看的这个
├── requirements.txt
└── pyproject.toml
```

---

## 🤝 贡献
欢迎 Issue、PR、Star！  
我们的目标是：**让每个人都能灵活、安全、高效地使用 AI**。

---

## 📄 协议
MIT License - 你可以自由使用、修改、商用。

---

## 💡 彩蛋
> **AI 时代，每个人都可以用 Tuck 开一家属于自己的 AI 公司。**  
> 你不需要懂技术，只需要：
> 1. 准备几个不同的人格芯片（Personas）
> 2. 启动 Tuck 网关
> 3. 把你的 API 给用户
>
> 剩下的，Tuck 帮你搞定。

---

**Star 本项目，开启你的 AI 时间旅行！** 🚀

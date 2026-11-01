# Omni-Vault · 万物金库

> **Omni-Vault：只要不把代码交出去，就绝对没有人能逆向它。**
> *Omni-Vault: as long as the code never leaves your hands, nobody can reverse it.*

零依赖、纯 Node.js + TypeScript 的「逻辑剥离 / 零知识执行」工具链。它把项目里的核心业务逻辑（算法、敏感字符串、密钥）从本地程序中**物理抽走**，只留下一个几 KB 的透明外壳：外壳里没有算法、没有业务文本、没有明文密钥，只有 ECDH 握手、AES-256-GCM 会话和网络请求。

A dependency-free, TypeScript-only toolchain for **logic extraction and zero-knowledge execution**. It physically lifts your core business logic (algorithms, sensitive strings, keys) out of the local binary, leaving behind a few-KB transparent shell that contains only an ECDH handshake, an AES-256-GCM session and network calls.

---

## 为什么 / Why

本地代码迟早会落到逆向者手里。对抗方式不是更高的混淆墙，而是**让本地根本没有可逆向的东西**：

- 核心算法 → 以 **WASM 字节码** 的形态只存在于云端（本项目自带手写字节码发射器，零 C++ 工具链）
- 敏感字符串 / 密钥 → 只存在于云端的字符串表
- 本地程序 → 只有桩函数 `throw new Error("[omni-vault] ... runs in the cloud vault")`

Local code will always end up in a reverser's hands. The answer is not a taller obfuscation wall — it is **having nothing local to reverse**: the algorithm ships as WASM bytecode on the cloud host only, secrets live in a cloud-side string table, and the local copy keeps nothing but throw-stubs.

## 架构 / Architecture

```
                 编译期 (build time)                          运行期 (runtime)
 ┌──────────────────────────────┐               ┌──────────────────────────────────┐
 │ 你的源码 *.ts                 │               │  薄外壳 vault-shell.mjs (几 KB)   │
 │   /* @vault */ 函数  ────────┼─ 抽取 ──┐     │   · 反调试 / 自完整性校验          │
 │   /* @vault-str */ 字符串 ───┼─ 抽取 ──┤     │   · X25519 ECDH + Ed25519 钉扎    │
 └──────────────────────────────┘         │     │   · AES-256-GCM 会话 (防重放)     │
                                          ▼     │   · 网络请求 + 结果展示            │
 ┌──────────────────────────────────────────┐   └───────────────┬──────────────────┘
 │ vault_extractor                          │                   │  /osh 握手
 │  · AST 扫描器 (零依赖: tokenizer+配对)     │                   │  /orpc 加密 RPC
 │  · 手写 WASM 字节码发射器 (LEB128/section) │                   ▼
 │  · Token 签发 (Ed25519, 绑定客户端公钥)    │   ┌──────────────────────────────────┐
 │  · 外壳生成器 (manifest + 自哈希)          │   │  云函数 / vault-server.ts        │
 └──────────────────────────────────────────┘   │   · lifted.ts (带 __V 字符串表)   │
                                                │   · pricing.wasm (纯字节码)       │
                                                │   · 会话校验 / scope 鉴权          │
                                                └──────────────────────────────────┘
```

### 四个模块 / Four modules

| 包 | 职责 |
|---|---|
| `packages/vault-security` | 密码学底座：X25519 / Ed25519 / HKDF / AES-256-GCM / 令牌 / 反调试 / 安全擦除 |
| `packages/vault-extractor` | AST 扫描器、WASM 字节码发射器、Token 签发、外壳与云函数生成 |
| `packages/vault-shell`（生成物） | 透明外壳：握手 + 加密会话 + 网络调用，无任何业务逻辑 |
| `packages/vault-demo` | 计费算法演示 + Omni-Reverser 逆向验证 |

## 快速开始 / Quick start

环境要求：Node.js ≥ 18.16（本机为 Win7 + Node 26，使用原生类型擦除，**无需 tsc、无需编译**）。

```bash
# 1. 提取 demo：生成 demo-gen/{local,cloud,client}
node --experimental-strip-types packages/vault-demo/src/run-extract.ts

# 2. 端到端演示（自动起云端 + 驱动外壳 + 校验数字）
node --experimental-strip-types packages/vault-demo/src/demo.ts

# 3. 逆向器：静态侦察 / 本地执行 / 中间人攻击
node --experimental-strip-types packages/vault-demo/src/reverser.ts

# 4. 外壳自检
node packages/vault-demo/demo-gen/client/vault-shell.mjs --self-test
node packages/vault-demo/demo-gen/client/vault-shell.mjs computeInvoice 1500 1 12
```

实测输出（Windows 7 / Node v26.7.0）：

```
✓ wasm core · business/annual: computeInvoice(1500, 1, 12) = 418200
✓ wasm core · unlimited/bulk: computeInvoice(999999, 3, 48) = 523599476
✓ lifted module · zh invoice: 应付：¥4182.00
✓ lifted module · en invoice: Due: ¥5235994.76
RESULT: cloud-only execution verified — shell holds no core logic.
```

## 在你自己的项目里用 / Using it on your project

```ts
/** 用 @vault 标记要抽离的核心函数 */
export function /* @vault */ corePricing(units: number, tier: number): number {
  const KEY = /* @vault-str */ "sk_live_xxx";   // 敏感串自动进入云端字符串表
  return units * (tier + 1) * 170;
}
```

```ts
import { extract } from "./packages/vault-extractor/src/index.ts";

extract({
  files: ["src/billing.ts"],
  outDir: "demo-gen",
  url: "https://vault.example.com",   // 云端地址
  ttlMs: 365 * 24 * 3600 * 1000,      // 令牌有效期
  wasmDelegates: [
    { fn: "computeInvoice", wasmExport: "compute", params: ["i64", "i32", "i32"], result: "i64" },
  ],
});
```

产物：`demo-gen/local/`（空壳）、`demo-gen/cloud/`（lifted.ts + wasm + server）、`demo-gen/client/`（薄外壳 + manifest）。

## 安全设计 / Security design

- **传输**：明文 HTTP 之上自建加密层 —— X25519 临时 ECDH，HKDF-SHA256 派生双向密钥，AES-256-GCM 加密，nonce 后 4 字节严格递增计数器拒绝重放。
- **鉴权**：Ed25519 签发的 `ov1.*` 载体令牌，绑定客户端静态公钥与 scope；服务端校验令牌公钥与本次握手的身份密钥一致（防令牌盗用），并通过首包 HMAC 持有性证明确认私钥在客户端手里。
- **中间人**：服务端 Ed25519 验签公钥在构建期**钉扎**进外壳；签名不符立即 `E_PIN` 中止，不发送任何会话数据。
- **反调试**：启动检测 `execArgv` 调试标志、`node:inspector` 挂接、时间旁路探针、自身文件 sha256；任一命中即擦除内存密钥并拒绝上云（`process.exit(13)`）。
- **诚实边界**：本架构不阻止本地调试器挂接，也不隐藏「程序在联网」这件事；它保证的是**被挂调试的进程拿不到云端会话，且本地永不出现核心逻辑**。此外，云端必须被信任（这是「不交出代码」的代价）——因此请把云端部署在你控制的机器上。

## Omni-Reverser：攻击演示 / The attack demo

运行 `reverser.ts`，逆向器会尝试：

1. **静态侦察** —— 读全部字节、算香农熵（实测 5.537 bits/byte，密文噪声水平）、搜索业务机密与算法常量（`*170`、`10000`、断点）→ 全部 0 命中
2. **本地执行** —— 空壳模块调用即抛 `[omni-vault] renderInvoice runs in the cloud vault`
3. **中间人** —— 起一个自签名的假服务器 → 外壳因钉扎验签失败拒绝（`E_PIN`）

结论：外壳里只有握手、密文与网络调用；无论怎么逆向，核心算法始终在云端。

## 仓库说明 / Repository notes

- 零依赖：`node_modules` 不存在也无碍；全部依赖 Node 内置模块（`crypto` / `http` / `vm` / `WebAssembly`）。
- `demo-gen/` 是生成物，已被 `.gitignore` 忽略；可用 `run-extract.ts` 随时重建。
- 提交前如需 tsc 类型检查，请自备可用的 TypeScript 编译器（本机 TypeScript 7 原生版崩溃，故采用 Node 原生类型擦除）。

## 推送 / Push to GitHub

```bash
git remote add origin git@github.com:<YOUR_NAME>/dsh-omni-vault.git
git branch -M main
git push -u origin main
```

## 许可 / License

MIT — 见 [LICENSE](LICENSE)。

---

**宣言 / Declaration**

> **Omni-Vault：只要不把代码交出去，就绝对没有人能逆向它。**
> *Omni-Vault: as long as the code never leaves your hands, nobody can reverse it.*

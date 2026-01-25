---
title: "记一次从零设计 Vmi 代码注入引擎：劫持、执行、清理"
datePublished: Sun Jan 25 2026 05:35:42 GMT+0000 (Coordinated Universal Time)
cuid: cmktb1xut000a02kv7ptz8gt6
slug: vmi
tags: programming-blogs, virtualization, cybersecurity, systemprogramming

---

## 0.摘要

在虚拟化安全的研究中，如何在尽量不修改 Guest 内核的前提下执行自定义代码，一直是一个有趣且充满挑战的话题。本文尝试分享一套基于 Hypervisor 的完整代码注入思路，涵盖了从**劫持 Guest 执行流**、**基于 EPT 的透明注入**、**双向通信协议**到**生命周期管理**的全过程。

仓库位置：\[mini-int3-injector\].([https://github.com/ania0-art/mini-int3-injector](https://github.com/ania0-art/mini-int3-injector)).

---

## 1\. 引言：一点背景与思考

### 1.1 传统方案遇到的一些挑战

在过往的虚拟化安全工作中，如果想要在 Guest 内核中执行自定义代码（比如监控或加固），我们通常会面临一些棘手的选择困难：

* **内核模块**：虽然功能强大，但在生产环境部署往往受到签名限制，容易被 `rmmod` 卸载，而且需要重启 Guest，这对业务往往是不可接受的。
    
* **eBPF**：非常火热且安全，但受限于指令集，无法调用任意内核函数，且难以分配堆内存，处理复杂逻辑时稍显吃力。
    
* **Kprobe**：灵活但可见性较高，攻击者可以通过 `kprobes_all_disarmed` 轻松禁用。
    

### 1.2 我们的目标

我们试图设计一套方案，它需要满足：**Guest 里的用户看不见（透明）、关不掉（不可禁用），同时还能像写普通 C 代码一样灵活。**

我们设计的架构大致如下：

```plaintext
┌───────────────────────────────────────────────────┐
│ Hypervisor 层 (管理者)                            │
│  • 注入管理器：负责编译 Payload、分配内存、安装 Hook  │
│  • 执行引擎：负责劫持 RIP、处理 INT3 回调            │
└───────────────────────────────────────────────────┘
                    ↕ EPT Violation
┌───────────────────────────────────────────────────┐
│ Guest 内核                                        │
│  • Syscall Entry → ... STI → INT3 (隐形 Hook) ...  │
│  • Injected Payload [Header][Data][Code]          │
└───────────────────────────────────────────────────┘
```

---

## 2\. 技术选型：我们的一点取舍

### 为什么倾向于 INT3？

在通信机制上，我们放弃了常见的 `VMCALL`，而是选择了 `INT3`。虽然这看起来有点“非主流”，但通过对比可以发现它的独特优势：

| **特性** | **INT3** | **VMCALL** |
| --- | --- | --- |
| **兼容性** | ✅ 通吃所有 x86 架构 | ⚠️ 通常需要虚拟化扩展支持 |
| **隐蔽性** | ✅ 普通单字节指令 (0xCC) | ❌ 显式的 Hypercall，特征明显 |
| **寄存器占用** | ✅ 不占用 RAX | ❌ 往往占用 RAX 传递调用号 |

最关键的是，INT3 不占用 `RAX`，这让我们能够用 RAX 来传递“**魔数 (Magic Number)**”以区分不同的回调类型。

---

## 3\. 核心技术详解

### 3.1 尝试“隐形”：基于 EPT 的 Hook 实现

如何在代码段插入 `INT3` 却不被 发现？我们利用了 EPT 的“**双视图**”特性：让 Guest 读的时候看原始页，执行的时候走影子页。 以下是我们实现该逻辑的核心伪代码：

```c
// 数据结构：隐形补丁上下文
struct stealth_hook {
    uint64_t    target_addr;        // 目标指令地址
    uint8_t     original_bytes[16]; // 原始指令
    uint8_t     original_len;       // 原始长度
    void* ept_entry;          // EPT 表项句柄
    bool        installed;          // 是否已安装
}

// 安装隐形补丁的逻辑
function install_stealth_hook(hook, target_addr) {
    // 1. 保存原始指令，防止破坏逻辑
    hook.target_addr = target_addr
    guest_read_memory(target_addr, hook.original_bytes, 16)
    hook.original_len = disasm_get_instruction_length(hook.original_bytes)

    // 2. 分配影子页（Shadow Page）
    shadow_page = allocate_physical_page()

    // 3. 复制整页内容到影子页（先保证内容一致）
    original_page = get_guest_physical_page(target_addr)
    copy_page(shadow_page, original_page)

    // 4. 在影子页中写入 INT3（这是真正执行的代码）
    offset_in_page = target_addr & 0xFFF
    shadow_page[offset_in_page] = 0xCC    // INT3

    // 5. 修改 EPT 执行权限：执行时映射到影子页
    ept_remap_execute(target_addr, shadow_page)

    // 6. 保持 EPT 读写权限：读写时依然映射到原始页
    ept_keep_read_write(target_addr, original_page)

    hook.installed = true
}
```

### 3.2 Payload 格式与编译

为了让注入的代码能像“插件”一样被加载，代码必须是**位置无关 (PIC)** 的，且需要一个协议头来告诉 Hypervisor 入口和出口在哪里。

**Header 设计：**

```c
struct payload_header {
    uint32_t    magic;          // 魔数：0x494E4A43 ("INJC")
    uint16_t    entry_offset;   // 入口点偏移
    uint16_t    exit_offset;    // 退出点偏移
    uint16_t    code_size;      // 代码大小
    uint64_t    runtime_addr;   // 运行时地址（由 Hypervisor 填充）
} __attribute__((packed));
```

**Linker Script (关键部分)：**

这是生成可用 Payload 的关键，我们需要精确控制内存布局：

```c
/* payload.ld - 位置无关 Payload 的链接脚本 */
OUTPUT_FORMAT("binary")

SECTIONS
{
    . = 0x0000;
    
    /* 头部：固定 18 字节 */
    .header : ALIGN(1) {
        LONG(0x494E4A43)            /* magic */
        SHORT(_entry - _start)      /* entry_offset */
        SHORT(_exit - _start)       /* exit_offset */
        SHORT(_code_end - _entry)   /* code_size */
        QUAD(0)                     /* runtime_addr (待填充) */
    }

    /* 数据段：存放运行时参数 */
    .data : ALIGN(1) { *(.data .data.*) }

    /* 入口段：Trampoline 代码 */
    .entry : ALIGN(1) {
        _entry = .;
        *(.entry .entry.*)
    }

    /* 代码段：主逻辑 */
    .text : ALIGN(1) {
        *(.text .text.*)
        _code_end = .;
    }

    /* 退出标记：INT3 */
    .exit : ALIGN(1) { _exit = .; }

    /DISCARD/ : { *(.note.* .comment .eh_frame) }
    _start = 0;
}
```

### 3.3 寻找完美的劫持点

我们选择 **Syscall 入口 (**`entry_SYSCALL_64`) 作为劫持点，因为它是必经之路。但为了系统稳定性，我们特意避开了 `STI` 指令之前的区域。

**查找逻辑：**

```c
// 在 syscall 入口路径中查找合适的 hook 点
function find_hook_point(syscall_entry_addr) {
    current_addr = syscall_entry_addr
    sti_found = false

    while current_addr < syscall_entry_addr + 0x1000 {
        instruction = disasm(current_addr)

        if !sti_found {
            // 必须先找到 STI（开中断）
            if instruction.type == INST_STI { sti_found = true }
        } else {
            // 在 STI 之后，找第一条非条件跳转指令，确保能安全返回
            if instruction.length >= 1 && !instruction.is_conditional {
                return current_addr
            }
        }
        current_addr += instruction.length
    }
    return NULL;
}
```

### 3.4 Guest-Hypervisor 通信设计

Guest 里的代码怎么跟外面的 Hypervisor 说话？我们设计了一套基于寄存器传参的简易协议。

**Guest 端实现 (payload.c)：**

```c
// 数据段：由 Hypervisor 填充实际地址和魔数
struct payload_data {
    uint64_t hypercall_magic;
    uint64_t completion_magic;
    uint64_t error_magic;
    void* (*module_alloc)(size_t size);
    // ... 其他内核函数指针
} __attribute__((section(".data")));

// Hypercall 封装
macro hypercall_2(magic, arg1, arg2) {
    register uint64_t _rax asm("rax") = magic;
    register uint64_t _r8  asm("r8")  = arg1;
    register uint64_t _r9  asm("r9")  = arg2;
    asm volatile("int3" : "+r"(_rax) : "r"(_r8), "r"(_r9));
}

// 主逻辑示例
function main_logic() {
    // 1. 在 Guest 内部分配内存
    void *ptr = g_data.module_alloc(1024);

    // 2. 告诉 Hypervisor 分配结果
    hypercall_2(g_data.hypercall_magic, ptr, 0);

    // 3. 任务完成，通知退出
    register uint64_t _rax asm("rax") = g_data.completion_magic;
    asm volatile("int3" : "+r"(_rax));
}
```

**Hypervisor 端处理 (handle\_vm\_exit)：**

```c
function handle_payload_breakpoint(ctx, guest_rip) {
    magic = read_guest_register(RAX); // 检查魔数

    if magic == ctx.magic.hypercall {
        // 处理调用请求
        arg1 = read_guest_register(R8);
        process_hypercall(arg1);
        return HANDLED;
    }
    
    if magic == ctx.magic.completion {
        // 处理完成信号
        cleanup_payload(ctx);
        return HANDLED;
    }
    
    // ... 处理错误或退出
}
```

---

## 4\. 完整实现流程

### 4.1 注入与激活

这是整个流程中最关键的一步，涉及内存分配、符号解析和补丁安装。

```c
// injection_manager.c

function inject_payload(payload_type) {
    // 1. 准备上下文
    ctx = allocate(struct payload_context);
    ctx.raw_data = get_payload_binary(payload_type);
    
    // 2. 动态生成本次会话的魔数 (增强安全性)
    ctx.magic.hypercall   = generate_magic_number();
    
    // 3. 填充 Payload 数据段 (把外部世界的知识传进去)
    // 填魔数
    write_payload_data(ctx, offset, &ctx.magic.hypercall, 8);
    // 填内核函数地址 (通过 kallsyms 查找)
    addr_alloc = find_kernel_symbol("module_alloc");
    write_payload_data(ctx, offset, &addr_alloc, 8);

    // 4. 在 Guest 内存缝隙 (Slack Space) 中写入 Payload
    ctx.payload_addr = allocate_guest_slack_space(ctx.raw_size);
    guest_write_memory(ctx.payload_addr, ctx.raw_data, ctx.raw_size);

    // 5. 找到并安装 Hook
    syscall_entry = find_kernel_symbol("entry_SYSCALL_64");
    hook_addr = find_hook_point(syscall_entry);
    install_stealth_hook(&ctx.hook, hook_addr);

    // 6. 激活
    list_add(&g_active_payloads, ctx);
}
```

### 4.2 执行与通信

当 Guest 触发 Hook 时的处理逻辑：

```c
// 当 Guest 触发 Hook 点的 INT3
function start_payload_execution(ctx) {
    // 1. 临时卸载 Hook，恢复原始指令，防止重入或死锁
    uninstall_stealth_hook(&ctx.hook);

    // 2. 计算 Payload 入口地址
    entry_addr = ctx.payload_addr + ctx.header.entry_offset;

    // 3. 简单粗暴：直接修改 RIP 寄存器
    guest_rip = read_guest_register(RIP);
    write_guest_register(RIP, entry_addr);

    // 4. Guest 继续跑，下一条指令就是我们的 trampoline
    return SKIP_INSTRUCTION;
}
```

### 4.3 退出与清理

Payload 跑完后的“擦屁股”工作同样重要，不能留下痕迹。

```c
function cleanup_payload(ctx) {
    // 1. 将 RIP 拨回最初的 Hook 点 (模拟原始 syscall 路径)
    original_rip = ctx.hook.target_addr;
    write_guest_register(RIP, original_rip);

    // 2. 释放占用的 Guest 内存
    free_guest_slack_space(ctx.payload_addr, ctx.raw_size);

    // 3. 销毁上下文
    list_remove(&g_active_payloads, ctx);
    free(ctx);

    // Guest 会认为刚才只是做了一次普通的 syscall
    return SKIP_INSTRUCTION;
}
```

---

## 5\. 小结

本文介绍了一套基于 Hypervisor 的内核代码注入方案，核心技术包括：

* **EPT 双视图**：实现隐蔽 Hook
    
* **PIE + Linker Script**：支持任意地址加载
    
* **INT3 + Magic Number**：Guest-Host 通信
    
* **Slack Space + RIP 劫持**：临时执行与清理
    

> 本文部分技术思路参考了 Bitdefender HVMI 等开源 VMI 项目的设计模式。文中所有伪代码和实现细节为作者原创整理。
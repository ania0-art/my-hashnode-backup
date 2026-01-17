---
title: "记一次虚拟化下的detour框架实现"
datePublished: Sat Jan 17 2026 09:24:17 GMT+0000 (Coordinated Universal Time)
cuid: cmki3p3c3000602l1evytbr2t
slug: detour
tags: csharp, linux, virtualization, cybersecurity, systemprogramming

---

# 1.Detour机制基础

## 1.1 什么是Detour？

在虚拟化安全监控领域，我们经常需要监控Guest OS内部的关键操作——进程创建、权限提升、内存映射变化等。传统的EPT（Extended Page Table）监控虽然可以捕获内存访问，但存在明显的局限性：

* 语义鸿沟：从"某个地址被写入"推断"进程被创建"需要复杂的分析
    
* 性能开销：细粒度的内存监控会产生大量VM-Exit
    
* 覆盖盲区：纯寄存器操作、链表修改等无法通过内存监控捕获
    

因此，我们需要一种更直接的方法：在关键函数的入口和出口插入监控代码。这就是Detour（函数劫持）技术。

## 1.2 基本原理：五字节的魔法

Detour的核心思想非常简单：修改目标函数的开头几个字节，插入一条跳转指令。 在x86-64架构中，一条相对跳转指令只需要5个字节： E9 XX XX XX XX # jmp rel32 (相对跳转) 这5个字节可以跳转到±2GB范围内的任意地址，对于内核空间来说完全够用。 原理示意：

```plaintext
  # 原始函数
  target_function:
      55                # push rbp
      48 89 e5              # mov rbp, rsp
      48 83 ec 20           # sub rsp, 0x20
      ...
  # 修改后
  target_function:
      E9 XX XX XX XX        # jmp <our_handler>
      ...                   # 后续代码保持不变
```

当程序调用这个函数时，CPU执行到第一条指令就会跳转到我们的Handler代码，从而实现监控。

## 1.3 虚拟化环境的特殊性

在虚拟化环境中实现Detour，与传统的用户态Hook有本质区别：

### 1.3.1 跨特权级操作

* **传统 Detour**：Ring 3 (用户态) → Hook → Ring 3。
    
* **虚拟化 Detour**：Ring -1 (Hypervisor) → 注入代码 → Ring 0 (Guest 内核)。
    

这带来了一个复杂的架构问题：代码是由 Hypervisor 注入的，但必须运行在 Guest 的上下文中。我们需要通过 **VM-Exit** 机制在两个世界之间传递信息。

### 1.3.2 透明性要求

恶意软件可能会检测自己是否被监控：

```c
  // 恶意软件的反调试代码
  void check_hook(void) {
      unsigned char *func = (unsigned char *)target_function;

      if (func[0] == 0xE9) {  // 检测jmp指令
          printk("Detected hook! Exiting...\n");
          do_exit(-1);
      }
  }
```

因此，我们必须实现双重视图：

* Guest 读取函数代码 → 看到原始内容（55 48 89 e5...）
    
* Guest 执行函数代码 → 实际执行修改后的代码（E9 XX XX XX XX） 这需要利用EPT机制实现内存隐藏（Memory Cloaking）。
    

## 1.4 三层架构设计

经过思考和实践，可以使用一个三层架构来实现完整的Detour机制： 第一层：Guest Handler（注入代码层） 这是在Guest内核空间注入的轻量级代码，核心任务： 提取函数参数（从寄存器/栈） 触发VM-Exit（通过VMCALL或INT3指令） 执行被覆盖的原始指令 跳回原函数继续执行 代码结构示例：

```plaintext
  handler_code:
      # 1. 保存上下文（如果需要）
      push rax
      push rdi
      # 2. 准备参数（从寄存器读取）
      mov rax, rdi              # 参数1
      mov rsi, rsi              # 参数2
      
      # 3. 触发VM-Exit
      vmcall    # 特权指令，触发陷入
      
      # 4. 恢复上下文
      pop rdi
      pop rax
      
      # 5. 执行原始指令（被覆盖的部分）
  relocated_code:
      push rbp
      mov rbp, rsp

      # 6. 跳回原函数
      jmp target_function+5
```

第二层：Hypervisor Callback（分析决策层） 这是在Hypervisor中运行的安全分析代码，拥有完整的系统视图和分析能力。 核心任务： 捕获VM-Exit事件 从VMCS/寄存器提取参数 执行安全策略检查 维护追踪状态 做出决策（允许/阻止/修改） 处理流程示例：

```c
  // Hypervisor中的回调函数
  int handle_target_function(void *context) {
      // 1. 提取参数
      uint64_t arg1 = get_register(RDI);
      uint64_t arg2 = get_register(RSI);

      // 2. 读取Guest内存（如果需要）
      char buffer[256];
      read_guest_memory(arg1, buffer, sizeof(buffer));

      // 3. 安全分析
      if (is_malicious_operation(buffer)) {
          // 记录告警
          log_alert("Detected malicious operation");

          // 阻止操作
          inject_error_to_guest(-EPERM);
          return BLOCK_OPERATION;
      }

      // 4. 更新追踪状态
      update_tracking_state(arg1, arg2);

      // 5. 允许操作继续
      return ALLOW_OPERATION;
  }
```

第三层：Framework（基础设施层） 这是负责整个Detour生命周期的管理框架。 核心功能： Hook设置

```c
  // 伪代码示例
  int setup_detour(uint64_t target_addr, void *callback) {
      // 1.1 定位目标函数
      uint64_t func_addr = resolve_function_address(target_addr);

      // 1.2 分配Handler内存（在Guest空间）
      uint64_t handler_addr = allocate_guest_memory(HANDLER_SIZE);

      // 1.3 生成Handler代码
      generate_handler_code(handler_addr, callback);

      // 1.4 重定位原始指令
      relocate_original_instructions(func_addr, handler_addr);

      // 1.5 修改目标函数（插入jmp）
      write_jump_instruction(func_addr, handler_addr);

      // 1.6 设置内存隐藏
      setup_memory_cloaking(func_addr, 5);

      return 0;
  }
```

# 2.detour以及相关技术实现

## 2.1 Hook设置：四个关键步骤

实现Detour需要完成四个核心步骤。

### 步骤1：定位目标函数

根据函数是否导出，有两种定位方法：

```c
  // 导出函数：通过符号表直接查找
  // 解析内核符号表（ELF/PE格式）
  uint64_t addr = lookup_symbol("target_function");
  // 未导出函数：通过代码特征匹配
  // 定义字节模式
  pattern = "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10";
  mask= "xxxxxxxxxx";  // x=精确匹配，?=任意
  // 在内核代码段扫描
  uint64_t addr = scan_pattern(kernel_text_start, kernel_text_end,pattern, mask);
```

### 步骤2：生成Handler代码

Handler是注入到Guest的轻量级代码，结构固定：

```c
  handler_code:
      # 1. 参数准备（利用调用约定）
      mov rdi, <detour_id>      # 标识符
      # arg1, arg2已在RSI, RDX中
      # 2. 触发VM-Exit
      vmcall
      # 3. 执行被覆盖的原始指令
      <relocated_instructions>
      # 4. 跳回原函数
      jmp<target_function + N>
```

### 步骤3：指令重定位

由于jmp指令覆盖了原函数的前5字节，必须把这些指令复制到Handler中执行。 核心挑战在于：不能简单复制字节，因为指令可能包含：

* RIP-relative寻址：mov rax, \[rip+0x1234\]
    
* 相对跳转：jmp +0x20 解决方案：
    

```c
  // 1. 反汇编原始指令
  while (total_length < 5) {
      decode_instruction(&instr, code + offset);
      total_length += instr.length;
  }

  // 2. 重定位RIP-relative指令
  if (instr.is_rip_relative) {
      // 计算原始目标地址
      target = old_rip + instr.length + instr.offset;

      // 计算新的偏移
      new_offset = target - (new_rip + instr.length);

      // 修改指令中的偏移字段
      patch_instruction_offset(&instr, new_offset);
  }

  // 3. 写入Handler
  write_relocated_code(handler_addr, relocated_code);
```

### 步骤4：修改原函数

最后一步是将jmp指令写入目标函数：

```c
  // 生成jmp指令（5字节）
  jmp_code[0] = 0xE9;  // opcode
  *(int32_t *)&jmp_code[1] = handler_addr - (target_addr + 5);

  // 原子性写入（避免多核竞态）
  pause_all_vcpus();
  write_guest_memory(target_addr, jmp_code, 5);
  resume_all_vcpus();
```

原子性保证：

* 方法1：暂停所有VCPU
    
* 方法2：使用INT3断点过渡（先写0xCC，再写完整jmp） 至此，Hook设置完成。
    

## 2.2 Memory Cloaking：实现透明性

Memory Cloaking让Guest读取函数代码时看到原始内容，但执行时运行修改后的代码。

### 2.2.1 双重视图原理

利用EPT（Extended Page Table）机制实现读写分离： EPT权限配置：

```plaintext
  ┌─────────────┬──────────────┬──────────────┐
  │访问类型      │ EPT权限      │ 处理方式      │
  ├─────────────┼──────────────┼──────────────┤
  │ Read        │ Hook         │ 返回原始内容  │
  │ Write       │ Hook         │ 阻止修改      │
  │ Execute     │ Allow        │ 执行修改内容  │
  └─────────────┴──────────────┴──────────────┘
```

实现：

```c
  // 1. 设置EPT Hook
  set_ept_permissions(gpa, length,EPT_READ_HOOK | EPT_WRITE_HOOK,// Hook读写
                     EPT_EXEC_ALLOW);                  // 允许执行

  // 2. 保存双份内容
  cloak->original = {0x55, 0x48, 0x89, 0xE5, ...};  // 原始
  cloak->patched  = {0xE9, 0xXX, 0xXX, 0xXX, ...};  // 修改后

  // 3. 注册EPT Violation处理
  register_ept_handler(gpa, handle_cloaked_access);
```

### 2.2.2 EPT Violation处理

当Guest读取被隐藏的内存时：

```c
  int handle_cloaked_read(ept_violation_t *vio) {
      // 1. 查找Cloak
      cloak = find_cloak(vio->gpa);

      // 2. 解码读取指令
      decode_instruction(vio->rip, &instr);
      // 例如：mov rax, [addr]

      // 3. 用原始内容模拟执行
      uint32_t offset = vio->gpa - cloak->gpa;
      data = cloak->original[offset];
      set_guest_register(instr.dest_reg, data);

      // 4. 推进RIP
      advance_rip(instr.length);

      return HANDLED;
  }
```

# 3.1Detour类型与应用

## 3.1 简单型Detour

用途：只需要知道函数被调用，不关心返回值。 实现结构

```c
  handler:
      # 1. 提取参数
      mov rdi, <detour_id>
      # arg1, arg2 已在RSI, RDX

      # 2. 触发通知
      vmcall

      # 3. 执行原始指令
      <relocated_code>

      # 4. 跳回
      jmp target_function + N
```

## 3.2 返回型Detour

用途：需要获取函数返回值，确认操作是否成功。 实现结构

```c
  entry_handler:
      # 1. 保存上下文
      push <saved_params>
      
      # 2. Entry回调
      call pre_function
      vmcall

      # 3. 检查是否需要return hook
      cmp [rsp], 0
      jg skip_return

      # 4. 劫持返回地址
      lea rax, [return_handler]
      mov [rsp + offset], rax

  skip_return:
      <relocated_code>
      jmp target_function + N

  return_handler:
      # 5. Return回调（RAX=返回值）
      call function_return
      vmcall

      # 6. 清理并返回
      add rsp, <size>
      ret
```

## 3.3 参数覆盖型Detour

用途：修改函数参数，改变函数行为。 实现结构

```c
  handler:
      # 1. 调用处理函数
      push rax
      call modify_function

      # 2. 用返回值覆盖参数寄存器
      mov rdi, rax  # 覆盖第一个参数
      pop rax
      # 3. 执行原始指令
      <relocated_code>
      jmp target_function + N
```

## 3.4 条件跳过型Detour

用途：根据条件决定是否执行原函数，实现操作阻止。 实现结构

```c
  handler:
      # 1. 调用判断函数
      push rax
      call check_function
      test eax, eax
      jnz skip_original# 非0=跳过原函数
      pop rax

      # 2. 执行原函数
      <relocated_code>
      jmp target_function + N

  skip_original:
      # 3. 直接返回（不执行原函数）
      pop rax
      ret
```

# 4.实践心得

## 4.1 性能优化

Detour机制的性能瓶颈主要在VM-Exit，每次VM-Exit的开销约为1000-5000个CPU周期。

### 4.1.1 减少VM-Exit频率

策略1：避免Hook高频函数

```c
  //  不好的选择
  hook_function("kmalloc");
  hook_function("mutex_lock");  

  //  好的选择
  hook_function("do_execve");    
  hook_function("commit_creds");
```

策略2：批量处理

```c
  // 在一次VM-Exit中处理多个事件
  void handle_vmcall(void) {
      // 收集多个待处理事件
      event_t events[MAX_BATCH];
      int count = collect_pending_events(events, MAX_BATCH);

      // 批量处理
      for (int i = 0; i < count; i++) {
          process_event(&events[i]);
      }
  }
```

### 4.1.2 优化Guest Handler

原则：Handler代码越小越快

```c
  # 低效的Handler
  handler:
      push rax
      push rbx
      push rcx
      push rdx
      push rsi
      push rdi
      # ... 保存所有寄存器
      call complex_function
      # ... 恢复所有寄存器
      vmcall

  #  高效的Handler
  handler:
      # 只保存必要的寄存器
      push rax
      mov rdi, <id>
      vmcall
      pop rax
```

## 4.2 稳定性保证

Detour运行在内核层，任何错误都可能导致Guest崩溃。

### 4.2.1 指令重定位验证

问题：重定位错误会导致立即崩溃

```c
  // 验证重定位结果
  bool verify_relocation(uint8_t *original, uint8_t *relocated,uint64_t old_addr, uint64_t new_addr) {
      // 1. 反汇编两份代码
      instruction_t orig_instrs[16], reloc_instrs[16];
      int orig_count = disassemble_all(original, orig_instrs);
      int reloc_count = disassemble_all(relocated, reloc_instrs);

      if (orig_count != reloc_count) {
          return false;  // 指令数量不匹配
      }

      // 2. 验证每条指令
      for (int i = 0; i < orig_count; i++) {
          if (!verify_instruction_equivalence(&orig_instrs[i],
                                             &reloc_instrs[i],
                                             old_addr, new_addr)) {
              return false;
          }
      }

      return true;
  }
```

4.2.2 并发安全

问题：多个VCPU可能同时触发同一个Hook

```c
  //  不安全的实现
  void handle_event(void) {
      global_counter++;  // 竞态条件！
      process_data(shared_buffer);  // 数据竞争！
  }

  //  安全的实现
  void handle_event(void) {
      // 方法1：使用原子操作
      atomic_inc(&global_counter);

      // 方法2：使用per-VCPU数据
      vcpu_data[current_vcpu_id].counter++;

      // 方法3：使用锁（注意性能）
      spin_lock(&event_lock);
      process_data(shared_buffer);
      spin_unlock(&event_lock);
  }
```

## 4.3 常见陷阱

在具体实践中，我遇到过很多容易犯的错误。

### 4.3.1 指令边界问题

陷阱：jmp指令可能覆盖到指令中间

```c
  #原始代码
  target_function:
      48 8B 05 12 34 56 78  # mov rax, [rip+0x78563412]  (7字节)
      90# nop                         (1字节)

  # ❌ 错误：只覆盖5字节
  target_function:
      E9 XX XX XX XX        # jmp handler (5字节)
      5678                 # 残留字节！90                    # nop
  #如果有代码跳转到+5位置，会执行到残留字节，导致崩溃
```

解决方案：

```c
  // 确保覆盖完整指令
  int calculate_patch_size(uint64_t addr) {
      int total = 0;
      while (total < 5) {
          instruction_t instr;
          decode_instruction(addr + total, &instr);
          total += instr.length;
      }
      return total;  // 可能是5, 6, 7...字节
  }

  // 用NOP填充多余空间
  void patch_function_safe(uint64_t addr, uint64_t handler) {
      int patch_size = calculate_patch_size(addr);

      uint8_t code[16];
      code[0] = 0xE9;  // jmp
      *(uint32_t *)&code[1] = handler - (addr + 5);

      // 填充NOP
      for (int i = 5; i < patch_size; i++) {
          code[i] = 0x90;  // nop
      }

      write_guest_memory(addr, code, patch_size);
  }
```

4.3.2 栈对齐问题 陷阱：x86-64要求栈16字节对齐

```c
  // 错误：栈未对齐
  handler:
      push rax              # RSP -= 8（现在是8字节对齐）
      call some_function    # 调用函数要求16字节对齐！
      #崩溃：某些SSE指令要求对齐访问

  // 正确：保持对齐
  handler:
      push rax              # RSP -= 8
      sub rsp, 8            # RSP -= 8（现在是16字节对齐）
      call some_function
      add rsp, 8
      pop rax
```

检查对齐：

```c
  void verify_stack_alignment(void) {
      uint64_t rsp = get_guest_rsp();
      if (rsp & 0xF) {
          log_error("Stack misaligned: RSP=%llx", rsp);
      }
  }
```

### 4.3.3 寄存器污染

陷阱：Handler修改了不该修改的寄存器

```c
  #  错误：破坏了RCX
  handler:
      mov rcx, <detour_id>  # 覆盖了原函数的参数！
      vmcall
      <relocated_code>

  #  正确：保存和恢复
  handler:
      push rcx              # 保存
      mov rcx, <detour_id>
      vmcall
      pop rcx               # 恢复
      <relocated_code>
```

# 5.总结

Detour 机制是虚拟化安全监控的基石。通过构建“Guest Handler + Hypervisor Callback”的三层架构，并配合 EPT 内存隐藏，我们可以在不修改 Guest OS 源码的情况下，实现对内核行为的细粒度监控。

如果你感兴趣，下一篇文章可以详细说明一下如何将代码注入到guest os中
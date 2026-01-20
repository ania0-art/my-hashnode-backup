---
title: "记一次实现minivmi"
datePublished: Tue Jan 20 2026 14:53:35 GMT+0000 (Coordinated Universal Time)
cuid: cmkmps50v000c02jp3fota8rq
slug: minivmi
tags: c, virtual-machine, linux, xen

---

我已经验证了运行结果：

* `sudo ./list_domains` 可以列出 dom0 + guest，并拿到 guest 的 `uuid`
    
* `sudo ./cr3trace_uuid --uuid <uuid>` 可以持续打印 CR3 写入事件（含 old/new CR3、RIP）
    
* 项目位置：[minivmi](https://github.com/ania0-art/minivmi)
    

```shell
luckybird@luckybird:~/vmi_test/minivmi/_build/bin$ sudo ./list_domains
count=2
domid=0 hvm=no dying=no shutdown=no name='Domain-0' uuid=''
domid=5 hvm=yes dying=no shutdown=no name='ubuntu2204' uuid='d5448ca1-abfc-45cd-9566-718742f51fb3'
luckybird@luckybird:~/vmi_test/minivmi/_build/bin$ sudo ./cr3trace_uuid --uuid d5448ca1-abfc-45cd-9566-718742f51fb3
attach uuid=d5448ca1-abfc-45cd-9566-718742f51fb3 domid=5
monitor started (Ctrl+C to stop)
domid=5 uuid=d5448ca1-abfc-45cd-9566-718742f51fb3 vcpu=1 old=0x1812002 new=0x3250c006 rip=0xffffffff946a7c4c
domid=5 uuid=d5448ca1-abfc-45cd-9566-718742f51fb3 vcpu=1 old=0x3250c006 new=0x3250d806 rip=0xffffffff95400213
domid=5 uuid=d5448ca1-abfc-45cd-9566-718742f51fb3 vcpu=1 old=0x3250d806 new=0x3250c006 rip=0xffffffff9540009d
domid=5 uuid=d5448ca1-abfc-45cd-9566-718742f51fb3 vcpu=1 old=0x3250c006 new=0x3250d806 rip=0xffffffff95400213
```

## 1\. minivmi架构

minivmi 的策略是：**直接调用 Xen 的公开 C API**，把“必要的系统边界”明明白白露出来：

* `libxc`（`<xenctrl.h>`）：枚举 domain、开启 vm\_event、配置 ctrlreg 监控
    
* `xenstore`（`<xenstore.h>`）：读 `/local/domain/<domid>/...` 补齐 name/uuid
    
* `xenevtchn`（`<xenevtchn.h>`）：event channel 通知，让用户态知道 ring 有事件了 这三块拼起来，就是最小 VMI “底座”。
    

## 2\. Xen 上“监控 CR3”到底在监控什么：vm\_event + ring + evtchn

看到 CR3 事件并打印，背后的链路是：

1. **guest 写 CR3**（硬件虚拟化拦截点）触发 VMExit
    
2. Xen 生成一个 `vm_event_request` 写入共享内存（**vm\_event ring**）
    
3. Xen 通过 event channel（**evtchn**）通知 dom0 用户态：ring 有数据
    
4. dom0 用户态（minivmi）从 ring 读 request，处理后写回 response
    
5. minivmi 调 `notify`，Xen 收到 response 后**放行 guest 继续执行**
    

**关键点：sync 拦截是“必须写回 response 才能放行 guest”。** 所以 VMI 的本质不是“读到了什么”，而是 **“拦截—处理—响应—放行”闭环**。

## 3\. 列出 domain（发现目标 guest）

目标：确认环境可用、能识别目标 guest。

实现思路：

* 用 `libxc` 枚举 domain：拿到 `domid` + flags
    
* 用 `xenstore` 补齐 `name/uuid`：
    
    * `/local/domain/<domid>/name`
        
    * `/local/domain/<domid>/vm`（内容通常是 `"/vm/<uuid>"`）
        

### 3.1 关键代码（完整函数）

```c
int minivmi_domains_snapshot(struct minivmi_domain **out_domains,
                             size_t *out_count,
                             char *err, size_t err_len)
{
    if (!out_domains || !out_count) {
        set_err(err, err_len, "bad args");
        return -1;
    }
    *out_domains = NULL;
    *out_count = 0;

    xc_interface *xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        set_err(err, err_len, "xc_interface_open failed: %s", strerror(errno));
        return -1;
    }

    struct xs_handle *xs = xs_open(XS_OPEN_READONLY);
    if (!xs) {
        set_err(err, err_len, "xs_open failed: %s", strerror(errno));
        xc_interface_close(xch);
        return -1;
    }

    /* 第1步（域枚举）：通过一次 libxc hypercall 获取域列表。 */
    const unsigned int cap = 1024;
    xc_domaininfo_t *infos = calloc(cap, sizeof(*infos));
    if (!infos) {
        set_err(err, err_len, "oom");
        xs_close(xs);
        xc_interface_close(xch);
        return -1;
    }

    const int n = xc_domain_getinfolist(xch, 0, cap, infos);
    if (n < 0) {
        set_err(err, err_len, "xc_domain_getinfolist failed: %s", strerror(errno));
        free(infos);
        xs_close(xs);
        xc_interface_close(xch);
        return -1;
    }

    struct minivmi_domain *domains = calloc((size_t)n, sizeof(*domains));
    if (!domains) {
        set_err(err, err_len, "oom");
        free(infos);
        xs_close(xs);
        xc_interface_close(xch);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        const uint32_t domid = (uint32_t)infos[i].domain;
        domains[i].domid = domid;
        domains[i].xen_flags = infos[i].flags;

        /*
         * 第1步（补齐 name/uuid）：xenstore 的常见路径约定：
         * - /local/domain/<domid>/name  -> 可读名字
         * - /local/domain/<domid>/vm    -> "/vm/<uuid>"
         */
        char path[256];

        snprintf(path, sizeof(path), "/local/domain/%u/name", domid);
        char *name = xs_read_strdup(xs, path);
        if (name) {
            safe_copy(domains[i].name, sizeof(domains[i].name), name, strlen(name));
            free(name);
        }

        snprintf(path, sizeof(path), "/local/domain/%u/vm", domid);
        char *vm = xs_read_strdup(xs, path);
        if (vm) {
            const char *u = vm;
            if (strncmp(vm, "/vm/", 4) == 0) u = vm + 4; /* 去掉 "/vm/" 前缀 */
            safe_copy(domains[i].uuid, sizeof(domains[i].uuid), u, strlen(u));
            free(vm);
        }
    }

    free(infos);
    xs_close(xs);
    xc_interface_close(xch);

    *out_domains = domains;
    *out_count = (size_t)n;
    return 0;
}
```

### 3.2 运行验证

```shell
  #在 _build/bin/ 下执行：
  sudo ./list_domains
  #示例输出：
  count=2
  domid=0 hvm=no  ... name='Domain-0' uuid=''
  domid=5 hvm=yes ... name='ubuntu2204' uuid='d5448ca1-abfc-45cd-9566-718742f51fb3'
```

结论：目标 guest 的 uuid 已可用，后续建议按 uuid 定位（比 domid 更稳定）。

## 4\. attach（建立 vm\_event 通道）

attach 阶段的目标是：让 Xen 给我们一个 vm\_event ring，并通过 evtchn 通知我们。

流程：

1. ensure\_hvm\_domain()：确认目标域是 HVM 且存活
    
2. xc\_monitor\_enable()：开启 vm\_event，得到：
    
    * 一页共享 ring（mmap 到当前进程）
        
    * remote\_port（给 evtchn bind 用）
        
3. xenevtchn\_bind\_interdomain()：把 Xen 给的 port 绑定成 dom0 可监听的本地 port，并获取 fd
    
4. ring\_init\_back()：初始化共享 ring 与 back\_ring 视图
    

### 4.1 关键代码（完整函数）

```c
  struct minivmi_cr3_monitor *minivmi_cr3_monitor_open(uint32_t domid,
                                                       const char *uuid_hint,
                                                       char *err, size_t err_len)
  {
      /*
       * 第2步（attach）：建立一条“监控会话”。
       * - 验证目标域是 HVM 且存活
       * - 开启 vm_event（xc_monitor_enable）：拿到共享 ring 页 + 一个 remote evtchn port
       * - 建立 event channel（bind interdomain）：拿到本地 port + fd，用于 poll 等待事件
       */
      struct minivmi_cr3_monitor *m = calloc(1, sizeof(*m));
      if (!m) {
          set_err(err, err_len, "oom");
          return NULL;
      }

      m->domid = domid;
      if (uuid_hint && uuid_hint[0]) {
          safe_copy(m->uuid, sizeof(m->uuid), uuid_hint, strlen(uuid_hint));
      }

      m->ring_page_len = (unsigned long)getpagesize();

      m->xch = xc_interface_open(NULL, NULL, 0);
      if (!m->xch) {
          set_err(err, err_len, "xc_interface_open failed: %s", strerror(errno));
          minivmi_cr3_monitor_close(m);
          return NULL;
      }

      if (ensure_hvm_domain(m->xch, domid, err, err_len) != 0) {
          minivmi_cr3_monitor_close(m);
          return NULL;
      }

      /*
       * 第2步（关键 hypercall）：开启 vm_event。
       * - 返回值：一页 mmap 到本进程的共享内存（ring）
       * - out 参数：remote_port（给 xenevtchn_bind_interdomain 用）
       */
      m->ring_page = xc_monitor_enable(m->xch, domid, &m->remote_port);
      if (!m->ring_page) {
          set_err(err, err_len, "xc_monitor_enable failed for domid=%u: %s", domid, strerror(errno));
          minivmi_cr3_monitor_close(m);
          return NULL;
      }
      m->monitor_enabled = true;

      /*
       * 第2步（事件通道）：绑定 interdomain evtchn。
       * - vm_event ring 里有事件时，Xen 会通过 evtchn 唤醒 dom0 用户态
       * - 我们用 poll(fd) 等待它变为可读
       */
      m->xce = xenevtchn_open(NULL, 0);
      if (!m->xce) {
          set_err(err, err_len, "xenevtchn_open failed: %s", strerror(errno));
          minivmi_cr3_monitor_close(m);
          return NULL;
      }

      xenevtchn_port_or_error_t p = xenevtchn_bind_interdomain(m->xce, domid, m->remote_port);
      if (p < 0) {
          set_err(err, err_len, "xenevtchn_bind_interdomain failed: %s", strerror(errno));
          minivmi_cr3_monitor_close(m);
          return NULL;
      }
      m->local_port = (evtchn_port_t)p;

      m->evtchn_fd = xenevtchn_fd(m->xce);
      if (m->evtchn_fd < 0) {
          set_err(err, err_len, "xenevtchn_fd failed: %s", strerror(errno));
          minivmi_cr3_monitor_close(m);
          return NULL;
      }

      ring_init_back(m);
      return m;
  }
```

> 注意：同一个 domain 通常只能被一个 monitor 连接，否则 xc\_monitor\_enable() 可能返回 EBUSY。

## 5\. 开启 CR3 拦截点（monitor\_write\_ctrlreg）

vm\_event 是通道，下一步才是“拦截什么”。

```c
  int minivmi_cr3_monitor_enable(struct minivmi_cr3_monitor *m,
                                 char *err, size_t err_len)
  {
      if (!m) {
          set_err(err, err_len, "bad args");
          return -1;
      }

      /*
       * 第3步（配置拦截点）：让 Xen 在“写 CR3”时产生 vm_event 事件。
       * - sync=true：同步拦截（guest 在事件点暂停，直到我们写回 response）
       * - onchangeonly=true：只在 CR3 真变化时触发，减少噪声
       */
      const int rc = xc_monitor_write_ctrlreg(m->xch, m->domid,
                                             VM_EVENT_X86_CR3,
                                             true,  /* enable */
                                             true,  /* sync */
                                             0,     /* bitmask */
                                             true); /* onchangeonly */
      if (rc != 0) {
          set_err(err, err_len, "xc_monitor_write_ctrlreg(CR3) failed: %s", strerror(errno));
          return -1;
      }

      m->cr3_enabled = true;
      return 0;
  }
```

## 6\. 事件循环（读 ring → 回调 → 写回 response → 放行 guest）

这是整个 VMI 闭环的核心，也是“最小事件管理器”。

流程要点：

* poll(evtchn\_fd)：等待 Xen 通知
    
* xenevtchn\_pending()：消费通知（port 会被 mask）
    
* drain ring：把 ring 里所有 request 读完
    
* 写回 response 并 notify Xen 放行 guest
    
* unmask 继续收下一次通知
    

### 6.1 关键代码（完整核心循环）

```c
  int minivmi_cr3_monitor_loop(struct minivmi_cr3_monitor *m,
                               minivmi_cr3_cb cb,
                               void *user,
                               volatile sig_atomic_t *stop_flag,
                               char *err, size_t err_len)
  {
      if (!m || !cb || !stop_flag) {
          set_err(err, err_len, "bad args");
          return -1;
      }

      struct pollfd pfd;
      pfd.fd = m->evtchn_fd;
      pfd.events = POLLIN | POLLERR;

      while (!(*stop_flag)) {
          pfd.revents = 0;
          const int prc = poll(&pfd, 1, 200);
          if (prc < 0) {
              if (errno == EINTR) continue;
              set_err(err, err_len, "poll(evtchn) failed: %s", strerror(errno));
              return -1;
          }
          if (prc == 0) continue;

          /*
           * 第3步（等事件 + 消费通知）：
           * - poll(fd) 告诉我们“有 evtchn 通知到了”
           * - xenevtchn_pending() 取出哪个 port 触发，并进入 masked 状态
           * - 我们处理完 ring 后，必须 xenevtchn_unmask() 才能继续收下一次通知
           */
          const xenevtchn_port_or_error_t pend = xenevtchn_pending(m->xce);
          if (pend < 0) {
              set_err(err, err_len, "xenevtchn_pending failed: %s", strerror(errno));
              return -1;
          }

          int handled = 0;
          vm_event_request_t req;

          while (ring_pop_req(&m->back_ring, &req)) {
              /*
               * 第3步（写回 response）：默认做法是“原样回显”。
               * - 对 minivmi 这个最小 demo 来说：不改寄存器/不注入动作
               * - 只要写回 response 并 notify，Xen 就会放行 guest 继续执行
               */
              vm_event_response_t rsp = req;

              if (req.reason == VM_EVENT_REASON_WRITE_CTRLREG &&
                  req.u.write_ctrlreg.index == VM_EVENT_X86_CR3) {

                  struct minivmi_cr3_event ev;
                  memset(&ev, 0, sizeof(ev));
                  ev.domid = m->domid;
                  safe_copy(ev.uuid, sizeof(ev.uuid), m->uuid, strlen(m->uuid));
                  ev.vcpu = (uint16_t)req.vcpu_id;
                  ev.old_cr3 = req.u.write_ctrlreg.old_value;
                  ev.new_cr3 = req.u.write_ctrlreg.new_value;
                  ev.rip = req.data.regs.x86.rip;

                  /* 第3步（对外暴露）：把 CR3 事件交给用户回调。 */
                  cb(&ev, user);
              }

              ring_put_rsp(&m->back_ring, &rsp);
              handled++;
          }

          if (handled) {
              /*
               * 第3步（闭环完成）：push responses + notify Xen。
               */
              RING_PUSH_RESPONSES(&m->back_ring);
              if (xenevtchn_notify(m->xce, m->local_port) < 0) {
                  set_err(err, err_len, "xenevtchn_notify failed: %s", strerror(errno));
                  return -1;
              }
          }

          if (xenevtchn_unmask(m->xce, (evtchn_port_t)pend) < 0) {
              set_err(err, err_len, "xenevtchn_unmask failed: %s", strerror(errno));
              return -1;
          }
      }

      return 0;
  }
```
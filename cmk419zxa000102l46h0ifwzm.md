---
title: "记一次linux0.12段页式内存管理学习"
datePublished: Wed Jan 07 2026 13:07:47 GMT+0000 (Coordinated Universal Time)
cuid: cmk419zxa000102l46h0ifwzm
slug: linux012
tags: linux

---

## 0.说明

此次学习是通过翻阅《Linux内核完全注释》，部分图片出自该书

## **1.引导启动程序**

linux0.12版本中引导启动程序三个:实模式下的16位代码程序bootsect.S setup.S和保护模式下的head.s

总体而言当pc的电源打开后，80x86的cpu将自动进入实模式，并从地址0xFFFF0开始自动执行程序代码（ROM-BIOS）。BIOS将执行系统的某些硬件检测和诊断功能，并在物理地址0处开始设置和初始化中断向量。此后，它将磁盘引导扇区（bootsect.S）读入绝对地址0x7C00处，并跳转到这里开始引导启动机器运行。当bootsect.S被执行时就会把自己移动到内存绝对地址0x90000（576KB）处，并把启动设备盘中后2KB字节代码（boot/setup.S）读入到内存0x90200处。而内核的其他部分（system模块）则被读入到从内存地址0x10000（64KB）开始处。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790716333/f422fdca-f821-4261-ad7d-6c4452717622.png align="center")

setup程序将会把system模块移动到物理内存起始位置处，这样system模块中代码的地址也即等于实际的物理地址，便于对内核代码和数据进行操作。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790735691/d43f093a-54ca-459a-96fb-9aec40f7fc0d.png align="center")

将整个system从地址0x10000移至0x0000处，进入保护模式并跳转至系统的余下部分（在0x0000处）。到此时，所有32位运行方式的启动设置均已被完成: IDT、GDT以及LDT被加载，处理器和协处理器也已确认，分页工作也设置好了，最终会调用执行init/main.c中的main()代码。

**bootsect的代码为什么不把系统模块直接加载到物理地址0x0000开始处而要在setup程序中再进行移动呢？**这是因为随后执行的setup开始部分的代码还需要利用ROM BIOS提供的中断调用功能来获取有关机器配置的一些参数（例如显示卡模式、硬盘参数表等）。而当BIOS初始化时会在物理内存开始处放置一个大小为0x400字节(1KB)的中断向量表，直接把系统模块放在物理内存开始处将导致该中断向量表被覆盖掉。因此引导程序需要在使用完BIOS的中断调用后才能将这个区域覆盖掉。

### **bootsect.S**

在PC机加电、ROM BIOS自检后，ROM BIOS会把引导扇区代码bootsect加载到内存地址0x7C00开始处并执行之。在bootsect代码执行期间，它会将自己移动到**内存绝对地址0x90000**开始处并继续执行。该程序的主要作用是首先把从磁盘第2个扇区开始的4个扇区的**setup模块（由setup.s编译而成**）加载到内存紧接着bootsect后面位置处（0x90200），然后利用BIOS中断0x13取磁盘参数表中当前启动引导盘的参数，接着在屏幕上显示“Loading system...”字符串。再者把磁盘上setup模块后面的system模块加载到内存0x10000开始的地方。随后确定根文件系统的设备号。最后长跳转到setup程序开始处（0x90200）去执行setup程序。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790752250/c144b400-e703-4a52-914a-97acb5551b78.png align="center")

```plaintext
    mov ax,#BOOTSEG(0x7c0)
    mov ds,ax
    mov ax,#INITSEG(0x9000)
    mov es,ax
    mov cx,#256
    sub si,si
    sub di,di
    rep #重复递减cx，共512个字节
    movw
    jmpi    go,INITSEG
```

### **setup.S**

setup.S是一个操作系统加载程序，它的主要作用是**利用ROM BIOS中断读取机器系统数据，并将这些数据保存到0x90000开始的位置（覆盖掉了bootsect程序所在的地方）**

然后setup程序将system模块从0x10000-0x8ffff整块向下移动到内存绝对地址0x00000处。接下来**加载中断描述符表寄存器(IDTR)和全局描述符表寄存器(GDTR)**，开启A20地址线，重新设置两个中断控制芯片8259A，将硬件中断号重新设置为0x20 -0x2f。最后设置**CPU的控制寄存器CR0（也称机器状态字）**，进入**32位保护模式**运行，并跳转到位于system模块最前面部分的head.s程序继续运行。为了能让head.s在32位保护模式下运行，在本程序中**临时设置了中断描述符表（IDT）和全局描述符表（GDT），并在GDT中设置了当前内核代码段的描述符和数据段的描述符。**下面在head.s程序中还会根据内核的需要重新设置这些描述符表。

在setup.s程序执行结束后，系统模块system被移动到物理内存地址0x00000开始处，而从位置0x90000开始处则存放了内核将会使用的一些系统基本参数（**idt设置为空表**）

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790773563/305bab40-7367-46ca-a0d4-d2195a9b0034.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790788441/0040eb0c-25e4-4699-9b94-546c40356193.png align="center")

```plaintext
end_move:
    mov ax,#SETUPSEG    
    mov ds,ax
    lidt    idt_48      ! 加载idt,6字节 前俩字节描述符表的字节长度值，后4字节基地址
    lgdt    gdt_48      ! 加载gdt
gdt:                    #描述符表由多个8字节长的描述符项组成
    .word   0,0,0,0     ! dummy
    .word   0x07FF      ! 8Mb - limit=2047 (2048*4096=8Mb)
    .word   0x0000      ! base address=0
    .word   0x9A00      ! code read/exec  #代码段 0x08
    .word   0x00C0      ! granularity=4096, 386
    .word   0x07FF      ! 8Mb - limit=2047 (2048*4096=8Mb)
    .word   0x0000      ! base address=0
    .word   0x9200      ! data read/write #数据段 0x10
    .word   0x00C0      ! granularity=4096, 386
idt_48:
    .word   0           ! idt limit=0
    .word   0,0         ! idt base=0L
#加载gdtr的lgdt6字节操作数，前俩个是线长 后俩个是基地址
gdt_48:
    .word   0x800       ! gdt limit=2048, 256 GDT entries
    .word   512+gdt,0x9 ! gdt base = 0X90200+gdt
    
jmpi    0,8 #跳转到head.s 8-段选择符，0-描述符指定代码段中的偏移值
```

### **head.s**

head.s程序在**被编译生成目标文件后会与内核其他程序的目标文件一起被链接成system模块**，并位于system模块的最前面开始部分。

这段程序实际上处于内存绝对地址0处开始的地方。首先它加载各个**数据段寄存器**，重新设置**中断描述符表IDT**，共256项，并使各个表项均指向一个只报错误的哑中断子程序ignore\_int。这个哑中断向量指向一个默认的“ignore\_int”处理过程。**当发生了一个中断而又没有重新设置过该中断向量时就会显示信息“未知中断（Unknown interrupt）”**。这里对所有256项都进行设置可以有效防止出现一般保护性错误（A gerneal protection fault）(异常13)。否则的话，如果设置的IDT少于256项，那么在一个要求的中断所指定的描述符项大于设置的最大描述符项时，**CPU就会产生一个一般保护出错（异常13）。**另外，如果硬件出现问题而没有把设备的向量放到数据总线上，此时CPU通常会从数据总线上读入全1（0xff）作为向量，因此会去读取IDT表中的第256项，因此也会造成一般保护出错。对于系统中需要使用的一些中断，内核会在其继续初始化的处理过程中（init/main.c）重新设置这些中断的中断描述符项，让它们指向对应的实际处理过程。通常，异常中断处理过程（int0 --int 31）都在**traps.c**的初始化函数中进行了重新设置（kernl/traps.c，第185行），而系统调用中断int128则在调度程序初始化函数中进行了重新设置

在head.s程序中，**中断门描述符中段选择符字段被设置为0x0008**，表示该哑中断服务处理程序ignore\_int在内核代码中，而偏移值被设置为ignore\_int中断服务处理程序在head.s程序中的偏移值。在设置好中断描述符表之后，本程序又重新设置了**全局段描述符表GDT**。实际上新设置的GDT表与原来在setup.s程序中设置的GDT表描述符除了在段限长上有些区别以外（原为8MB，现为16MB），其他内容完全一样。因此这里重新设置GDT的主要原因是为了把GDT表放在内存内核代码比较合理的地方。

接着程序设置管理内存的分页处理机制，**将页目录表放在绝对物理地址0开始处**（也是本程序所处的物理内存位置，因此这段程序已执行部分将被覆盖掉），紧随后面会放置共可寻址16MB内存的4个页表，并分别设置它们的表项。

这里每个表项的属性标志都被设置成**0x07（P=1、U/S=1、R/W=1）**，表示该页存在、用户可读写。这样设置内核页表属性的原因是：**CPU的分段机制和分页管理都有保护方法**。分页机制中页目录表和页表项中设置的保护标志（U/S、R/W）需要与段描述符中的特权级（PL）保护机制一起组合使用。但段描述符中的PL起主要作用。CPU会首先检查段保护，然后再检查页保护。如果当前特权级CPL &lt; 3（例如0），则说明CPU正在以超级用户（Supervisor）身份运行。此时所有页面都能访问，并可随意进行内存读写操作。如果CPL = 3，则说明CPU正在以用户（User）身份运行。此时只有属于User的页面（U/S=1）可以访问，并且只有标记为可读写的页面（W/R = 1）是可写的。而此时属于超级用户的页面（U/S=0）则既不可写、也不可以读。由于内核代码有些特别之处，即其中包含有任务0和任务1的代码和数据。因此这里把页面属性设置为0x7就可以保证这两个任务代码能够在用户态下执行，但却又不能随意访问内核资源。

最后，head.s程序利用返回指令将预先放置在堆栈中的/init/main.c程序的入口地址弹出，去运行**main()程序**。

head.s程序执行结束后，内核代码就算已经正式完成了内存页目录和页表的设置，并重新设置了内核实际使用的中断描述符表IDT和全局描述符表GDT。另外，代码还为软盘驱动程序开辟了1KB字节的缓冲区。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790826124/12ecfe7b-09b2-4cc5-95e6-5becc448b234.png align="center")

```plaintext
call setup_idt
call setup_gdt
#指向ignore_int中断门
setup_idt:
    lea ignore_int,%edx
    movl $0x00080000,%eax
    movw %dx,%ax        /* selector = 0x0008 = cs */
    movw $0x8E00,%dx    /* interrupt gate - dpl=0, present */
    lea _idt,%edi        #_idt中断描述符表地址
    mov $256,%ecx
rp_sidt:
    movl %eax,(%edi)     #哑中断存入表中
    movl %edx,4(%edi)    #eax放入edi+4
    addl $8,%edi         #edi指向表中下一项
    dec %ecx
    jne rp_sidt
    lidt idt_descr
    ret
idt_descr:
    .word 256*8-1       # idt contains 256 entries
    .long _idt
_idt:   .fill 256,8,0       # idt is uninitialized
#重新设置gdt表
setup_gdt:
    lgdt gdt_descr
    ret
gdt_descr:
    .word 256*8-1       # so does gdt (not that that's any
    .long _gdt      # magic number, but it works for me :^)
_gdt:   .quad 0x0000000000000000    /* NULL descriptor */
    .quad 0x00c09a0000000fff    /* 16Mb */
    .quad 0x00c0920000000fff    /* 16Mb */
    .quad 0x0000000000000000    /* TEMPORARY - don't use */
    .fill 252,8,0           /* space for LDT's and TSS's etc */
#存放页表
.org 0x1000
pg0:
.org 0x2000
pg1:
.org 0x3000
pg2:
.org 0x4000
pg3:
#设置页表页目录
setup_paging:
    movl $1024*5,%ecx       /* 5 pages - pg_dir+4 page tables */
    xorl %eax,%eax
    xorl %edi,%edi          /* pg_dir is at 0x000 */
    cld;rep;stosl           #eax内容存到es:edi所指内存处，edi+4
    #设置页目录表
    movl $pg0+7,_pg_dir         /* set present bit/user r/w */ 0x00001007
    movl $pg1+7,_pg_dir+4       /*  --------- " " --------- */
    movl $pg2+7,_pg_dir+8       /*  --------- " " --------- */
    movl $pg3+7,_pg_dir+12      /*  --------- " " --------- */
    #设置页表 当前项目所映射的物理内存地址+该页的标志
    movl $pg3+4092,%edi
    movl $0xfff007,%eax     /*  16Mb - 4096 + 7 (r/w user,p) */
    std
1:  stosl           /* fill pages backwards - more efficient :-) */
    subl $0x1000,%eax
    jge 1b
    xorl %eax,%eax      /* pg_dir is at 0x0000 */
    movl %eax,%cr3      /* cr3 - page directory start */
    movl %cr0,%eax
    orl $0x80000000,%eax
    movl %eax,%cr0      /* set paging (PG) bit */
    ret         /* this also flushes prefetch-queue */
```

### **32位保护模式**

描述符表分为三种：**全局描述符表（GDT）、中断描述符表（IDT）和局部描述符表（LDT）**。当CPU运行在保护模式下，某一时刻GDT和IDT分别只能有一个，分别由寄存器GDTR和IDTR指定它们的表基址。局部表的个数可以有0个或最多8191个，这由GDT表中未用项数和所设计的具体系统确定。在某一个时刻，当前LDT表的基址由LDTR寄存器的内容指定，并且LDTR的内容使用GDT中某个描述符来加载，即LDT也是由GDT中的描述符来指定。

通常来说，内核对于每个任务（进程）使用一个LDT。在运行时，程序可以使用GDT中的描述符以及当前任务的LDT中的描述符。对于Linux 0.12内核来说同时可以有64个任务在执行，因此GDT表中最多有64个LDT表的描述符项存在。

中断描述符表IDT的结构与GDT类似，在Linux内核中它正好位于GDT表的前面。共含有256项8字节的描述符。但每个描述符项的格式与GDT的不同，其中存放着相应中断过程的偏移值（0-1，6-7字节）、所处段的选择符值（2-3字节）和一些标志（4-5字节）。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790861552/7faf7c41-bdda-4010-8355-85b2372a224f.png align="center")

每个任务在GDT中占有两个描述符项。GDT表中的LDT0描述符项是第一个任务（进程）的局部描述符表的描述符，TSS0是第一个任务的任务状态段（TSS）的描述符。每个LDT中含有三个描述符，其中第一个不用，第二个是任务代码段的描述符，第三个是任务数据段和堆栈段的描述符。

## **2.初始化程序init**

### **main函数**

main.c程序首先利用前面setup.s程序取得的**机器参数设置系统的根文件设备号以及一些内存全局变量。**这些内存变量指明了**主内存区的开始地址、系统所拥有的内存容量和作为高速缓冲区内存的末端地址**。如果还定义了虚拟盘（RAMDISK），则主内存区将适当减少。高速缓冲部分还需要扣除被显示卡显存和其BIOS占用的部分。高速缓冲是用于磁盘等块设备临时存放数据的地方，以1K（1024）字节为一个数据块单位。主内存区域的内存由内存管理模块mm通过分页机制进行管理分配，以4K（4096）字节为一个内存页单位。内核程序可以自由访问高速缓冲中的数据，但需要通过mm才能使用分配到的内存页面。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790880006/602b77b7-5166-43f1-a774-72684fdf4b49.png align="center")

内核进行各方面的硬件初始化工作。包括**陷阱门、块设备、字符设备和tty，还包括人工设置第一个任务（task 0）**。待所有初始化工作完成后，程序就设置中断允许标志以开启中断，并切换到任务0中运行。到此时，可以说内核已基本完成所有设置工作。接下来内核会通过任务0创建几个最初的任务，运行shell程序并显示命令行提示符，从而Linux系统进入正常运行阶段。

在整个内核完成初始化后，内核将执行控制权切换到了**用户模式（任务0）**，也即CPU从0特权级切换到了第3特权级。此时**main.c的主程序就工作在任务0中**。然后系统第一次调用进程创建函数fork()，创建出一个用于运行init()的子进程（通常被称为init进程）

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790900285/b39ea6b6-e97e-4452-a282-02a21c500fb2.png align="center")

main.c程序首先确定如何分配使用**系统物理内存**，然后调用内核各部分的初始化函数分别对**内存管理、中断处理、块设备和字符设备、进程管理以及硬盘和软盘硬件进行初始化处理**。在完成了这些操作之后，系统各部分已经处于可运行状态。此后程序把自己“手工”移动到任务0（进程0）中运行，并使用fork()调用首次创建出**进程1（init进程）**，并在其中调用init()函数。在该函数中程序将继续进行应用环境的初始化**并执行shell登录程序**。而原进程0则会在系统空闲时被调度执行，因此进程0通常也被称为idle进程。此时进程0仅执行pause()系统调用，并又会调用调度函数。

```plaintext
void main(void) 
{       
    .....
    trap_init();
    ......
    sched_init();
    ......
    if (!fork()) {      /* we count on this going ok */
        init();
    }
    ......
}
/*进程初始化*/
struct task_struct *current = &(init_task.task);
void sched_init(void)
{
    int i;
    struct desc_struct * p;
    ......
    /*在全局描述符表中设置任务0的tss和ldt,gdt--_gdt*/
    set_tss_desc(gdt+FIRST_TSS_ENTRY,&(init_task.task.tss));
    set_ldt_desc(gdt+FIRST_LDT_ENTRY,&(init_task.task.ldt));
    ......
    ltr(0);//在任务切换时自动改变
    lldt(0); //以后新任务的加载是cpu根据tss中的ldt项自动加载
    ......
}
#define set_tss_desc(n,addr) _set_tssldt_desc(((char *) (n)),addr,"0x89")
#define set_ldt_desc(n,addr) _set_tssldt_desc(((char *) (n)),addr,"0x82")
#define _set_tssldt_desc(n,addr,type) \
__asm__ ("movw $104,%1\n\t" \
    "movw %%ax,%2\n\t" \
    "rorl $16,%%eax\n\t" \
    "movb %%al,%3\n\t" \
    "movb $" type ",%4\n\t" \
    "movb $0x00,%5\n\t" \
    "movb %%ah,%6\n\t" \
    "rorl $16,%%eax" \
    ::"a" (addr), "m" (*(n)), "m" (*(n+2)), "m" (*(n+4)), \
     "m" (*(n+5)), "m" (*(n+6)), "m" (*(n+7)) \
    )
#define ltr(n) __asm__("ltr %%ax"::"a" (_TSS(n)))
#define lldt(n) __asm__("lldt %%ax"::"a" (_LDT(n)))
#define _TSS(n) ((((unsigned long) n)<<4)+(FIRST_TSS_ENTRY<<3))//一个描述符8字节长
#define _LDT(n) ((((unsigned long) n)<<4)+(FIRST_LDT_ENTRY<<3))
/*中断向量初始化*/
void trap_init(void)
{
    int i;
    set_trap_gate(0,&divide_error);
    ......
}
#define set_trap_gate(n,addr) \
    _set_gate(&idt[n],15,0,addr)
#define _set_gate(gate_addr,type,dpl,addr) \
__asm__ ("movw %%dx,%%ax\n\t" \
    "movw %0,%%dx\n\t" \
    "movl %%eax,%1\n\t" \
    "movl %%edx,%2" \
    : \
    : "i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
    "o" (*((char *) (gate_addr))), \
    "o" (*(4+(char *) (gate_addr))), \
    "d" ((char *) (addr)),"a" (0x00080000))
```

```plaintext
_sys_fork:
    call _find_empty_process
    testl %eax,%eax
    js 1f
    push %gs
    pushl %esi
    pushl %edi
    pushl %ebp
    pushl %eax
    call _copy_process
    addl $20,%esp
1:  ret
int copy_process(int nr,long ebp,long edi,long esi,long gs,long none,
        long ebx,long ecx,long edx, long orig_eax, 
        long fs,long es,long ds,
        long eip,long cs,long eflags,long esp,long ss)
{
    ......
    set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
    set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&(p->ldt));
    ......
}
```

### **init()函数**

可分为4个部分：①安装根文件系统；②显示系统信息；③运行系统初始资源配置文件rc中的命令；④执行用户登录shell程序。

1.安装根文件系统

代码首先调用系统调用setup()，用来收集硬盘设备分区表信息并安装根文件系统。在安装根文件系统之前，系统会先判断是否需要先建立虚拟盘。若编译内核时设置了虚拟盘的大小，并在前面内核初始化过程中已经开辟了一块内存用作虚拟盘，则内核就会首先尝试把根文件系统加载到内存的虚拟盘区中。

2.显示系统信息

然后init()打开一个终端设备tty0，并复制其文件描述符以产生标准输入stdin、标准输出stdout和错误输出stderr设备。内核随后利用这些描述符在终端上显示一些系统信息，例如高速缓冲区中缓冲块总数、主内存区空闲内存总字节数等。

3.执行资源配置文件

接着init()又新建了一个进程（进程2），并在其中为建立用户交互使用环境而执行一些初始配置操作，即在用户可以使用shell命令行环境之前，内核调用/bin/sh程序运行了配置文件etc/rc中设置的命令。rc文件的作用与DOS操作系统根目录上的AUTOEXEC.BAT文件类似。这段代码首先通过关闭文件描述符0，并立刻打开文件/etc/rc，从而把标准输入stdin定向到etc/rc文件上。这样，所有的标准输入数据都将从该文件中读取。然后内核以非交互形式执行/bin/sh，从而实现执行/etc/rc文件中的命令。当该文件中的命令执行完毕后，/bin/sh就会立刻退出。因此进程2也就随之结束。

4.执行登录shell程序

init()函数的最后一部份用于在新建进程中为用户建立一个新的会话，并运行用户登录shell程序/bin/sh。在系统执行进程2中的程序时，父进程（init进程）一直等待着它的结束。随着进程2的退出，父进程就进入到一个无限循环中。在该循环中，父进程会再次生成一个新进程，然后在该进程中创建一个新的会话，并以登录shell方式再次执行程序/bin/sh，以创建用户交互shell环境。然后父进程继续等待该子进程。虽然登录shell与前面的非交互式shell是同一个程序/bin/sh，但是所使用的命令行参数（argv\[\]）不同。登录shell的第0个命令行参数的第1个字符一定是一个减号'-'。这个特定的标志会在/bin/sh执行时通知它这不是一次普通的运行，而是作为登录shell运行/bin/sh的。从这时开始，用户就可以正常使用Linux命令行环境了，而父进程随之又进入等待状态。此后若用户在命令行上执行了exit或logout命令，那么在显示一条当前登录shell退出的信息后，系统就会在这个无限循环中再次重复以上创建登录shell进程的过程。

```plaintext
// include/init/main.c
void init(void)
{
    int pid, i;
    // setup()系统调用。用于读取硬盘参数包括分区表信息并加载虚拟盘（若存在的话）和安装根文件系统设备。
    setup((void *)&drive_info);
    // 以读写访问方式打开设备“/dev/tty0”，它对应终端控制台
    // 这里再把它以读和写的方式分别打开是为了复制产生标准输出句柄 stdout(1)和标准出错输出句柄 stderr(2)。 
    (void)open("/dev/tty1", O_RDWR, 0);
    (void)dup(0); // 复制句柄，产生句柄 1 号--stdout 标准输出设备
    (void)dup(0); // 复制句柄，产生句柄 2 号--stderr 标准出错输出设备
    // 下面打印缓冲区块数(每块 1024 字节)和总字节数，以及主内存区空闲内存字节数
    printf("%d buffers = %d bytes buffer space\n\r", NR_BUFFERS,
           NR_BUFFERS * BLOCK_SIZE);
    printf("Free mem: %d bytes\n\r", memory_end - main_memory_start);
    // 创建一个子进程（任务 2），并在该子进程中运行/etc/rc 文件中的命令。
    // 该子进程的代码首先把标准输入 stdin 重定向到/etc/rc 文件，然后使用execve()函数运行 / bin / sh 程序。
    // 该程序从标准输入中读取 rc 文件中的命令，并以解释方式执行之。
    // 关闭句柄 0 并立刻打开/etc/rc 文件的作用是把标准输入 stdin 重新定向到/etc/rc 文件。这样通过控制台读操作就可以读取 /etc / rc 文件中的内容。
    if (!(pid = fork()))
    {
        close(0);
        if (open("/etc/rc", O_RDONLY, 0))
            _exit(1);
        execve("/bin/sh", argv_rc, envp_rc);
        _exit(2);
    }
    // 下面是父进程（1）执行的语句。wait()等待子进程停止或终止，返回值应是子进程的进程号(pid)。
   // 这三句的作用是父进程等待子进程的结束。&i 是存放返回状态信息的位置。如果 wait()返回值不等于子进程号，则继续等待。 
    if (pid > 0) while (pid != wait(&i))
        /* nothing */;
    // 如果执行到这里，说明刚创建的子进程已执行完/etc/rc 文件（或文件不存在），因此该子进
    程自动停止或终止。
    while (1)
    {
        if ((pid = fork()) < 0)
        {
            printf("Fork failed in init\r\n");
            continue;
        }
        // 创建一个子进程，用于运行登录和控制台 shell 程序
        if (!pid)
        {
            close(0);
            close(1);
            close(2);
            setsid();
            (void)open("/dev/tty1", O_RDWR, 0);
            (void)dup(0);
            (void)dup(0);
            _exit(execve("/bin/sh", argv, envp));
        }
        _exit(0);
        // 新的子进程
        // 创建一新的会话
    }
    while (1)
        if (pid == wait(&i))
            break;
    printf("\n\rchild %d died with code %04x\n\r", pid, i);
    sync();
    // 同步操作，刷新缓冲区
    /* NOTE! _exit, not exit() */
    // _exit()和 exit()都用于正常终止一个函数。但_exit()直接是一个 sys_exit 系统调用，而exit() 则通常是普通函数库中的一个函数。
   // 它会先执行一些清除操作，例如调用执行各终止处理程序、关闭所有标准 IO 等，然后调用
     sys_exit。
}
```

## **3.段页管理**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790939890/488a42d3-3c51-4b30-b329-16c648b53f1e.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790954532/29c45684-12d8-4de7-8582-7a25fe4a8d6a.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790977913/20599a73-a45e-47d5-a879-c8c469463680.png align="center")

对于访问某个段的程序，必须已经把段选择符加载到一个段寄存器中

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767790996674/a7e2da60-b009-4fe3-a024-a613bef4e5f5.png align="center")

lldt,ltr指令用于加载ldt和tr

内存分页依靠页目录表和内存页表组成二级表实现。每项4字节，总共寻址4g内存，所有进程共用一个页目录表。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791012679/efac72c4-49d7-444f-a0ad-fb04fb203754.png align="center")

分页机制：32位的线性地址分成了三部分

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791040132/f322156e-ace6-4b27-a2cc-bf7007679742.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791054490/1649ff9e-aaeb-4e90-8512-2e4562763dc2.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791066799/72f887e1-4d2d-4b1f-8634-c57b63f93cb6.png align="center")

物理内存：主内存区是内存管理进行分配和管理

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791083881/9eefa689-9234-4363-b41a-6b56cc367d8a.png align="center")

每个进程所占据的逻辑地址空间在线性地址空间中都是从nr\*64MB的地址位置开始（nr是任务号），占用逻辑地址空间的范围是64MB。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791095242/f40bf258-c8c7-45f3-9150-bb2a855cbd67.png align="center")

逻辑地址，线性地址与物理地址的转换：

在复制页表时需要从一个给定页目录项线性地址转换得到对应的页表的物理内存地址；在涉及写时复制（copy-on-write）操作时，会涉及到把线性地址空间中的页面映射到物理内存地址的操作；在试图共享程序一页面时，就会涉及到把程序逻辑地址页面映射到CPU线性地址空间中的变换操作。

### **memory.c**

对于内核代码和数据所占物理内存区域以外的内存（1MB以上内存区域），内核使用了一个字节数组mem\_map\[\]来表示物理内存页面的状态。每个字节描述一个物理内存页的占用状态。其中的值表示被占用的次数，0表示对应的物理内存空闲着。当申请一页物理内存时，就将对应字节的值增1。当值为100时，表示已被完全占用，不能再被分配。

系统首先计算出1MB以上的内存区域所对应的内存页面数（PAGING\_PAGES），并把mem\_map\[\]所有项都置为100（占用），然后把主内存区域对应的mem\_map\[\]项中的值清零，。因此内核所使用的位于1MB地址以上的高速缓冲区域以及虚拟磁盘区域（若有的话）都已经被初始化成占用状态。mem\_map\[\]中对应主内存区域的项则在系统使用过程中进行设置或复位。

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1767791124692/4450ec37-2742-44a6-817e-b77b6900d1be.png align="center")

内存管理初始化：

```plaintext
void mem_init(long start_mem, long end_mem)
{
    int i;
    HIGH_MEMORY = end_mem;
    for (i=0 ; i<PAGING_PAGES ; i++)
        mem_map[i] = USED;
    i = MAP_NR(start_mem);
    end_mem -= start_mem;
    end_mem >>= 12;
    while (end_mem-->0)
        mem_map[i++]=0;
}
```

释放内存页：

```plaintext
void free_page(unsigned long addr) //addr开始的一页内存
{
    ......
    addr -= LOW_MEM;
    addr >>= 12;
    if (mem_map[addr]--) return;
    mem_map[addr]=0;
    panic("trying to free free page");
}
int free_page_tables(unsigned long from,unsigned long size)//根据from和size释放内存块并置表项空闲
{
    unsigned long *pg_table;
    unsigned long * dir, nr;
    ......
    size = (size + 0x3fffff) >> 22;//计算释放的页表个数
    dir = (unsigned long *) ((from>>20) & 0xffc); //计算起始目录项
    for ( ; size-->0 ; dir++) {
        if (!(1 & *dir))
            continue;
        pg_table = (unsigned long *) (0xfffff000 & *dir);//页表地址
        for (nr=0 ; nr<1024 ; nr++) {
            if (*pg_table) {
                if (1 & *pg_table)
                    free_page(0xfffff000 & *pg_table);
                else
                    swap_free(*pg_table >> 1);
                *pg_table = 0;
            }
            pg_table++;
        }
        free_page(0xfffff000 & *dir);
        *dir = 0;
    }
    invalidate();
    return 0;
}
```

**copy\_page\_tables()**用于复制指定线性地址和长度（页表个数）内存对应的页目录项和页表，从而使得被复制的页目录和页表对应的原物理内存区被共享使用。该函数首先验证指定的源线性地址和目的线性地址是否都在4Mb的内存边界地址上，然后由指定线性地址换算出对应的起始页目录项（from\_dir, to\_dir），并计算需复制的内存区占用的页表数（即页目录项数）；接着开始分别将原目录项和页表项复制到新的空闲目录项和页表项中。页目录表只有一个，而新进程的页表需要申请空闲内存页面来存放。此后再将原始和新的页目录和页表项都设置成只读的页面。当有写操作时就会利用页异常调用执行写时复制操作。最后对共享物理内存页对应的字节图数组项进行增1操作。

```plaintext
int copy_page_tables(unsigned long from,unsigned long to,long size)
{
    from_dir = (unsigned long *) ((from>>20) & 0xffc);//目录指针
    to_dir = (unsigned long *) ((to>>20) & 0xffc);
    size = ((unsigned) (size+0x3fffff)) >> 22; //页表数
    //对每个页目录项依次申请1页内存保护对应的页表
    for( ; size-->0 ; from_dir++,to_dir++) {
        if (1 & *to_dir)
            panic("copy_page_tables: already exist");
        if (!(1 & *from_dir))
            continue;
        from_page_table = (unsigned long *) (0xfffff000 & *from_dir);//页表地址
        if (!(to_page_table = (unsigned long *) get_free_page()))
            return -1;  /* Out of memory, see freeing */
        *to_dir = ((unsigned long) to_page_table) | 7;
        nr = (from==0)?0xA0:1024;
        //复制页表
        for ( ; nr-- > 0 ; from_page_table++,to_page_table++) {
            this_page = *from_page_table;
            if (!this_page)
                continue;
            //交换设备处理
            if (!(1 & this_page)) {
                if (!(new_page = get_free_page()))
                    return -1;
                read_swap_page(this_page>>1, (char *) new_page);
                *to_page_table = this_page;
                *from_page_table = new_page | (PAGE_DIRTY | 7);
                continue;
            }
            this_page &= ~2;
            *to_page_table = this_page;
            if (this_page > LOW_MEM) {
                *from_page_table = this_page;
                this_page -= LOW_MEM;
                this_page >>= 12;
                mem_map[this_page]++;
            }
        }
    }
    invalidate();
    return 0;
}
```

**put\_page()**函数用于将一指定的物理内存页面映射到指定的线性地址处。它首先确定指定的内存页面地址在1M和系统最高端内存地址范围内，然后计算该指定线性地址在页目录表中对应的目录项。若该目录项有效则取其对应页表的地址，否则申请空闲页给页表使用，并设置该页表中对应页表项的属性。最后仍返回指定的物理内存页面地址。

```plaintext
static unsigned long put_page(unsigned long page,unsigned long address)
{//将线性地址空间中指定地址address处的页面映射到主内存页面page
    ......
    page_table = (unsigned long *) ((address>>20) & 0xffc);//页目录项
    if ((*page_table)&1)
        page_table = (unsigned long *) (0xfffff000 & *page_table);//页表地址
    else {
        if (!(tmp=get_free_page()))
            return 0;
        *page_table = tmp | 7;
        page_table = (unsigned long *) tmp;
    }
    page_table[(address>>12) & 0x3ff] = page | 7;
    return page;
}
```

**un\_wp\_page()**，写时复制

```plaintext
void un_wp_page(unsigned long * table_entry)//页表项指针
{
    old_page = 0xfffff000 & *table_entry;
    //共享页面？
    if (old_page >= LOW_MEM && mem_map[MAP_NR(old_page)]==1) {
        *table_entry |= 2;
        invalidate();
        return;
    }
    //申请新页面使用
    if (!(new_page=get_free_page()))
        oom();
    if (old_page >= LOW_MEM)
        mem_map[MAP_NR(old_page)]--;
    copy_page(old_page,new_page);
    *table_entry = new_page | 7;
    invalidate();
}   
```

**do\_no\_page()**是页异常中断过程中调用的缺页处理函数。它首先判断指定的线性地址在一个进程空间中相对于进程基址的偏移长度值。如果它大于代码加数据长度，或者进程刚开始创建，则立刻申请一页物理内存，并映射到进程线性地址中，然后返回；接着尝试进行页面共享操作，若成功，则立刻返回；否则申请一页内存并从设备中读入一页信息；若加入该页信息时，指定线性地址+1页长度超过了进程代码加数据的长度，则将超过的部分清零。然后将该页映射到指定的线性地址处。

```plaintext
void do_no_page(unsigned long error_code,unsigned long address)
{
    page = *(unsigned long *) ((address >> 20) & 0xffc);//页目录项
    if (page & 1) {
        page &= 0xfffff000;//二级页表地址
        page += (address >> 10) & 0xffc;//页表项指针
        tmp = *(unsigned long *) page;//页表项内容
        if (tmp && !(1 & tmp)) {
            swap_in((unsigned long *) page);
            return;
        }
    }
    address &= 0xfffff000;
    tmp = address - current->start_code;//对应的逻辑地址
    //计算数据块号
    if (tmp >= LIBRARY_OFFSET ) {//60mb
        inode = current->library;
        block = 1 + (tmp-LIBRARY_OFFSET) / BLOCK_SIZE;
    } else if (tmp < current->end_data) {
        inode = current->executable;
        block = 1 + tmp / BLOCK_SIZE;//1kb
    } else {
        inode = NULL;
        block = 0;
    }
    //动态申请的数据内存页面
    if (!inode) {
        get_empty_page(address);
        return;
    }
    if (share_page(inode,tmp))
        return;
    if (!(page = get_free_page()))
        oom();
    //根据块号和i节点找到设备号
    for (i=0 ; i<4 ; block++,i++)
        nr[i] = bmap(inode,block);
    bread_page(page,inode->i_dev,nr);//读入到page
    //读取页面过短，清零操作
    i = tmp + 4096 - current->end_data;
    if (i>4095)
        i = 0;
    tmp = page + 4096;
    while (i-- > 0) {
        tmp--;
        *(char *)tmp = 0;
    }
    if (put_page(page,address))
        return;
    free_page(page);
    oom();
}
```
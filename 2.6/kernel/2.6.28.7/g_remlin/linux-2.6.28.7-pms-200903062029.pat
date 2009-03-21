diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/pms.h linux-2.6.28.7-pms/arch/x86/include/asm/pms.h
--- linux-2.6.28.7/arch/x86/include/asm/pms.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/include/asm/pms.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,5 @@
+#ifdef CONFIG_X86_32
+# include "pms_32.h"
+#else
+# include "pms_64.h" // #ifdef CONFIG_X86_64
+#endif
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/pms-protocol_32.h linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol_32.h
--- linux-2.6.28.7/arch/x86/include/asm/pms-protocol_32.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol_32.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,49 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ * 
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifdef CONFIG_X86
+#ifndef _HPC_ARCHPROTOCOL_H
+#define _HPC_ARCHPROTOCOL_H
+
+#include <asm/i387.h>
+
+#define MIG_ARCH_I386_LDT	1
+
+struct pmsp_mig_fp
+{
+	int has_fxsr;
+	union thread_xstate xstate;
+};
+
+struct pmsp_mig_arch
+{
+	int type;
+};
+
+struct pmsp_mig_arch_task
+{
+	u32 features[NCAPINTS];
+	long debugreg[8];
+	long fs;
+	long gs;
+	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
+};
+
+#endif /*  _HPC_ARCHPROTOCOL_H */
+#endif /* CONFIG_X86 */
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/pms-protocol_64.h linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol_64.h
--- linux-2.6.28.7/arch/x86/include/asm/pms-protocol_64.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol_64.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,46 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ * 
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifdef CONFIG_X86_64
+#ifndef _HPC_ARCHPROTOCOL_H
+#define _HPC_ARCHPROTOCOL_H
+
+#include <asm/i387.h>
+
+struct pmsp_mig_fp
+{
+	union thread_xstate xstate;
+};
+
+struct pmsp_mig_arch
+{
+	int type;
+};
+
+struct pmsp_mig_arch_task
+{
+	unsigned long userrsp;
+	unsigned long fs;
+	unsigned long gs;
+	unsigned int es, ds, fsindex, gsindex;
+	u64 tls_array[GDT_ENTRY_TLS_ENTRIES];
+};
+
+#endif /*  _HPC_ARCHPROTOCOL_H */
+#endif /* CONFIG_X86_64 */
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/pms-protocol.h linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol.h
--- linux-2.6.28.7/arch/x86/include/asm/pms-protocol.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/include/asm/pms-protocol.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,5 @@
+#ifdef CONFIG_X86_32
+# include "pms-protocol_32.h"
+#else
+# include "pms-protocol_64.h"
+#endif
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/thread_info.h linux-2.6.28.7-pms/arch/x86/include/asm/thread_info.h
--- linux-2.6.28.7/arch/x86/include/asm/thread_info.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/include/asm/thread_info.h	2009-03-06 19:59:09.000000000 +0000
@@ -80,6 +80,7 @@
 #define TIF_SYSCALL_AUDIT	7	/* syscall auditing active */
 #define TIF_SECCOMP		8	/* secure computing */
 #define TIF_MCE_NOTIFY		10	/* notify userspace of an MCE */
+#define TIF_PMS_PENDING	15	/* PMS request pending */
 #define TIF_NOTSC		16	/* TSC is not accessible in userland */
 #define TIF_IA32		17	/* 32bit process */
 #define TIF_FORK		18	/* ret_from_fork */
@@ -103,6 +104,7 @@
 #define _TIF_SYSCALL_AUDIT	(1 << TIF_SYSCALL_AUDIT)
 #define _TIF_SECCOMP		(1 << TIF_SECCOMP)
 #define _TIF_MCE_NOTIFY		(1 << TIF_MCE_NOTIFY)
+#define _TIF_PMS_PENDING	(1 << TIF_PMS_PENDING)
 #define _TIF_NOTSC		(1 << TIF_NOTSC)
 #define _TIF_IA32		(1 << TIF_IA32)
 #define _TIF_FORK		(1 << TIF_FORK)
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/uaccess_32.h linux-2.6.28.7-pms/arch/x86/include/asm/uaccess_32.h
--- linux-2.6.28.7/arch/x86/include/asm/uaccess_32.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/include/asm/uaccess_32.h	2009-03-06 19:59:09.000000000 +0000
@@ -41,12 +41,23 @@
  * anything, so this is accurate.
  */
 
+/* g_remlin #warning "deputy_get_user_size & deputy_put_user_size required!" */
+
 static __always_inline unsigned long __must_check
 __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
 {
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_to_user(to, from, n);
+#endif
 	if (__builtin_constant_p(n)) {
 		unsigned long ret;
-
+#if 0
+#ifdef CONFIG_PMS
+		if (pms_memory_away())
+			return deputy_put_user(to, from, n);
+#endif
+#endif
 		switch (n) {
 		case 1:
 			__put_user_size(*(u8 *)from, (u8 __user *)to,
@@ -94,9 +105,21 @@
 	 * but as the zeroing behaviour is only significant when n is not
 	 * constant, that shouldn't be a problem.
 	 */
+#if 0
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_from_user(to, from, n);
+#endif
+#endif
 	if (__builtin_constant_p(n)) {
 		unsigned long ret;
 
+#if 1
+#ifdef CONFIG_PMS
+		if (pms_memory_away())
+			return deputy_get_user(to, from, n);
+#endif
+#endif
 		switch (n) {
 		case 1:
 			__get_user_size(*(u8 *)to, from, 1, ret, 1);
@@ -109,6 +132,12 @@
 			return ret;
 		}
 	}
+#if 1
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_from_user(to, from, n);
+#endif
+#endif
 	return __copy_from_user_ll_nozero(to, from, n);
 }
 
@@ -140,7 +169,10 @@
 	might_sleep();
 	if (__builtin_constant_p(n)) {
 		unsigned long ret;
-
+#ifdef CONFIG_PMS
+		if (pms_memory_away())
+			return deputy_get_user(to, from, n);
+#endif
 		switch (n) {
 		case 1:
 			__get_user_size(*(u8 *)to, from, 1, ret, 1);
@@ -153,6 +185,10 @@
 			return ret;
 		}
 	}
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_from_user(to, from, n);
+#endif
 	return __copy_from_user_ll(to, from, n);
 }
 
@@ -162,7 +198,10 @@
 	might_sleep();
 	if (__builtin_constant_p(n)) {
 		unsigned long ret;
-
+#ifdef CONFIG_PMS
+		if (pms_memory_away())
+			return deputy_get_user(to, from, n);
+#endif
 		switch (n) {
 		case 1:
 			__get_user_size(*(u8 *)to, from, 1, ret, 1);
@@ -175,6 +214,10 @@
 			return ret;
 		}
 	}
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_from_user(to, from, n);
+#endif
 	return __copy_from_user_ll_nocache(to, from, n);
 }
 
@@ -182,6 +225,10 @@
 __copy_from_user_inatomic_nocache(void *to, const void __user *from,
 				  unsigned long n)
 {
+#ifdef CONFIG_PMS
+        if (pms_memory_away())
+               return deputy_copy_from_user(to, from, n);
+#endif
        return __copy_from_user_ll_nocache_nozero(to, from, n);
 }
 
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/include/asm/uaccess.h linux-2.6.28.7-pms/arch/x86/include/asm/uaccess.h
--- linux-2.6.28.7/arch/x86/include/asm/uaccess.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/include/asm/uaccess.h	2009-03-06 19:59:09.000000000 +0000
@@ -37,6 +37,11 @@
 	((unsigned long __force)(addr) <		\
 	 (current_thread_info()->addr_limit.seg))
 
+#ifdef CONFIG_PMS
+/* defines above required by hpc/uaccess.h */
+#include <hpc/uaccess.h>
+#endif
+
 /*
  * Test whether a block of memory is a valid user space address.
  * Returns 0 if the range is valid, nonzero otherwise.
@@ -152,11 +157,21 @@
 		__get_user_x(8, __ret_gu, __val_gu, ptr)
 #endif
 
+#ifdef CONFIG_PMS
+#define __get_is_deputy_userspace(__ret_gu, __val_gu, ptr)								\
+	if (pms_memory_away())						\
+		__ret_gu = deputy_get_user(&__val_gu, ptr, sizeof (*(ptr)));	\
+	else
+#else
+#define __get_is_deputy_userspace	do { } while (0)
+#endif
+
 #define get_user(x, ptr)						\
 ({									\
 	int __ret_gu;							\
 	unsigned long __val_gu;						\
 	__chk_user_ptr(ptr);						\
+ 	__get_is_deputy_userspace(__ret_gu, __val_gu, ptr)							\
 	switch (sizeof(*(ptr))) {					\
 	case 1:								\
 		__get_user_x(1, __ret_gu, __val_gu, ptr);		\
@@ -262,10 +277,20 @@
 	__ret_pu;						\
 })
 
+#ifdef CONFIG_PMS
+#define __put_is_deputy_userspace(retval, x, ptr, size)								\
+	if (pms_memory_away())						\
+		retval = deputy_put_user((long) x, ptr, size);		\
+	else
+#else
+#define __put_is_deputy_userspac	do { } while (0)
+#endif
+
 #define __put_user_size(x, ptr, size, retval, errret)			\
 do {									\
 	retval = 0;							\
 	__chk_user_ptr(ptr);						\
+	__put_is_deputy_userspace(retval, x, ptr, size)								\
 	switch (size) {							\
 	case 1:								\
 		__put_user_asm(x, ptr, retval, "b", "b", "iq", errret);	\
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/Kconfig linux-2.6.28.7-pms/arch/x86/Kconfig
--- linux-2.6.28.7/arch/x86/Kconfig	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/Kconfig	2009-03-06 19:59:09.000000000 +0000
@@ -1917,4 +1917,6 @@
 
 source "arch/x86/kvm/Kconfig"
 
+source "hpc/Kconfig"
+
 source "lib/Kconfig"
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/asm-offsets_32.c linux-2.6.28.7-pms/arch/x86/kernel/asm-offsets_32.c
--- linux-2.6.28.7/arch/x86/kernel/asm-offsets_32.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/asm-offsets_32.c	2009-03-06 19:59:09.000000000 +0000
@@ -24,6 +24,10 @@
 #include <linux/lguest.h>
 #include "../../../drivers/lguest/lg.h"
 
+#ifdef CONFIG_PMS
+#include <hpc/task.h>
+#endif
+
 /* workaround for a warning with -Wmissing-prototypes */
 void foo(void);
 
@@ -144,4 +148,12 @@
 	OFFSET(BP_loadflags, boot_params, hdr.loadflags);
 	OFFSET(BP_hardware_subarch, boot_params, hdr.hardware_subarch);
 	OFFSET(BP_version, boot_params, hdr.version);
+#ifdef CONFIG_PMS
+        OFFSET(TASK_pms, task_struct, pms);
+        OFFSET(PMS_dflags, pms_task, dflags);
+        BLANK();
+        DEFINE(DDEPUTY, DDEPUTY);
+        DEFINE(DREMOTE, DREMOTE);
+        DEFINE(DSPLIT, DSPLIT);
+#endif /* CONFIG_PMS */
 }
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/asm-offsets_64.c linux-2.6.28.7-pms/arch/x86/kernel/asm-offsets_64.c
--- linux-2.6.28.7/arch/x86/kernel/asm-offsets_64.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/asm-offsets_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -20,6 +20,10 @@
 
 #include <xen/interface/xen.h>
 
+#ifdef CONFIG_PMS
+#include <hpc/task.h>
+#endif
+
 #define __NO_STUBS 1
 #undef __SYSCALL
 #undef _ASM_X86_UNISTD_64_H
@@ -34,6 +38,9 @@
 	ENTRY(state);
 	ENTRY(flags); 
 	ENTRY(pid);
+#ifdef CONFIG_PMS
+        DEFINE(TASK_pms, offsetof(struct task_struct, pms));
+#endif /* CONFIG_PMS */
 	BLANK();
 #undef ENTRY
 #define ENTRY(entry) DEFINE(TI_ ## entry, offsetof(struct thread_info, entry))
@@ -142,5 +149,13 @@
 	OFFSET(XEN_vcpu_info_pending, vcpu_info, evtchn_upcall_pending);
 #undef ENTRY
 #endif
+#ifdef CONFIG_PMS
+        BLANK();
+        DEFINE(PMS_dflags, offsetof(struct pms_task, dflags));
+        BLANK();
+        DEFINE(DDEPUTY, DDEPUTY);
+        DEFINE(DREMOTE, DREMOTE);
+        DEFINE(DSPLIT, DSPLIT);
+#endif
 	return 0;
 }
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/entry_32.S linux-2.6.28.7-pms/arch/x86/kernel/entry_32.S
--- linux-2.6.28.7/arch/x86/kernel/entry_32.S	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/entry_32.S	2009-03-06 19:59:09.000000000 +0000
@@ -233,6 +233,13 @@
 	CFI_ENDPROC
 END(ret_from_fork)
 
+#ifdef CONFIG_PMS
+ENTRY(ret_from_kickstart)
+	GET_THREAD_INFO(%ebp)
+	jmp syscall_exit
+END(ret_from_kickstart)
+#endif
+
 /*
  * Return to user mode is not as complex as all this looks,
  * but we want the default path for a system call return to
@@ -347,7 +354,22 @@
 sysenter_do_call:
 	cmpl $(nr_syscalls), %eax
 	jae syscall_badsys
+#ifdef CONFIG_PMS
+        pushl %ebp
+	CFI_ADJUST_CFA_OFFSET 4
+        movl TI_task(%ebp), %ebp
+        testl $DREMOTE, TASK_pms+PMS_dflags(%ebp) # is this a DREMOTE task ?
+        popl %ebp
+	CFI_ADJUST_CFA_OFFSET -4
+        jz sysenter_syscall_call
+        call *pmssys_call_table(,%eax,4)
+        jmp sysenter_syscall_called
+sysenter_syscall_call:
+#endif
 	call *sys_call_table(,%eax,4)
+#ifdef CONFIG_PMS
+sysenter_syscall_called:
+#endif
 	movl %eax,PT_EAX(%esp)
 	LOCKDEP_SYS_EXIT
 	DISABLE_INTERRUPTS(CLBR_ANY)
@@ -425,8 +447,22 @@
 	jnz syscall_trace_entry
 	cmpl $(nr_syscalls), %eax
 	jae syscall_badsys
+#ifdef CONFIG_PMS
+	pushl %ebp
+	CFI_ADJUST_CFA_OFFSET 4
+	movl TI_task(%ebp), %ebp
+	testl $DREMOTE, TASK_pms+PMS_dflags(%ebp) # is this a DREMOTE task ?
+	popl %ebp
+	CFI_ADJUST_CFA_OFFSET -4
+	jz syscall_call
+	call *pmssys_call_table(,%eax,4)
+	jmp syscall_called
+#endif
 syscall_call:
 	call *sys_call_table(,%eax,4)
+#ifdef CONFIG_PMS
+syscall_called:
+#endif
 	movl %eax,PT_EAX(%esp)		# store the return value
 syscall_exit:
 	LOCKDEP_SYS_EXIT
@@ -513,6 +549,18 @@
 	ALIGN
 	RING0_PTREGS_FRAME		# can't unwind into user space anyway
 work_pending:
+#ifdef CONFIG_PMS
+	/* Check if any requests are pending */
+	movl TI_flags(%ebp), %ecx
+	testl $_TIF_PMS_PENDING, %ecx
+	jz work_pending_no_pms
+work_pending_pms:
+	SAVE_ALL
+	call pms_pre_usermode
+	RESTORE_REGS
+	jmp work_resched
+work_pending_no_pms:
+#endif
 	testb $_TIF_NEED_RESCHED, %cl
 	jz work_notifysig
 work_resched:
@@ -528,6 +576,11 @@
 	jz restore_all
 	testb $_TIF_NEED_RESCHED, %cl
 	jnz work_resched
+#ifdef CONFIG_PMS
+#	/* _TIF_WORK or _TIF_ALLWORK ? */
+#	testl $_TIF_PMS_PENDING, %ecx
+#	jnz work_pending_pms
+#endif /* CONFIG_PMS */
 
 work_notifysig:				# deal with pending signals and
 					# notify-resume requests
@@ -1041,6 +1094,10 @@
 	CFI_ENDPROC
 END(spurious_interrupt_bug)
 
+#ifdef CONFIG_PMS
+ENTRY(user_thread_helper)
+	subl $60,%esp
+#endif
 ENTRY(kernel_thread_helper)
 	pushl $0		# fake return address for unwinder
 	CFI_STARTPROC
@@ -1210,3 +1267,9 @@
 #include "syscall_table_32.S"
 
 syscall_table_size=(.-sys_call_table)
+
+#ifdef CONFIG_PMS
+#include "pmssyscall_table_32.S"
+pmssyscall_table_size=(.-pmssys_call_table)
+#endif
+
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/entry_64.S linux-2.6.28.7-pms/arch/x86/kernel/entry_64.S
--- linux-2.6.28.7/arch/x86/kernel/entry_64.S	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/entry_64.S	2009-03-06 19:59:09.000000000 +0000
@@ -59,6 +59,10 @@
 #define __AUDIT_ARCH_64BIT 0x80000000
 #define __AUDIT_ARCH_LE	   0x40000000
 
+#ifdef CONFIG_PMS
+#include "pmssyscall_table_64.S"
+#endif
+
 	.code64
 
 #ifdef CONFIG_FUNCTION_TRACER
@@ -272,6 +276,16 @@
 	CFI_ENDPROC
 END(ret_from_fork)
 
+#ifdef CONFIG_PMS
+ENTRY(ret_from_kickstart)
+	CFI_STARTPROC
+	cli
+	swapgs
+	RESTORE_ALL 8
+	iretq
+	CFI_ENDPROC
+#endif
+
 /*
  * System call entry. Upto 6 arguments in registers are supported.
  *
@@ -334,6 +348,18 @@
 system_call_fastpath:
 	cmpq $__NR_syscall_max,%rax
 	ja badsys
+#ifdef CONFIG_PMS
+	movq threadinfo_task(%rcx), %rcx
+	testq $DREMOTE, TASK_pms+PMS_dflags(%rcx) # is this a DREMOTE task ?
+	jz syscall_call
+	movq %r10,%rcx
+	subq $6*8, %rsp
+	call *remote_sys_call_table(,%rax,8)
+	addq $6*8, %rsp
+	movq %rax,RAX-ARGOFFSET(%rsp)
+	jmp ret_from_sys_call
+syscall_call:
+#endif
 	movq %r10,%rcx
 	call *sys_call_table(,%rax,8)  # XXX:	 rip relative
 	movq %rax,RAX-ARGOFFSET(%rsp)
@@ -381,6 +407,20 @@
 
 	/* Handle a signal */ 
 sysret_signal:
+#ifdef CONFIG_PMS
+	/* Check if the process have pending requests     */
+	/* Must be after schedule() for real time sake       */
+	/* Once here, the current task struct may have moved */
+	cli
+	GET_THREAD_INFO(%rcx)
+	bt $TIF_PMS_PENDING,threadinfo_flags(%rcx)
+	jnc sysret_careful_no_pms
+	SAVE_REST
+	call pms_pre_usermode
+	RESTORE_REST
+	jmp sysret_check
+sysret_careful_no_pms:
+#endif
 	TRACE_IRQS_ON
 	ENABLE_INTERRUPTS(CLBR_NONE)
 #ifdef CONFIG_AUDITSYSCALL
@@ -537,6 +577,13 @@
  */ 								
 	
 	.macro PTREGSCALL label,func,arg
+#ifdef CONFIG_PMS
+	.globl pms_\label
+pms_\label:
+	leaq	pms_\func(%rip),%rax
+	leaq    -ARGOFFSET+8(%rsp),\arg /* 8 for return address */
+	jmp	pms_ptregscall_common
+#endif
 	.globl \label
 \label:
 	leaq	\func(%rip),%rax
@@ -573,6 +620,26 @@
 	CFI_ENDPROC
 END(ptregscall_common)
 	
+#ifdef CONFIG_PMS
+ENTRY(pms_ptregscall_common)
+	CFI_STARTPROC
+	addq $6*8, %rsp
+	popq %r11
+	CFI_ADJUST_CFA_OFFSET	-8
+	SAVE_REST
+	movq %r11, %r15
+	FIXUP_TOP_OF_STACK %r11
+	call *%rax
+	RESTORE_TOP_OF_STACK %r11
+	movq %r15, %r11
+	RESTORE_REST
+	pushq %r11
+	subq $6*8, %rsp
+	CFI_ADJUST_CFA_OFFSET	8
+	ret
+	CFI_ENDPROC
+#endif
+
 ENTRY(stub_execve)
 	CFI_STARTPROC
 	popq %r11
@@ -589,6 +656,27 @@
 	CFI_ENDPROC
 END(stub_execve)
 	
+#ifdef CONFIG_PMS
+ENTRY(pms_stub_execve)
+	CFI_STARTPROC
+	popq %r11
+	CFI_ADJUST_CFA_OFFSET	-8
+	SAVE_REST
+	movq %r11, %r15
+	FIXUP_TOP_OF_STACK %r11
+	call remote_do_execve
+	GET_THREAD_INFO(%rcx)
+	# FIXME pms doesn't support remote 32 bits tasks yet
+	#bt $TIF_IA32,threadinfo_flags(%rcx)
+	#jc exec_32bit
+	RESTORE_TOP_OF_STACK %r11
+	movq %r15, %r11
+	RESTORE_REST
+	push %r11
+	ret
+	CFI_ENDPROC
+#endif
+	
 /*
  * sigreturn is special because it needs to restore all registers on return.
  * This cannot be done with SYSRET, so use the IRET return path instead.
@@ -699,7 +787,13 @@
 	andl %edi,%edx
 	CFI_REMEMBER_STATE
 	jnz  retint_careful
-
+#if 0
+#ifdef CONFIG_PMS
+        SAVE_REST
+        call pms_pre_usermode
+        RESTORE_REST
+#endif /* CONFIG_PMS */
+#endif
 retint_swapgs:		/* return to user-space */
 	/*
 	 * The iretq could re-enable interrupts:
@@ -756,6 +850,18 @@
 	/* edi: workmask, edx: work */
 retint_careful:
 	CFI_RESTORE_STATE
+#ifdef CONFIG_PMS
+	/* Check if the task have pending requests */
+	bt $TIF_PMS_PENDING,%edx
+	jnc retint_careful_no_pms
+	sti
+	SAVE_REST
+	call pms_pre_usermode
+	RESTORE_REST
+	cli
+retint_careful_no_pms:
+#endif
+
 	bt    $TIF_NEED_RESCHED,%edx
 	jnc   retint_signal
 	TRACE_IRQS_ON
@@ -996,6 +1102,43 @@
 	CFI_ENDPROC
 	.endm
 
+#ifdef CONFIG_PMS
+ENTRY(user_thread)
+	CFI_STARTPROC
+	FAKE_STACK_FRAME $user_child_rip
+	SAVE_ALL
+
+	# rdi: flags, rsi: usp, rdx: will be &pt_regs
+	movq %rdx,%rdi
+	orq  kernel_thread_flags(%rip),%rdi
+	movq $-1, %rsi
+	movq %rsp, %rdx
+
+	xorl %r8d,%r8d
+	xorl %r9d,%r9d
+	
+	# clone now
+	call do_fork
+	movq %rax,RAX(%rsp)
+	xorl %edi,%edi
+
+	/*
+	 * It isn't worth to check for reschedule here,
+	 * so internally to the x86_64 port you can rely on kernel_thread()
+	 * not to reschedule the child before returning, this avoids the need
+	 * of hacks for example to fork off the per-CPU idle tasks.
+         * [Hopefully no generic code relies on the reschedule -AK]	
+	 */
+	RESTORE_ALL
+	UNFAKE_STACK_FRAME
+	ret
+	CFI_ENDPROC
+
+user_child_rip:
+	subq $168, %rsp
+	jmp child_rip
+#endif
+
 /*
  * Exception entry point. This expects an error code/orig_rax on the stack
  * and the exception handler in %rax.	
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/i387.c linux-2.6.28.7-pms/arch/x86/kernel/i387.c
--- linux-2.6.28.7/arch/x86/kernel/i387.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/i387.c	2009-03-06 19:59:09.000000000 +0000
@@ -224,13 +224,14 @@
 	return ret;
 }
 
+
 #if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
 
 /*
  * FPU tag word conversions.
  */
 
-static inline unsigned short twd_i387_to_fxsr(unsigned short twd)
+PMS_NSTATIC inline unsigned short twd_i387_to_fxsr(unsigned short twd)
 {
 	unsigned int tmp; /* to avoid 16 bit prefixes in the code */
 
@@ -251,7 +252,7 @@
 #define FP_EXP_TAG_SPECIAL	2
 #define FP_EXP_TAG_EMPTY	3
 
-static inline u32 twd_fxsr_to_i387(struct i387_fxsave_struct *fxsave)
+PMS_NSTATIC inline u32 twd_fxsr_to_i387(struct i387_fxsave_struct *fxsave)
 {
 	struct _fpxreg *st;
 	u32 tos = (fxsave->swd >> 11) & 7;
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/pmssyscall_table_32.S linux-2.6.28.7-pms/arch/x86/kernel/pmssyscall_table_32.S
--- linux-2.6.28.7/arch/x86/kernel/pmssyscall_table_32.S	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/kernel/pmssyscall_table_32.S	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,295 @@
+ENTRY(pmssys_call_table)
+	.long pms_sys_remote		/* 0 - old "setup()" system call, used for restarting */
+	.long pms_sys_remote		/* sys_exit */
+	.long pms_sys_fork		/* sys_fork */
+	.long pms_sys_remote		/* sys_read */
+	.long pms_sys_remote		/* sys_write */
+	.long pms_sys_remote		/* sys_open */
+	.long pms_sys_remote		/* sys_close */
+	.long pms_sys_remote		/* sys_waitpid */
+	.long pms_sys_remote		/* sys_creat */
+	.long pms_sys_remote		/* sys_link */
+	.long pms_sys_remote		/* sys_unlink */
+	.long pms_sys_execve		/* sys_execve */
+	.long pms_sys_remote		/* sys_chdir */
+	.long pms_sys_remote		/* sys_time */
+	.long pms_sys_remote		/* sys_mknod */
+	.long pms_sys_remote		/* sys_chmod */
+	.long pms_sys_remote		/* sys_lchown16 */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_stat */
+	.long pms_sys_remote		/* sys_lseek */
+	.long pms_sys_getpid		/* sys_getpid */
+	.long pms_sys_remote		/* sys_mount */
+	.long pms_sys_remote		/* sys_oldumount */
+	.long sys_setuid16		/* sys_setuid16 */
+	.long sys_getuid16		/* sys_getuid16 */
+	.long pms_sys_remote		/* sys_stime */
+	.long pms_sys_remote		/* sys_ptrace */
+	.long pms_sys_remote		/* sys_alarm */
+	.long pms_sys_remote		/* sys_fstat */
+	.long sys_pause			/* sys_pause */
+	.long pms_sys_remote		/* sys_utime */
+	.long sys_ni_syscall
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_access */
+	.long pms_sys_remote		/* sys_nice */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_sync */
+	.long pms_sys_remote		/* sys_kill */
+	.long pms_sys_remote		/* sys_rename */
+	.long pms_sys_remote		/* sys_mkdir */
+	.long pms_sys_remote		/* sys_rmdir */
+	.long pms_sys_remote		/* sys_dup */
+	.long pms_sys_remote		/* sys_pipe */
+	.long pms_sys_remote		/* sys_times */
+	.long sys_ni_syscall
+	.long sys_brk			/* sys_brk */
+	.long sys_setgid16		/* sys_setgid16 */
+	.long sys_getgid16		/* sys_getgid16 */
+	.long sys_signal		/* sys_signal */
+	.long sys_geteuid16		/* sys_geteuid16 */
+	.long sys_getegid16		/* sys_getegid16 */
+	.long pms_sys_remote		/* sys_acct */
+	.long pms_sys_remote		/* sys_umount */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_ioctl */
+	.long pms_sys_remote		/* sys_fcntl */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_setpgid */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_olduname */
+	.long pms_sys_remote		/* sys_umask */
+	.long pms_sys_remote		/* sys_chroot */
+	.long pms_sys_remote		/* sys_ustat */
+	.long pms_sys_remote		/* sys_dup2 */
+	.long pms_sys_remote		/* sys_getppid */
+	.long pms_sys_remote		/* sys_getpgrp */
+	.long pms_sys_remote		/* sys_setsid */
+	.long sys_sigaction		/* sys_sigaction */
+	.long pms_sys_remote		/* sys_sgetmask */
+	.long pms_sys_remote		/* sys_ssetmask */
+	.long sys_setreuid16		/* sys_setreuid16 */
+	.long sys_setregid16		/* sys_setregid16 */
+	.long sys_sigsuspend		/* sys_sigsuspend */
+	.long sys_sigpending		/* sys_sigpending */
+	.long pms_sys_remote		/* sys_sethostname */
+	.long pms_sys_remote		/* sys_setrlimit */
+	.long pms_sys_remote		/* sys_old_getrlimit */
+	.long pms_sys_remote		/* sys_getrusage */
+	.long pms_sys_remote		/* sys_gettimeofday */
+	.long pms_sys_remote		/* sys_settimeofday */
+	.long pms_sys_remote		/* sys_getgroups16 */
+	.long pms_sys_remote		/* sys_setgroups16 */
+	.long pms_sys_remote		/* old_select */
+	.long pms_sys_remote		/* sys_symlink */
+	.long pms_sys_remote		/* sys_lstat */
+	.long pms_sys_remote		/* sys_readlink */
+	.long pms_sys_remote		/* sys_uselib */
+	.long pms_sys_remote		/* sys_swapon */
+	.long pms_sys_remote		/* sys_reboot */
+	.long pms_sys_remote		/* old_readdir */
+	.long old_mmap			/* old_mmap */
+	.long sys_munmap		/* sys_munmap */
+	.long pms_sys_remote		/* sys_truncate */
+	.long pms_sys_remote		/* sys_ftruncate */
+	.long pms_sys_remote		/* sys_fchmod */
+	.long pms_sys_remote		/* sys_fchown16 */
+	.long pms_sys_remote		/* sys_getpriority */
+	.long pms_sys_remote		/* sys_setpriority */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_statfs */
+	.long pms_sys_remote		/* sys_fstatfs */
+	.long pms_sys_remote		/* sys_ioperm */
+	.long pms_sys_remote		/* sys_socketcall */
+	.long pms_sys_remote		/* sys_syslog */
+	.long pms_sys_remote		/* sys_setitimer */
+	.long pms_sys_remote		/* sys_getitimer */
+	.long pms_sys_remote		/* sys_newstat */
+	.long pms_sys_remote		/* sys_newlstat */
+	.long pms_sys_remote		/* sys_newfstat */
+	.long pms_sys_remote		/* sys_uname */
+	.long pms_sys_remote		/* sys_iopl */
+	.long pms_sys_remote		/* sys_vhangup */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_vm86old */
+	.long pms_sys_remote		/* sys_wait4 */
+	.long pms_sys_remote		/* sys_swapoff */
+	.long pms_sys_remote		/* sys_sysinfo */
+	.long pms_sys_remote		/* sys_ipc */
+	.long pms_sys_remote		/* sys_fsync */
+	.long sys_sigreturn		/* sys_sigreturn */
+	.long pms_sys_clone		/* sys_clone */
+	.long pms_sys_remote		/* sys_setdomainname */
+	.long pms_sys_remote		/* sys_newuname */
+	.long sys_modify_ldt		/* sys_modify_ldt */
+	.long pms_sys_remote		/* sys_adjtimex */
+	.long sys_mprotect		/* sys_mprotect */
+	.long sys_sigprocmask		/* sys_sigprocmask */
+	.long sys_ni_syscall 
+	.long pms_sys_remote		/* sys_init_module */
+	.long pms_sys_remote		/* sys_delete_module */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_quotactl */
+	.long pms_sys_remote		/* sys_getpgid */
+	.long pms_sys_remote		/* sys_fchdir */
+	.long pms_sys_remote		/* sys_bdflush */
+	.long pms_sys_remote		/* sys_sysfs */
+	.long pms_sys_remote		/* sys_personality */
+	.long sys_ni_syscall
+	.long sys_setfsuid16		/* sys_setfsuid16 */
+	.long sys_setfsgid16		/* sys_setfsgid16 */
+	.long pms_sys_remote		/* sys_llseek */
+	.long pms_sys_remote		/* sys_getdents */
+	.long pms_sys_remote		/* sys_select */
+	.long pms_sys_remote		/* sys_flock */
+	.long pms_sys_remote		/* sys_msync */
+	.long pms_sys_remote		/* sys_readv */
+	.long pms_sys_remote		/* sys_writev */
+	.long sys_getsid		/* sys_getsid */
+	.long pms_sys_remote		/* sys_fdatasync */
+	.long pms_sys_remote		/* sys_sysctl */
+	.long pms_sys_remote		/* sys_mlock */
+	.long pms_sys_remote		/* sys_munlock */
+	.long pms_sys_remote		/* sys_mlockall */
+	.long pms_sys_remote		/* sys_munlockall */
+	.long pms_sys_remote		/* sys_sched_setparam */
+	.long pms_sys_remote		/* sys_sched_getparam */
+	.long pms_sys_remote		/* sys_sched_setscheduler */
+	.long pms_sys_remote		/* sys_sched_getscheduler */
+	.long sys_sched_yield		/* sys_sched_yield */
+	.long pms_sys_remote		/* sys_sched_get_priority_max */
+	.long pms_sys_remote		/* sys_sched_get_priority_min */
+	.long pms_sys_remote		/* sys_sched_rr_get_interval */
+	.long sys_nanosleep		/* sys_nanosleep */
+	.long sys_mremap		/* sys_mremap */
+	.long sys_setresuid16		/* sys_setresuid16 */
+	.long sys_getresuid16		/* sys_getresuid16 */
+	.long pms_sys_remote		/* sys_vm86 */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_poll */
+	.long pms_sys_remote		/* sys_nfsservctl */
+	.long sys_setresgid16		/* sys_setresgid16 */
+	.long sys_getresgid16		/* sys_getresgid16 */
+	.long pms_sys_remote		/* sys_prctl */
+	.long sys_rt_sigreturn		/* sys_rt_sigreturn */
+	.long sys_rt_sigaction		/* sys_rt_sigaction */
+	.long sys_rt_sigprocmask	/* sys_rt_sigprocmask */
+	.long sys_rt_sigpending		/* sys_rt_sigpending */
+	.long sys_rt_sigtimedwait	/* sys_rt_sigtimedwait */
+	.long sys_rt_sigqueueinfo	/* sys_rt_sigqueueinfo */
+	.long sys_rt_sigsuspend		/* sys_rt_sigsuspend */
+	.long pms_sys_remote		/* sys_pread64 */
+	.long pms_sys_remote		/* sys_pwrite64 */
+	.long pms_sys_remote		/* sys_chown16 */
+	.long pms_sys_remote		/* sys_getcwd */
+	.long pms_sys_remote		/* sys_capget */
+	.long pms_sys_remote		/* sys_capset */
+	.long sys_sigaltstack		/* sys_sigaltstack */
+	.long pms_sys_remote		/* sys_sendfile */
+	.long sys_ni_syscall
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_vfork */
+	.long pms_sys_remote		/* sys_getrlimit */
+	.long sys_mmap2		/* sys_mmap2 */
+	.long pms_sys_remote		/* sys_truncate64 */
+	.long pms_sys_remote		/* sys_ftruncate64 */
+	.long pms_sys_remote		/* sys_stat64 */
+	.long pms_sys_remote		/* sys_lstat64 */
+	.long pms_sys_remote		/* sys_fstat64 */
+	.long pms_sys_remote		/* sys_lchown */
+	.long sys_getuid		/* sys_getuid */
+	.long sys_getgid		/* sys_getgid */
+	.long sys_geteuid		/* sys_geteuid */
+	.long sys_getegid		/* sys_getegid */
+	.long sys_setreuid		/* sys_setreuid */
+	.long sys_setregid		/* sys_setregid */
+	.long pms_sys_remote		/* sys_getgroups */
+	.long pms_sys_remote		/* sys_setgroups */
+	.long pms_sys_remote		/* sys_fchown */
+	.long sys_setresuid		/* sys_setresuid */
+	.long sys_getresuid		/* sys_getresuid */
+	.long sys_setresgid		/* sys_setresgid */
+	.long sys_getresgid		/* sys_getresgid */
+	.long pms_sys_remote		/* sys_chown */
+	.long sys_setuid		/* sys_setuid */
+	.long sys_setgid		/* sys_setgid */
+	.long sys_setfsuid		/* sys_setfsuid */
+	.long sys_setfsgid		/* sys_setfsgid */
+	.long pms_sys_remote		/* sys_pivot_root */
+	.long sys_mincore		/* sys_mincore */
+	.long sys_madvise		/* sys_madvise */
+	.long pms_sys_remote		/* sys_getdents64 */
+	.long pms_sys_remote		/* sys_fcntl64 */
+	.long sys_ni_syscall
+	.long sys_ni_syscall
+	.long pms_sys_gettid		/* sys_gettid */
+	.long pms_sys_remote		/* sys_readahead */
+	.long pms_sys_remote		/* sys_setxattr */
+	.long pms_sys_remote		/* sys_lsetxattr */
+	.long pms_sys_remote		/* sys_fsetxattr */
+	.long pms_sys_remote		/* sys_getxattr */
+	.long pms_sys_remote		/* sys_lgetxattr */
+	.long pms_sys_remote		/* sys_fgetxattr */
+	.long pms_sys_remote		/* sys_listxattr */
+	.long pms_sys_remote		/* sys_llistxattr */
+	.long pms_sys_remote		/* sys_flistxattr */
+	.long pms_sys_remote		/* sys_removexattr */
+	.long pms_sys_remote		/* sys_lremovexattr */
+	.long pms_sys_remote		/* sys_fremovexattr */
+	.long pms_sys_remote		/* sys_tkill */
+	.long pms_sys_remote		/* sys_sendfile64 */
+	.long sys_futex			/* sys_futex */
+	.long pms_sys_remote		/* sys_sched_setaffinity */
+	.long pms_sys_remote		/* sys_sched_getaffinity */
+	.long pms_sys_remote		/* sys_set_thread_area */
+	.long pms_sys_remote		/* sys_get_thread_area */
+	.long pms_sys_remote		/* sys_io_setup */
+	.long pms_sys_remote		/* sys_io_destroy */
+	.long pms_sys_remote		/* sys_io_getevents */
+	.long pms_sys_remote		/* sys_io_submit */
+	.long pms_sys_remote		/* sys_io_cancel */
+	.long pms_sys_remote		/* sys_fadvise64 */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_exit_group */
+	.long pms_sys_remote		/* sys_lookup_dcookie */
+	.long pms_sys_remote		/* sys_epoll_create */
+	.long pms_sys_remote		/* sys_epoll_ctl */
+	.long pms_sys_remote		/* sys_epoll_wait */
+	.long pms_sys_remote		/* sys_remap_file_pages */
+	.long pms_sys_remote		/* sys_set_tid_address */
+	.long pms_sys_remote		/* sys_timer_create */
+	.long pms_sys_remote		/* sys_timer_settime */
+	.long pms_sys_remote		/* sys_timer_gettime */
+	.long pms_sys_remote		/* sys_timer_getoverrun */
+	.long pms_sys_remote		/* sys_timer_delete */
+	.long pms_sys_remote		/* sys_clock_settime */
+	.long pms_sys_remote		/* sys_clock_gettime */
+	.long pms_sys_remote		/* sys_clock_getres */
+	.long pms_sys_remote		/* sys_clock_nanosleep */
+	.long pms_sys_remote		/* sys_statfs64 */
+	.long pms_sys_remote		/* sys_fstatfs64 */	
+	.long pms_sys_remote		/* sys_tgkill */
+	.long pms_sys_remote		/* sys_utimes */
+	.long pms_sys_remote		/* sys_fadvise64_64 */
+	.long sys_ni_syscall
+	.long sys_mbind			/* sys_mbind */
+	.long pms_sys_remote		/* sys_get_mempolicy */
+	.long pms_sys_remote		/* sys_set_mempolicy */
+	.long pms_sys_remote		/* sys_mq_open */
+	.long pms_sys_remote		/* sys_mq_unlink */
+	.long pms_sys_remote		/* sys_mq_timedsend */
+	.long pms_sys_remote		/* sys_mq_timedreceive */
+	.long pms_sys_remote		/* sys_mq_notify */
+	.long pms_sys_remote		/* sys_mq_getsetattr */
+	.long pms_sys_remote		/* sys_kexec_load */
+	.long pms_sys_remote		/* sys_waitid */
+	.long sys_ni_syscall
+	.long pms_sys_remote		/* sys_add_key */
+	.long pms_sys_remote		/* sys_request_key */
+	.long pms_sys_remote		/* sys_keyctl */
+	.long pms_sys_remote		/* sys_ioprio_set */
+	.long pms_sys_remote		/* sys_ioprio_get */
+	.long pms_sys_remote		/* sys_inotify_init */
+	.long pms_sys_remote		/* sys_inotify_add_watch */
+	.long pms_sys_remote		/* sys_inotify_rm_watch */
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/pmssyscall_table_64.S linux-2.6.28.7-pms/arch/x86/kernel/pmssyscall_table_64.S
--- linux-2.6.28.7/arch/x86/kernel/pmssyscall_table_64.S	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/arch/x86/kernel/pmssyscall_table_64.S	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,263 @@
+.data
+
+ENTRY(remote_sys_call_table)
+	.quad pms_sys_remote		/* 0 sys_read */
+	.quad pms_sys_remote		/* 1 sys_write */
+	.quad pms_sys_remote		/* 2 sys_open */
+	.quad pms_sys_remote		/* 3 sys_close */
+	.quad pms_sys_remote		/* 4 sys_newstat */
+	.quad pms_sys_remote		/* 5 sys_newfstat */
+	.quad pms_sys_remote		/* 6 sys_newlstat */
+	.quad pms_sys_remote		/* 7 sys_poll */
+	.quad pms_sys_remote		/* 8 sys_lseek */
+	.quad sys_mmap			/* 9 sys_mmap */
+	.quad sys_mprotect		/* 10 sys_mprotect */
+	.quad sys_munmap		/* 11 sys_munmap */
+	.quad sys_brk			/* 12 sys_brk */
+	.quad sys_rt_sigaction		/* 13 sys_rt_sigaction */
+	.quad sys_rt_sigprocmask	/* 14 sys_rt_sigprocmask */
+	.quad stub_rt_sigreturn		/* 15 stub_rt_sigreturn */
+	.quad pms_sys_remote		/* 16 sys_ioctl */
+	.quad pms_sys_remote		/* 17 sys_pread64 */
+	.quad pms_sys_remote		/* 18 sys_pwrite64 */
+	.quad pms_sys_remote		/* 19 sys_readv */
+	.quad pms_sys_remote		/* 20 sys_writev */
+	.quad pms_sys_remote		/* 21 sys_access */
+	.quad pms_sys_remote		/* 22 sys_pipe */
+	.quad pms_sys_remote		/* 23 sys_select */
+	.quad pms_sys_remote		/* 24 sys_sched_yield */
+	.quad sys_mremap		/* 25 sys_mremap */
+	.quad sys_msync		/* 26 sys_msync */
+	.quad sys_mincore		/* 27 sys_mincore */
+	.quad sys_madvise		/* 28 sys_madvise */
+	.quad pms_sys_remote		/* 29 sys_shmget */
+	.quad pms_sys_remote		/* 30 wrap_sys_shmat */
+	.quad pms_sys_remote		/* 31 sys_shmctl */
+	.quad pms_sys_remote		/* 32 sys_dup */
+	.quad pms_sys_remote		/* 33 sys_dup2 */
+	.quad sys_pause		/* 34 sys_pause */
+	.quad sys_nanosleep		/* 35 sys_nanosleep */
+	.quad pms_sys_remote		/* 36 sys_getitimer */
+	.quad pms_sys_remote		/* 37 sys_alarm */
+	.quad pms_sys_remote		/* 38 sys_setitimer */
+	.quad pms_sys_getpid		/* 39 sys_getpid */
+	.quad pms_sys_remote		/* 40 sys_sendfile64 */
+	.quad pms_sys_remote		/* 41 sys_socket */
+	.quad pms_sys_remote		/* 42 sys_connect */
+	.quad pms_sys_remote		/* 43 sys_accept */
+	.quad pms_sys_remote		/* 44 sys_sendto */
+	.quad pms_sys_remote		/* 45 sys_recvfrom */
+	.quad pms_sys_remote		/* 46 sys_sendmsg */
+	.quad pms_sys_remote		/* 47 sys_recvmsg */
+	.quad pms_sys_remote		/* 48 sys_shutdown */
+	.quad pms_sys_remote		/* 49 sys_bind */
+	.quad pms_sys_remote		/* 50 sys_listen */
+	.quad pms_sys_remote		/* 51 sys_getsockname */
+	.quad pms_sys_remote		/* 52 sys_getpeername */
+	.quad pms_sys_remote		/* 53 sys_socketpair */
+	.quad pms_sys_remote		/* 54 sys_setsockopt */
+	.quad pms_sys_remote		/* 55 sys_getsockopt */
+	.quad pms_stub_clone		/* 56 stub_clone */
+	.quad pms_stub_fork		/* 57 stub_fork */
+	.quad pms_stub_vfork		/* 58 stub_vfork */
+	.quad pms_stub_execve		/* 59 stub_execve */
+	.quad pms_sys_remote		/* 60 sys_exit */
+	.quad pms_sys_remote		/* 61 sys_wait4 */
+	.quad pms_sys_remote		/* 62 sys_kill */
+	.quad pms_sys_remote		/* 63 sys_uname */
+	.quad pms_sys_remote		/* 64 sys_semget */
+	.quad pms_sys_remote		/* 65 sys_semop */
+	.quad pms_sys_remote		/* 66 sys_semctl */
+	.quad pms_sys_remote		/* 67 sys_shmdt */
+	.quad pms_sys_remote		/* 68 sys_msgget */
+	.quad pms_sys_remote		/* 69 sys_msgsnd */
+	.quad pms_sys_remote		/* 70 sys_msgrcv */
+	.quad pms_sys_remote		/* 71 sys_msgctl */
+	.quad pms_sys_remote		/* 72 sys_fcntl */
+	.quad pms_sys_remote		/* 73 sys_flock */
+	.quad pms_sys_remote		/* 74 sys_fsync */
+	.quad pms_sys_remote		/* 75 sys_fdatasync */
+	.quad pms_sys_remote		/* 76 sys_truncate */
+	.quad pms_sys_remote		/* 77 sys_ftruncate */
+	.quad pms_sys_remote		/* 78 sys_getdents */
+	.quad pms_sys_remote		/* 79 sys_getcwd */
+	.quad pms_sys_remote		/* 80 sys_chdir */
+	.quad pms_sys_remote		/* 81 sys_fchdir */
+	.quad pms_sys_remote		/* 82 sys_rename */
+	.quad pms_sys_remote		/* 83 sys_mkdir */
+	.quad pms_sys_remote		/* 84 sys_rmdir */
+	.quad pms_sys_remote		/* 85 sys_creat */
+	.quad pms_sys_remote		/* 86 sys_link */
+	.quad pms_sys_remote		/* 87 sys_unlink */
+	.quad pms_sys_remote		/* 88 sys_symlink */
+	.quad pms_sys_remote		/* 89 sys_readlink */
+	.quad pms_sys_remote		/* 90 sys_chmod */
+	.quad pms_sys_remote		/* 91 sys_fchmod */
+	.quad pms_sys_remote		/* 92 sys_chown */
+	.quad pms_sys_remote		/* 93 sys_fchown */
+	.quad pms_sys_remote		/* 94 sys_lchown */
+	.quad pms_sys_remote		/* 95 sys_umask */
+	.quad pms_sys_remote		/* 96 sys_gettimeofday */
+	.quad pms_sys_remote		/* 97 sys_getrlimit */
+	.quad pms_sys_remote		/* 98 sys_getrusage */
+	.quad pms_sys_remote		/* 99 sys_sysinfo */
+	.quad pms_sys_remote		/* 100 sys_times */
+	.quad pms_sys_remote		/* 101 sys_ptrace */
+	.quad pms_sys_remote		/* 102 sys_getuid */
+	.quad pms_sys_remote		/* 103 sys_syslog */
+	.quad pms_sys_remote		/* 104 sys_getgid */
+	.quad pms_sys_remote		/* 105 sys_setuid */
+	.quad pms_sys_remote		/* 106 sys_setgid */
+	.quad pms_sys_remote		/* 107 sys_geteuid */
+	.quad pms_sys_remote		/* 108 sys_getegid */
+	.quad pms_sys_remote		/* 109 sys_setpgid */
+	.quad pms_sys_remote		/* 110 sys_getppid */
+	.quad pms_sys_remote		/* 111 sys_getpgrp */
+	.quad pms_sys_remote		/* 112 sys_setsid */
+	.quad pms_sys_remote		/* 113 sys_setreuid */
+	.quad pms_sys_remote		/* 114 sys_setregid */
+	.quad pms_sys_remote		/* 115 sys_getgroups */
+	.quad pms_sys_remote		/* 116 sys_setgroups */
+	.quad pms_sys_remote		/* 117 sys_setresuid */
+	.quad pms_sys_remote		/* 118 sys_getresuid */
+	.quad sys_setresgid		/* 119 sys_setresgid */
+	.quad sys_getresgid		/* 120 sys_getresgid */
+	.quad pms_sys_remote		/* 121 sys_getpgid */
+	.quad sys_setfsuid		/* 122 sys_setfsuid */
+	.quad sys_setfsgid		/* 123 sys_setfsgid */
+	.quad sys_getsid		/* 124 sys_getsid */
+	.quad pms_sys_remote		/* 125 sys_capget */
+	.quad pms_sys_remote		/* 126 sys_capset */
+	.quad sys_rt_sigpending		/* 127 sys_rt_sigpending */
+	.quad sys_rt_sigtimedwait	/* 128 sys_rt_sigtimedwait */
+	.quad sys_rt_sigqueueinfo	/* 129 sys_rt_sigqueueinfo */
+	.quad pms_stub_rt_sigsuspend	/* 130 stub_rt_sigsuspend */
+	.quad pms_stub_sigaltstack	/* 131 stub_sigaltstack */
+	.quad pms_sys_remote		/* 132 sys_utime */
+	.quad pms_sys_remote		/* 133 sys_mknod */
+	.quad pms_sys_remote		/* 134 sys_uselib */
+	.quad pms_sys_remote		/* 135 sys_personality */
+	.quad pms_sys_remote		/* 136 sys_ustat */
+	.quad pms_sys_remote		/* 137 sys_statfs */
+	.quad pms_sys_remote		/* 138 sys_fstatfs */
+	.quad pms_sys_remote		/* 139 sys_sysfs */
+	.quad pms_sys_remote		/* 140 sys_getpriority */
+	.quad pms_sys_remote		/* 141 sys_setpriority */
+	.quad pms_sys_remote		/* 142 sys_sched_setparam */
+	.quad pms_sys_remote		/* 143 sys_sched_getparam */
+	.quad pms_sys_remote		/* 144 sys_sched_setscheduler */
+	.quad pms_sys_remote		/* 145 sys_sched_getscheduler */
+	.quad pms_sys_remote		/* 146 sys_sched_get_priority_max */
+	.quad pms_sys_remote		/* 147 sys_sched_get_priority_min */
+	.quad pms_sys_remote		/* 148 sys_sched_rr_get_interval */
+	.quad pms_sys_remote		/* 149 sys_mlock */
+	.quad pms_sys_remote		/* 150 sys_munlock */
+	.quad pms_sys_remote		/* 151 sys_mlockall */
+	.quad pms_sys_remote		/* 152 sys_munlockall */
+	.quad pms_sys_remote		/* 153 sys_vhangup */
+	.quad pms_sys_remote		/* 154 sys_modify_ldt */
+	.quad pms_sys_remote		/* 155 sys_pivot_root */
+	.quad pms_sys_remote		/* 156 sys_sysctl */
+	.quad pms_sys_remote		/* 157 sys_prctl */
+	.quad pms_sys_remote		/* 158 sys_arch_prctl */
+	.quad pms_sys_remote		/* 159 sys_adjtimex */
+	.quad pms_sys_remote		/* 160 sys_setrlimit */
+	.quad pms_sys_remote		/* 161 sys_chroot */
+	.quad pms_sys_remote		/* 162 sys_sync */
+	.quad pms_sys_remote		/* 163 sys_acct */
+	.quad pms_sys_remote		/* 164 sys_settimeofday */
+	.quad pms_sys_remote		/* 165 sys_mount */
+	.quad pms_sys_remote		/* 166 sys_umount */
+	.quad pms_sys_remote		/* 167 sys_swapon */
+	.quad pms_sys_remote		/* 168 sys_swapoff */
+	.quad pms_sys_remote		/* 169 sys_reboot */
+	.quad pms_sys_remote		/* 170 sys_sethostname */
+	.quad pms_sys_remote		/* 171 sys_setdomainname */
+	.quad pms_sys_remote		/* 172 stub_iopl */
+	.quad pms_sys_remote		/* 173 sys_ioperm */
+	.quad sys_ni_syscall		/* 174 */
+	.quad pms_sys_remote		/* 175 sys_init_module */
+	.quad pms_sys_remote		/* 176 sys_delete_module */
+	.quad sys_ni_syscall		/* 177 */
+	.quad sys_ni_syscall		/* 178 */
+	.quad pms_sys_remote		/* 179 sys_quotactl */
+	.quad pms_sys_remote		/* 180 sys_nfsservctl */
+	.quad sys_ni_syscall		/* 181 */
+	.quad sys_ni_syscall		/* 182 */
+	.quad sys_ni_syscall		/* 183 */
+	.quad sys_ni_syscall		/* 184 */
+	.quad sys_ni_syscall		/* 185 */
+	.quad pms_sys_gettid		/* 186 sys_gettid */
+	.quad pms_sys_remote		/* 187 sys_readahead */
+	.quad pms_sys_remote		/* 188 sys_setxattr */
+	.quad pms_sys_remote		/* 189 sys_lsetxattr */
+	.quad pms_sys_remote		/* 190 sys_fsetxattr */
+	.quad pms_sys_remote		/* 191 sys_getxattr */
+	.quad pms_sys_remote		/* 192 sys_lgetxattr */
+	.quad pms_sys_remote		/* 193 sys_fgetxattr */
+	.quad pms_sys_remote		/* 194 sys_listxattr */
+	.quad pms_sys_remote		/* 195 sys_llistxattr */
+	.quad pms_sys_remote		/* 196 sys_flistxattr */
+	.quad pms_sys_remote		/* 197 sys_removexattr */
+	.quad pms_sys_remote		/* 198 sys_lremovexattr */
+	.quad pms_sys_remote		/* 199 sys_fremovexattr */
+	.quad pms_sys_remote		/* 200 sys_tkill */
+	.quad pms_sys_remote		/* 201 sys_time64 */
+	.quad pms_sys_remote		/* 202 sys_futex */
+	.quad pms_sys_remote	 	/* 203 sys_sched_setaffinity */
+	.quad pms_sys_remote		/* 204 sys_sched_getaffinity */
+	.quad sys_ni_syscall		/* 205 */
+	.quad pms_sys_remote		/* 206 sys_io_setup */
+	.quad pms_sys_remote		/* 207 sys_io_destroy */
+	.quad pms_sys_remote		/* 208 sys_io_getevents */
+	.quad pms_sys_remote		/* 209 sys_io_submit */
+	.quad pms_sys_remote		/* 210 sys_io_cancel */
+	.quad sys_ni_syscall		/* 211 */
+	.quad pms_sys_remote		/* 212 sys_lookup_dcookie */
+	.quad pms_sys_remote		/* 213 sys_epoll_create */
+	.quad sys_ni_syscall		/* 214 */
+	.quad sys_ni_syscall		/* 215 */
+	.quad pms_sys_remote		/* 216 sys_remap_file_pages */
+	.quad pms_sys_remote		/* 217 sys_getdents64 */
+	.quad pms_sys_remote		/* 218 sys_set_tid_address */
+	.quad pms_sys_remote		/* 219 sys_restart_syscall */
+	.quad pms_sys_remote		/* 220 sys_semtimedop */
+	.quad pms_sys_remote		/* 221 sys_fadvise64 */
+	.quad pms_sys_remote		/* 222 sys_timer_create */
+	.quad pms_sys_remote		/* 223 sys_timer_settime */
+	.quad pms_sys_remote		/* 224 sys_timer_gettime */
+	.quad pms_sys_remote		/* 225 sys_timer_getoverrun */
+	.quad pms_sys_remote		/* 226 sys_timer_delete */
+	.quad pms_sys_remote		/* 227 sys_clock_settime */
+	.quad pms_sys_remote		/* 228 sys_clock_gettime */
+	.quad pms_sys_remote		/* 229 sys_clock_getres */
+	.quad pms_sys_remote		/* 230 sys_clock_nanosleep */
+	.quad pms_sys_remote		/* 231 sys_exit_group */
+	.quad pms_sys_remote		/* 232 sys_epoll_wait */
+	.quad pms_sys_remote		/* 233 sys_epoll_ctl */
+	.quad pms_sys_remote		/* 234 sys_tgkill */
+	.quad pms_sys_remote		/* 235 sys_utimes */
+	.quad sys_ni_syscall		/* 236 */
+	.quad sys_ni_syscall		/* 236 */
+	.quad sys_mbind			/* 237 sys_mbind */
+	.quad sys_set_mempolicy		/* 238 sys_set_mempolicy */
+	.quad sys_get_mempolicy		/* 239 sys_get_mempolicy */
+	.quad pms_sys_remote		/* 240 sys_mq_open */
+	.quad pms_sys_remote		/* 241 sys_mq_unlink */
+	.quad pms_sys_remote		/* 242 sys_mq_timedsend */
+	.quad pms_sys_remote		/* 243 sys_mq_timedreceive */
+	.quad pms_sys_remote		/* 244 sys_mq_notify */
+	.quad pms_sys_remote		/* 245 sys_mq_getsetattr */
+	.quad pms_sys_remote		/* 246 sys_kexec_load */
+	.quad pms_sys_remote		/* 247 sys_waitid */
+	.quad pms_sys_remote		/* 248 sys_add_key */
+	.quad pms_sys_remote		/* 249 sys_request_key */
+	.quad pms_sys_remote		/* 250 sys_keyctl */
+	.quad pms_sys_remote		/* 251 sys_ioprio_set */
+	.quad pms_sys_remote		/* 252 sys_ioprio_get */
+	.quad pms_sys_remote		/* 253 sys_inotify_init */
+	.quad pms_sys_remote		/* 254 sys_inotify_add_watch */
+	.quad pms_sys_remote		/* 255 sys_inotify_rm_watch */
+
+remote_syscall_table_size=(.-remote_sys_call_table)
+.text
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/process.c linux-2.6.28.7-pms/arch/x86/kernel/process.c
--- linux-2.6.28.7/arch/x86/kernel/process.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/process.c	2009-03-06 19:59:09.000000000 +0000
@@ -9,6 +9,8 @@
 #include <linux/clockchips.h>
 #include <asm/system.h>
 
+#include <linux/hpc.h>
+
 unsigned long idle_halt;
 EXPORT_SYMBOL(idle_halt);
 unsigned long idle_nomwait;
@@ -254,6 +256,37 @@
 	cpu_clear(cpu, c1e_mask);
 }
 
+#ifdef CONFIG_PMS
+extern void user_thread_helper(void);
+/*
+ * Create an user thread
+ * difference from kernel_thread are: no CLONE_VM, SIGCHLD, and leave space
+ * on the stack for user registers pt_regs.
+ */
+int user_thread(int (*fn)(void *), void * arg, unsigned long flags)
+{
+	struct pt_regs regs;
+
+	memset(&regs, 0, sizeof(regs));
+
+	regs.bx = (unsigned long) fn; // mig_handle_migration()
+	regs.dx = (unsigned long) arg; // rpid
+
+	regs.ds = __USER_DS;
+	regs.es = __USER_DS;
+	regs.fs = __KERNEL_PERCPU;
+	regs.orig_ax = -1;
+	regs.ip = (unsigned long) user_thread_helper;
+	regs.cs = __KERNEL_CS | get_kernel_rpl();
+	regs.flags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;
+	
+	regs.fs = __KERNEL_PERCPU;
+	regs.cs = __KERNEL_CS | get_kernel_rpl();
+	/* Ok, create the new process.. */
+	return do_fork(flags | SIGCHLD | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL);
+}
+#endif
+
 /*
  * C1E aware idle routine. We check for C1E active in the interrupt
  * pending message MSR. If we detect C1E, then we handle it the same
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/signal_32.c linux-2.6.28.7-pms/arch/x86/kernel/signal_32.c
--- linux-2.6.28.7/arch/x86/kernel/signal_32.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/signal_32.c	2009-03-06 19:59:09.000000000 +0000
@@ -598,7 +598,7 @@
  * want to handle. Thus you cannot kill init even with a SIGKILL even by
  * mistake.
  */
-static void do_signal(struct pt_regs *regs)
+PMS_NSTATIC void do_signal(struct pt_regs *regs)
 {
 	struct k_sigaction ka;
 	siginfo_t info;
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/signal_64.c linux-2.6.28.7-pms/arch/x86/kernel/signal_64.c
--- linux-2.6.28.7/arch/x86/kernel/signal_64.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/signal_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -398,7 +398,7 @@
  * want to handle. Thus you cannot kill init even with a SIGKILL even by
  * mistake.
  */
-static void do_signal(struct pt_regs *regs)
+PMS_NSTATIC void do_signal(struct pt_regs *regs)
 {
 	struct k_sigaction ka;
 	siginfo_t info;
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/sys_i386_32.c linux-2.6.28.7-pms/arch/x86/kernel/sys_i386_32.c
--- linux-2.6.28.7/arch/x86/kernel/sys_i386_32.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/sys_i386_32.c	2009-03-06 19:59:09.000000000 +0000
@@ -24,6 +24,8 @@
 
 #include <asm/syscalls.h>
 
+#include <linux/hpc.h>
+
 asmlinkage long sys_mmap2(unsigned long addr, unsigned long len,
 			  unsigned long prot, unsigned long flags,
 			  unsigned long fd, unsigned long pgoff)
@@ -34,6 +36,10 @@
 
 	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
 	if (!(flags & MAP_ANONYMOUS)) {
+#ifdef CONFIG_PMS
+		if (task_test_dflags(current, DREMOTE))
+			return remote_do_mmap(addr, len, prot, flags, fd, pgoff);
+#endif
 		file = fget(fd);
 		if (!file)
 			goto out;
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/sys_x86_64.c linux-2.6.28.7-pms/arch/x86/kernel/sys_x86_64.c
--- linux-2.6.28.7/arch/x86/kernel/sys_x86_64.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/sys_x86_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -14,6 +14,7 @@
 #include <linux/personality.h>
 #include <linux/random.h>
 #include <linux/uaccess.h>
+#include <linux/hpc.h>
 
 #include <asm/ia32.h>
 #include <asm/syscalls.h>
@@ -33,6 +34,10 @@
 	file = NULL;
 	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
 	if (!(flags & MAP_ANONYMOUS)) {
+#ifdef CONFIG_PMS
+		if (task_test_dflags(current, DREMOTE))
+			return remote_do_mmap(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
+#endif
 		file = fget(fd);
 		if (!file)
 			goto out;
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/kernel/vm86_32.c linux-2.6.28.7-pms/arch/x86/kernel/vm86_32.c
--- linux-2.6.28.7/arch/x86/kernel/vm86_32.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/kernel/vm86_32.c	2009-03-06 19:59:09.000000000 +0000
@@ -41,6 +41,7 @@
 #include <linux/ptrace.h>
 #include <linux/audit.h>
 #include <linux/stddef.h>
+#include <linux/hpc.h>
 
 #include <asm/uaccess.h>
 #include <asm/io.h>
@@ -159,6 +160,11 @@
 
 	ret->fs = current->thread.saved_fs;
 	loadsegment(gs, current->thread.saved_gs);
+#ifdef CONFIG_PMS
+	task_lock(current);
+	task_clear_stay(current, DSTAY_86);
+	task_unlock(current);
+#endif
 
 	return ret;
 }
@@ -208,6 +214,13 @@
 	struct task_struct *tsk;
 	int tmp, ret = -EPERM;
 
+#ifdef CONFIG_PMS
+	ret = -ENOMEM;
+	if (!task_go_home_for_reason(current, DSTAY_86))
+		goto out;
+	ret = -EPERM;
+#endif
+
 	tsk = current;
 	if (tsk->thread.saved_sp0)
 		goto out;
@@ -268,6 +281,11 @@
 	ret = -EFAULT;
 	if (tmp)
 		goto out;
+#ifdef CONFIG_PMS
+	ret = -ENOMEM;
+	if (!task_go_home_for_reason(current, DSTAY_86))
+		goto out;
+#endif
 	info.regs32 = &regs;
 	info.vm86plus.is_vm86pus = 1;
 	tsk->thread.vm86_info = (struct vm86_struct __user *)v86;
@@ -356,6 +374,11 @@
 
 	regs32 = save_v86_state(regs16);
 	regs32->ax = retval;
+#ifdef CONFIG_PMS
+        task_lock(current);
+        task_clear_stay(current, DSTAY_86);
+        task_unlock(current);
+#endif
 	__asm__ __volatile__("movl %0,%%esp\n\t"
 		"movl %1,%%ebp\n\t"
 		"jmp resume_userspace"
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/lib/copy_user_64.S linux-2.6.28.7-pms/arch/x86/lib/copy_user_64.S
--- linux-2.6.28.7/arch/x86/lib/copy_user_64.S	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/lib/copy_user_64.S	2009-03-06 19:59:09.000000000 +0000
@@ -73,6 +73,16 @@
 	jc bad_to_user
 	cmpq TI_addr_limit(%rax),%rcx
 	jae bad_to_user
+#ifdef CONFIG_PMS
+        /* pms_memory_away inlined */
+        cmpq $0xffffffffffffffff,threadinfo_addr_limit(%rax) /* compare to kernel DS */
+        je copy_to_user_orig
+        movq threadinfo_task(%rax), %rax
+        testq $DDEPUTY, TASK_pms+PMS_dflags(%rax) # is this a DDEPUTY task ?
+        jz copy_to_user_orig
+        jmp deputy_copy_to_user
+#endif /* CONFIG_PMS */
+copy_to_user_orig:
 	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
 	CFI_ENDPROC
 
@@ -85,6 +95,16 @@
 	jc bad_from_user
 	cmpq TI_addr_limit(%rax),%rcx
 	jae bad_from_user
+#ifdef CONFIG_PMS
+        /* pms_memory_away inlined */
+        cmpq $0xffffffffffffffff,threadinfo_addr_limit(%rax) /* compare to kernel DS */
+        je copy_from_user_orig
+        movq threadinfo_task(%rax), %rax
+        testq $DDEPUTY, TASK_pms+PMS_dflags(%rax) # is this a DDEPUTY task ?
+        jz copy_from_user_orig
+        jmp deputy_copy_from_user
+        copy_from_user_orig:
+#endif /* CONFIG_PMS */
 	ALTERNATIVE_JUMP X86_FEATURE_REP_GOOD,copy_user_generic_unrolled,copy_user_generic_string
 	CFI_ENDPROC
 ENDPROC(copy_from_user)
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/lib/usercopy_32.c linux-2.6.28.7-pms/arch/x86/lib/usercopy_32.c
--- linux-2.6.28.7/arch/x86/lib/usercopy_32.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/lib/usercopy_32.c	2009-03-06 19:59:09.000000000 +0000
@@ -14,6 +14,8 @@
 #include <asm/uaccess.h>
 #include <asm/mmx.h>
 
+#include <hpc/uaccess.h>
+
 #ifdef CONFIG_X86_INTEL_USERCOPY
 /*
  * Alignment at which movsl is preferred for bulk memory copies.
@@ -32,6 +34,15 @@
 #define movsl_is_ok(a1, a2, n) \
 	__movsl_is_ok((unsigned long)(a1), (unsigned long)(a2), (n))
 
+#ifdef CONFIG_PMS
+#define __strncpy_from_user_is_deputy_userspace(dst, src, count)	\
+	if (pms_memory_away())						\
+		return deputy_strncpy_from_user(dst, src, count);
+#else
+#define 
+#define __strncpy_from_user_is_deputy_userspace(dst, src, count)
+#endif
+
 /*
  * Copy a null terminated string from userspace.
  */
@@ -40,6 +51,7 @@
 do {									   \
 	int __d0, __d1, __d2;						   \
 	might_sleep();							   \
+	__strncpy_from_user_is_deputy_userspace(dst, src, count)	\
 	__asm__ __volatile__(						   \
 		"	testl %1,%1\n"					   \
 		"	jz 2f\n"					   \
@@ -199,6 +211,10 @@
 
 	might_sleep();
 
+#ifdef CONFIG_PMS
+	if (pms_memory_away())
+		return deputy_strnlen_user(s, n);
+#endif
 	__asm__ __volatile__(
 		"	testl %0, %0\n"
 		"	jz 3f\n"
diff --exclude=.git -Nru linux-2.6.28.7/arch/x86/lib/usercopy_64.c linux-2.6.28.7-pms/arch/x86/lib/usercopy_64.c
--- linux-2.6.28.7/arch/x86/lib/usercopy_64.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/arch/x86/lib/usercopy_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -42,6 +42,10 @@
 __strncpy_from_user(char *dst, const char __user *src, long count)
 {
 	long res;
+#ifdef CONFIG_PMS
+	if (pms_memory_away())
+		return deputy_strncpy_from_user(dst, src, count);
+#endif
 	__do_strncpy_from_user(dst, src, count, res);
 	return res;
 }
@@ -51,6 +55,10 @@
 strncpy_from_user(char *dst, const char __user *src, long count)
 {
 	long res = -EFAULT;
+#ifdef CONFIG_PMS
+	if (pms_memory_away())
+		return deputy_strncpy_from_user(dst, src, count);
+#endif
 	if (access_ok(VERIFY_READ, src, 1))
 		return __strncpy_from_user(dst, src, count);
 	return res;
@@ -112,6 +120,10 @@
 	long res = 0;
 	char c;
 
+#ifdef CONFIG_PMS
+	if (pms_memory_away())
+		return deputy_strnlen_user(s, n);
+#endif
 	while (1) {
 		if (res>n)
 			return n+1;
@@ -138,6 +150,10 @@
 	long res = 0;
 	char c;
 
+#ifdef CONFIG_PMS
+	if (pms_memory_away())
+		return deputy_strnlen_user(s, 0);
+#endif
 	for (;;) {
 		if (get_user(c, s))
 			return 0;
diff --exclude=.git -Nru linux-2.6.28.7/fs/namei.c linux-2.6.28.7-pms/fs/namei.c
--- linux-2.6.28.7/fs/namei.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/fs/namei.c	2009-03-06 19:59:09.000000000 +0000
@@ -143,6 +143,13 @@
 
 	result = ERR_PTR(-ENOMEM);
 	tmp = __getname();
+#ifdef CONFIG_PMS
+	/* g_remlin FIXME */
+	if (tmp && pms_memory_away()) {
+		deputy_strncpy_from_user(tmp, filename, PATH_MAX);
+		return tmp;
+	}
+#endif
 	if (tmp)  {
 		int retval = do_getname(filename, tmp);
 
diff --exclude=.git -Nru linux-2.6.28.7/fs/proc/base.c linux-2.6.28.7-pms/fs/proc/base.c
--- linux-2.6.28.7/fs/proc/base.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/fs/proc/base.c	2009-03-06 19:59:09.000000000 +0000
@@ -79,6 +79,7 @@
 #include <linux/oom.h>
 #include <linux/elf.h>
 #include <linux/pid_namespace.h>
+#include <linux/hpc.h>
 #include "internal.h"
 
 /* NOTE:
@@ -1464,6 +1465,7 @@
 
 /* dentry stuff */
 
+
 /*
  *	Exceptional case: normally we are not allowed to unhash a busy
  * directory. In this case, however, we can do it - no aliasing problems
@@ -1946,6 +1948,9 @@
 	if (p->fop)
 		inode->i_fop = p->fop;
 	ei->op = p->op;
+#ifdef CONFIG_PMS
+        inode->i_nlink += 1;
+#endif
 	dentry->d_op = &pid_dentry_operations;
 	d_add(dentry, inode);
 	/* Close the race of the process dying before we return the dentry */
@@ -2242,6 +2247,112 @@
 };
 #endif
 
+#ifdef CONFIG_PMS
+
+static ssize_t proc_pid_pms_read(struct file * file, char * buf,
+					size_t count, loff_t *ppos)
+{
+	struct inode * inode = file->f_dentry->d_inode;
+	unsigned long page;
+	ssize_t length;
+	ssize_t end;
+	struct task_struct *task = get_proc_task(inode);
+
+	if (count > PAGE_SIZE)
+		count = PAGE_SIZE;
+	if (!(page = __get_free_page(GFP_KERNEL)))
+		return -ENOMEM;
+
+	length = proc_pms_pid_getattr(task,
+	(char*)file->f_dentry->d_name.name,
+	(void*)page, count);
+	if (length < 0) {
+		free_page(page);
+		return length;
+	}
+	/* Static 4kB (or whatever) block capacity */
+	if (*ppos >= length) {
+		free_page(page);
+		return 0;
+	}
+	if (count + *ppos > length)
+		count = length - *ppos;
+	end = count + *ppos;
+	if (copy_to_user(buf, (char *) page + *ppos, count))
+		count = -EFAULT;
+	else
+		*ppos = end;
+	free_page(page);
+	return count;
+}
+
+static ssize_t proc_pid_pms_write(struct file * file, const char * buf,
+					size_t count, loff_t *ppos)
+{
+	struct inode * inode = file->f_dentry->d_inode;
+	char *page;
+	ssize_t length;
+	struct task_struct *task = get_proc_task(inode);
+
+	if (count > PAGE_SIZE)
+		count = PAGE_SIZE;
+	if (*ppos != 0) {
+		/* No partial writes. */
+		return -EINVAL;
+	}
+	page = (char*)__get_free_page(GFP_USER);
+	if (!page)
+		return -ENOMEM;
+	length = -EFAULT;
+	if (copy_from_user(page, buf, count))
+		goto out;
+
+	length = proc_pms_pid_setattr(task,
+					(char*)file->f_dentry->d_name.name,
+					(void*)page, count);
+out:
+	free_page((unsigned long) page);
+	return length;
+}
+
+static struct file_operations proc_pid_pms_operations = {
+	.read           = proc_pid_pms_read,
+	.write          = proc_pid_pms_write,
+ };
+
+static struct pid_entry pms_dir_stuff[] = {
+	REG("where",    S_IRUGO|S_IWUGO, pid_pms),
+	REG("stay",    S_IRUGO|S_IWUGO, pid_pms),
+	REG("debug",    S_IRUGO|S_IWUGO, pid_pms),
+};
+
+static int proc_pms_dir_readdir(struct file * filp,
+			     void * dirent, filldir_t filldir)
+{
+	return proc_pident_readdir(filp,dirent,filldir,
+				   pms_dir_stuff,ARRAY_SIZE(pms_dir_stuff));
+}
+
+static struct file_operations proc_pms_dir_operations = {
+	.read		= generic_read_dir,
+	.readdir	= proc_pms_dir_readdir,
+};
+
+static struct dentry *proc_pms_dir_lookup(struct inode *dir,
+				struct dentry *dentry, struct nameidata *nd)
+{
+	return proc_pident_lookup(dir, dentry,
+				  pms_dir_stuff, ARRAY_SIZE(pms_dir_stuff));
+}
+
+static struct inode_operations proc_pms_dir_inode_operations = {
+	.lookup		= proc_pms_dir_lookup,
+	.getattr	= pid_getattr,
+	.setattr	= proc_setattr,
+};
+
+#endif /* CONFIG_PMS */
+
 /*
  * /proc/self:
  */
@@ -2345,6 +2456,9 @@
 	if (p->fop)
 		inode->i_fop = p->fop;
 	ei->op = p->op;
+#ifdef CONFIG_PMS
+        inode->i_nlink += 1;
+#endif
 	dentry->d_op = &proc_base_dentry_operations;
 	d_add(dentry, inode);
 	error = NULL;
@@ -2518,6 +2632,9 @@
 #ifdef CONFIG_TASK_IO_ACCOUNTING
 	INF("io",	S_IRUGO, tgid_io_accounting),
 #endif
+#ifdef CONFIG_PMS
+	DIR("pms",      S_IRUGO|S_IXUGO, pms_dir),
+#endif
 };
 
 static int proc_tgid_base_readdir(struct file * filp,
@@ -2655,6 +2772,9 @@
 	inode->i_nlink = 2 + pid_entry_count_dirs(tgid_base_stuff,
 		ARRAY_SIZE(tgid_base_stuff));
 
+#ifdef CONFIG_PMS
+        inode->i_nlink += 1;
+#endif
 	dentry->d_op = &pid_dentry_operations;
 
 	d_add(dentry, inode);
@@ -2850,6 +2970,9 @@
 #ifdef CONFIG_TASK_IO_ACCOUNTING
 	INF("io",	S_IRUGO, tid_io_accounting),
 #endif
+#ifdef CONFIG_PMS
+	DIR("pms",      S_IRUGO|S_IXUGO, pms_dir),
+#endif
 };
 
 static int proc_tid_base_readdir(struct file * filp,
@@ -2892,6 +3015,9 @@
 	inode->i_nlink = 2 + pid_entry_count_dirs(tid_base_stuff,
 		ARRAY_SIZE(tid_base_stuff));
 
+#ifdef CONFIG_PMS
+        inode->i_nlink += 1;
+#endif
 	dentry->d_op = &pid_dentry_operations;
 
 	d_add(dentry, inode);
diff --exclude=.git -Nru linux-2.6.28.7/fs/proc/root.c linux-2.6.28.7-pms/fs/proc/root.c
--- linux-2.6.28.7/fs/proc/root.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/fs/proc/root.c	2009-03-06 19:59:09.000000000 +0000
@@ -19,6 +19,7 @@
 #include <linux/smp_lock.h>
 #include <linux/mount.h>
 #include <linux/pid_namespace.h>
+#include <linux/hpc.h>
 
 #include "internal.h"
 
@@ -137,6 +138,9 @@
 #endif
 	proc_mkdir("bus", NULL);
 	proc_sys_init();
+#ifdef CONFIG_PMS
+	proc_pms_init();
+#endif
 }
 
 static int proc_root_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat
diff --exclude=.git -Nru linux-2.6.28.7/fs/select.c linux-2.6.28.7-pms/fs/select.c
--- linux-2.6.28.7/fs/select.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/fs/select.c	2009-03-06 19:59:09.000000000 +0000
@@ -420,6 +420,9 @@
 
 	return retval;
 }
+#ifdef CONFIG_KCOMD_MODULE
+EXPORT_SYMBOL_GPL(do_select);
+#endif
 
 /*
  * We can actually return ERESTARTSYS instead of EINTR, but I'd
diff --exclude=.git -Nru linux-2.6.28.7/hpc/arch-i386.c linux-2.6.28.7-pms/hpc/arch-i386.c
--- linux-2.6.28.7/hpc/arch-i386.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/arch-i386.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,323 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/kernel.h>
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+
+#include <asm/uaccess.h>
+#include <asm/ptrace.h>
+#include <asm/desc.h>
+#include <asm/i387.h>
+#include <asm/cpufeature.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/remote.h>
+
+
+inline static void fxsave_to_fsave(union thread_xstate *to, union thread_xstate *from)
+{
+	u8 *fcp, *tcp;
+	int i;
+
+	to->fsave.cwd = from->fxsave.cwd;
+	to->fsave.swd = from->fxsave.swd;
+	to->fsave.twd = twd_fxsr_to_i387(&from->fxsave);
+	to->fxsave.padding[0] = from->fxsave.fop;
+	to->fsave.fip = from->fxsave.fip;
+	to->fsave.fcs = from->fxsave.fcs;
+	to->fsave.foo = from->fxsave.foo;
+	to->fxsave.padding[1] = from->fxsave.mxcsr;
+	to->fsave.fos = from->fxsave.fos;
+
+	fcp = (u8 *) from->fxsave.st_space;
+	tcp = (u8 *) to->fsave.st_space;
+
+	/* 8 registers of 16 bytes to copy to 10 bytes */
+	for (i = 0; i < 8; i++, tcp += 10, fcp += 16)
+		memcpy(tcp, fcp, 10);
+
+	memcpy(to->fxsave.xmm_space, from->fxsave.xmm_space,
+					sizeof(to->fxsave.xmm_space));
+}
+
+inline static void fsave_to_fxsave(union thread_xstate *to, union thread_xstate *from)
+{
+	u8 *fcp, *tcp;
+	int i;
+
+	to->fxsave.cwd = from->fsave.cwd;
+	to->fxsave.swd = from->fsave.swd;
+	to->fxsave.twd = twd_i387_to_fxsr(from->fsave.twd);
+	to->fxsave.fop = from->fxsave.padding[0];
+	to->fxsave.fip = from->fsave.fip;
+	to->fxsave.fcs = from->fsave.fcs;
+	to->fxsave.foo = from->fsave.foo;
+	to->fxsave.mxcsr = from->fxsave.padding[1];
+	to->fxsave.fos = from->fsave.fos;
+
+	fcp = (u8 *) from->fsave.st_space;
+	tcp = (u8 *) to->fxsave.st_space;
+
+	/* 8 registers of 10 bytes to copy to 16 bytes */
+	for (i = 0; i < 8; i++, tcp += 16, fcp += 10)
+		memcpy(tcp, fcp, 10);
+
+	memcpy(to->fxsave.xmm_space, from->fxsave.xmm_space,
+					sizeof(from->fxsave.xmm_space));
+}
+
+
+/*****************************************************************************/
+/* receive part */
+
+#if 0
+int arch_mig_receive_specific(struct task_struct *p, struct pmsp_mig_arch *m)
+{
+	switch (m->type)
+	{
+		case MIG_ARCH_I386_LDT:
+			printk(KERN_WARNING "PMS: mig arch ldt not handle yet.\n");
+			break;
+		default:
+			printk(KERN_ERR "PMS: mig arch type not handle.\n");
+			return 1;
+	}
+	return 0;
+}
+#endif
+
+int arch_mig_receive_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+	int i;
+
+	/* copy pt_regs */
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	memcpy(regs, &m->regs, sizeof(struct pt_regs));
+
+	/* debugs regs */
+	p->thread.debugreg0 = m->arch.debugreg[0];
+	p->thread.debugreg1 = m->arch.debugreg[1];
+	p->thread.debugreg2 = m->arch.debugreg[2];
+	p->thread.debugreg3 = m->arch.debugreg[3];
+	p->thread.debugreg6 = m->arch.debugreg[6];
+	p->thread.debugreg7 = m->arch.debugreg[7];
+
+	/* copy some segmentation registers */
+	p->thread.fs = m->arch.fs;
+	p->thread.gs = m->arch.gs;
+	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
+		p->thread.tls_array[i] = m->arch.tls_array[i];
+
+	return 0;
+}
+
+int arch_mig_receive_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	if (!p->thread.xstate)
+		p->thread.xstate = kmem_cache_alloc(task_xstate_cachep, GFP_KERNEL);
+	if (!p->thread.xstate)
+		return -ENOMEM;
+
+	unlazy_fpu(p);
+	if ((cpu_has_fxsr && fp->has_fxsr)
+	|| (!cpu_has_fxsr && !fp->has_fxsr))
+	{
+		/* same kind of cpu, just memcpy the structure */
+		WARN_ON((unsigned long)p->thread.xstate & 15);
+		memcpy(p->thread.xstate, &fp->xstate, xstate_size);
+		return 0;
+	}
+
+	if (fp->has_fxsr)
+		fxsave_to_fsave(p->thread.xstate, &fp->xstate);
+	else
+		fsave_to_fxsave(p->thread.xstate, &fp->xstate);
+
+	return 0;
+}
+
+/*****************************************************************************/
+/* send part */
+
+void arch_mig_send_pre(struct task_struct *p)
+{
+	if (p->mm->context.ldt)
+		clear_LDT();
+}
+
+void arch_mig_send_post(struct task_struct *p)
+{
+	if (p->mm->context.ldt)
+		load_LDT(&p->mm->context);
+}
+
+int arch_mig_send_specific(struct task_struct *p)
+{
+	mm_context_t *pc = &p->mm->context;
+
+	if (pc->size)
+		printk(KERN_WARNING "process has specific ldt\n");
+	return 0;
+}
+
+int arch_mig_send_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	//unlazy_fpu(p);
+	fp->has_fxsr = cpu_has_fxsr;
+	memcpy(&fp->xstate, p->thread.xstate, xstate_size); /* g_remlin - trust xstate_size ? */
+	return 0;
+}
+
+int arch_mig_send_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+	int i;
+
+	/* copy pt_regs */
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	memcpy(&m->regs, regs, sizeof(struct pt_regs));
+
+	/* There is no guarantee that the value of the %fs/%gs registers */
+	/* stored in the thread struct are accurate, use the real ones (TM) */
+	savesegment(fs, m->arch.fs);
+	savesegment(gs, m->arch.gs);
+
+	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
+		m->arch.tls_array[i] = p->thread.tls_array[i];
+
+	/* copy debugregs */
+	m->arch.debugreg[0] = p->thread.debugreg0;
+	m->arch.debugreg[1] = p->thread.debugreg1;
+	m->arch.debugreg[2] = p->thread.debugreg2;
+	m->arch.debugreg[3] = p->thread.debugreg3;
+	m->arch.debugreg[6] = p->thread.debugreg6;
+	m->arch.debugreg[7] = p->thread.debugreg7;
+
+	if (task_test_dflags(p, DDEPUTY))
+		memcpy(m->arch.features, boot_cpu_data.x86_capability,
+					sizeof(m->arch.features));
+
+	return 0;
+}
+
+
+asmlinkage void ret_from_kickstart(void) __asm__("ret_from_kickstart");
+
+NORET_TYPE void arch_kickstart(struct task_struct *p)
+{
+	struct pt_regs *regs;
+	regs = ARCH_TASK_GET_USER_REGS(p);
+
+	if (p->thread.debugreg7) {
+		set_debugreg(p->thread.debugreg0, 0);
+		set_debugreg(p->thread.debugreg1, 1);
+		set_debugreg(p->thread.debugreg2, 2);
+		set_debugreg(p->thread.debugreg3, 3);
+		set_debugreg(p->thread.debugreg6, 6);
+		set_debugreg(p->thread.debugreg7, 7);
+	}
+
+	load_TLS(&p->thread, smp_processor_id());
+
+	loadsegment(fs, p->thread.fs);
+	loadsegment(gs, p->thread.gs);
+
+	regs->cs = __USER_CS;
+
+	/* flush_thread(); */
+	/* FIXME: not sure about this one */
+	flush_signals(p);
+
+	asm(	"movl %0,%%esp\n\t"
+		"jmp ret_from_kickstart\n\t"
+		: /**/ : "r"(regs));
+}
+
+/*****************************************************************************/
+
+#include <hpc/syscalls.h>
+#include <asm/unistd.h>
+
+long arch_exec_syscall(int n, struct syscall_parameter * args)
+{
+	long ret;
+
+	PMSDEBUG_SYS(4, "exec_sys[%d](%lx, %lx, %lx, %lx, %lx, %lx)\n", n,
+			args->arg[0], args->arg[1], args->arg[2],
+			args->arg[3], args->arg[4], args->arg[5]);
+
+	/* g_remlin: revise! */
+	__asm__ __volatile__ (
+			"movl %0,%%eax\n\t"
+			"movl %1,%%ebx\n\t"
+			"movl %2,%%ecx\n\t"
+			"movl %3,%%edx\n\t"
+			"movl %4,%%edi\n\t"
+			"movl %5,%%esi\n\t"
+			"movl %%eax, %0\n\t"
+			"int $0x80\n\t"
+			: "=a" (ret)
+			: "b" (args->arg[0]), "c" (args->arg[1]), "d" (args->arg[2]),
+			"D" (args->arg[3]), "S" (args->arg[4]), "a" (n)
+			);
+	return (ret);
+
+	/*
+	syscall_func_t fct;
+	extern void * sys_call_table[];
+
+	fct = (syscall_func_t) sys_call_table[n];
+	return fct(*((struct syscall_parameter *) args));
+	*/
+}
+
+asmlinkage long pms_sys_fork(struct pt_regs regs)
+{
+	return remote_do_fork(SIGCHLD, regs.sp, &regs, 0, NULL, NULL);
+}
+
+asmlinkage long pms_sys_clone(struct pt_regs regs)
+{
+	unsigned long clone_flags;
+	unsigned long newsp;
+	int __user *parent_tidptr, *child_tidptr;
+	int retval;
+
+	clone_flags = regs.bx;
+	newsp = regs.cx;
+	parent_tidptr = (int __user *)regs.dx;
+	child_tidptr = (int __user *)regs.di;
+	if (!newsp)
+		newsp = regs.sp;
+	retval = remote_do_fork(clone_flags, newsp, &regs, 0, parent_tidptr, child_tidptr);
+	return retval;
+}
+
+/*****************************************************************************/
+
+extern void do_signal(struct pt_regs *regs);	/* g_remlin: not here! */
+
+void arch_do_signal(struct task_struct *p)
+{
+  do_signal(ARCH_TASK_GET_USER_REGS(p));
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/arch-ppc.c linux-2.6.28.7-pms/hpc/arch-ppc.c
--- linux-2.6.28.7/hpc/arch-ppc.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/arch-ppc.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,113 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <asm/uaccess.h>
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+#include <hpc/debug.h>
+#include <asm/ptrace.h>
+#include <hpc/prototype.h>
+#include <asm/processor.h>
+#include <hpc/arch.h>
+
+/*****************************************************************************/
+/* receive part */
+
+#if 0
+int arch_mig_receive_specific(struct task_struct *p, struct pmsp_mig_arch *m)
+{
+	return 0;
+}
+#endif
+
+int arch_mig_receive_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	memcpy(regs, &m->regs, sizeof(struct pt_regs));
+	return 0;
+}
+
+void arch_mig_receive_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	struct thread_struct *th = &p->thread;
+
+	memcpy(th->fpr, fp->fpr, sizeof(th->fpr));
+
+	th->fpscr_pad = fp->fpscr_pad; /* FIXME: not sure this one is needed */
+	th->fpscr = fp->fpscr;
+
+}
+
+/*****************************************************************************/
+/* send part */
+
+void arch_mig_send_pre(struct task_struct *p)
+{
+}
+
+void arch_mig_send_post(struct task_struct *p)
+{
+}
+
+int arch_mig_send_specific(struct task_struct *p)
+{
+	return 0;
+}
+
+int arch_mig_send_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	struct thread_struct *th = &p->thread;
+
+	memcpy(fp->fpr, th->fpr, sizeof(fp->fpr));
+
+	fp->fpscr_pad = th->fpscr_pad; /* FIXME: not sure this one is needed */
+	fp->fpscr = th->fpscr;
+	return 0;
+}
+
+int arch_mig_send_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	memcpy(&m->regs, &regs, sizeof(struct pt_regs));
+	return 0;
+}
+
+
+void arch_kickstart(struct task_struct *p)
+{
+	struct pt_regs *regs;
+
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	asm (	"mr 1, %0\n\t"
+		"b ret_from_kickstart\n\t"
+		: /**/ : "r"(regs));
+}
+
+long arch_exec_syscall(int n, struct syscall_parameter * args)
+{
+	syscall_func_t fct;
+	extern void * sys_call_table[];
+
+	fct = (syscall_func_t) sys_call_table[n];
+	return fct(*((struct syscall_parameter *) args));
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/arch-x86_64.c linux-2.6.28.7-pms/hpc/arch-x86_64.c
--- linux-2.6.28.7/hpc/arch-x86_64.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/arch-x86_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,234 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ * 
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <asm/uaccess.h>
+#include <linux/kernel.h>
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+#include <hpc/debug.h>
+#include <asm/ptrace.h>
+#include <asm/desc.h>
+#include <asm/i387.h>
+
+#include <hpc/arch.h>
+#include <hpc/task.h>
+#include <hpc/syscalls.h>
+#include <hpc/prototype.h>
+#include <hpc/remote.h>
+
+/*****************************************************************************/
+/* receive part */
+#if 0
+int arch_mig_receive_specific(struct task_struct *p, struct pmsp_mig_arch *m)
+{
+	return 0;
+}
+#endif
+
+int arch_mig_receive_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+
+	regs = ARCH_TASK_GET_USER_REGS(p);
+	memcpy(regs, &m->regs, sizeof(struct pt_regs));
+
+	p->thread.ds = m->arch.ds;
+	p->thread.es = m->arch.es;
+	p->thread.fs = m->arch.fs;
+	p->thread.gs = m->arch.gs;
+	p->thread.fsindex = m->arch.fsindex;
+	p->thread.gsindex = m->arch.gsindex;
+	p->thread.userrsp = m->arch.userrsp;
+	write_pda(oldrsp, m->arch.userrsp);
+
+	return 0;
+}
+
+void arch_mig_receive_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	if (!p->thread.xstate)
+		p->thread.xstate = kmem_cache_alloc(task_xstate_cachep, GFP_KERNEL);
+	if (!p->thread.xstate)
+		return -ENOMEM;
+
+	unlazy_fpu(p);
+
+	if ((cpu_feature_has_fxsr() && fp->has_fxsr)
+	|| (!cpu_feature_has_fxsr() && !fp->has_fxsr))
+	{
+		/* same kind of cpu, just memcpy the structure */
+		WARN_ON((unsigned long)p->thread.xstate & 15);
+		memcpy(p->thread.xstate, &fp->xstate, xstate_size);
+		return 0;
+	}
+
+	if (fp->has_fxsr)
+		fxsave_to_fsave(p->thread.xstate, &fp->xstate);
+	else
+		fsave_to_fxsave(p->thread.xstate, &fp->xstate);
+
+}
+
+/*****************************************************************************/
+/* send part */
+
+void arch_mig_send_pre(struct task_struct *p)
+{
+	if (p->mm->context.ldt)
+		clear_LDT();
+}
+
+void arch_mig_send_post(struct task_struct *p)
+{
+	if (p->mm->context.ldt)
+		load_LDT(&p->mm->context);
+}
+
+int arch_mig_send_specific(struct task_struct *p)
+{
+	return 0;
+}
+
+int arch_mig_send_fp(struct task_struct *p, struct pmsp_mig_fp *fp)
+{
+	unlazy_fpu(p);
+	memcpy(&fp->data, &p->thread.i387, sizeof(p->thread.i387));
+	return 0;
+}
+
+int arch_mig_send_proc_context(struct task_struct *p, struct pmsp_mig_task *m)
+{
+	struct pt_regs *regs;
+	int i;
+	unsigned int fstmp;
+
+	regs = ARCH_TASK_GET_USER_REGS(p);
+
+	memcpy(&m->regs, regs, sizeof(struct pt_regs));
+
+	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
+		m->arch.tls_array[i] = p->thread.tls_array[i];
+
+	m->arch.ds = p->thread.ds;
+	m->arch.es = p->thread.es;
+
+	/* at this point, registers are not yet in the thread struct, since we */
+	/* did not schedule, we have to read it directly from the registers    */
+
+	rdmsrl(MSR_FS_BASE, m->arch.fs);
+
+	__asm__ __volatile__ ("\t movl %%fs, %0;\n": "=r" (fstmp));
+	p->thread.fsindex = fstmp;		/* Fxxxxg gcc not understanding offsets!*/
+
+	rdmsrl(MSR_KERNEL_GS_BASE, m->arch.gs); /*usermode gs because of swapgs*/
+
+	m->arch.gsindex = p->thread.gsindex;
+	m->arch.userrsp = read_pda(oldrsp);
+
+	return 0;
+}
+
+
+asmlinkage void ret_from_kickstart(void) __asm__("ret_from_kickstart");
+
+void arch_kickstart(struct task_struct *p)
+{
+	/* regs must stay first !!!!!!!! it mark the stacj start*/
+	struct pt_regs *regs;
+	regs = ARCH_TASK_GET_USER_REGS(p);
+
+	if (p->thread.debugreg7) {
+		set_debugreg(p->thread.debugreg0, 0);
+		set_debugreg(p->thread.debugreg1, 1);
+		set_debugreg(p->thread.debugreg2, 2);
+		set_debugreg(p->thread.debugreg3, 3);
+		set_debugreg(p->thread.debugreg6, 6);
+		set_debugreg(p->thread.debugreg7, 7);
+	}
+
+	if (p->thread.ds)
+		loadsegment(ds, p->thread.ds);
+
+	if (p->thread.es)
+		loadsegment(es, p->thread.es);
+
+	if (p->thread.fsindex)
+		loadsegment(fs, p->thread.fsindex);
+
+	if (p->thread.fs)
+		wrmsrl(MSR_FS_BASE, p->thread.fs);
+
+	if (p->thread.gsindex)
+		load_gs_index(p->thread.gsindex);
+
+	load_TLS(&p->thread, smp_processor_id());
+
+	regs->cs = __USER_CS;
+	regs->ss = __USER_DS;
+	set_fs(USER_DS);
+
+	flush_signals(p);
+
+	asm(	"movq %0,%%rsp\n\t"
+		"jmp ret_from_kickstart\n\t"
+		: /**/ : "r"(regs));
+
+	/*(regs is the first variable, hence, the stack start */
+}
+
+long arch_exec_syscall(int n, struct syscall_parameter * args)
+{
+	long ret;
+
+	asm (	"movq %5, %%r8\n\t"
+		"movq %6, %%r9\n\t"
+		"call *sys_call_table(,%%rax,8)\n\t"
+		: "=a" (ret)
+		: "D" (args->arg[0]), "S" (args->arg[1]), "d" (args->arg[2]),
+		  "c" (args->arg[3]), "g" (args->arg[4]), "g" (args->arg[5]),
+		  "a" (n)
+		: "memory", "r8", "r9");
+
+	return ret;
+}
+
+asmlinkage long pms_sys_fork(struct pt_regs regs)
+{
+	return remote_do_fork(SIGCHLD, regs.rsp, &regs, 0, NULL, NULL);
+}
+
+extern PMS_NSTATIC void fastcall do_signal(struct pt_regs *regs);
+
+/*****************************************************************************/
+void arch_do_signal(struct task_struct *p)
+{
+  do_signal(ARCH_TASK_GET_USER_REGS(p));
+}
+
+/*****************************************************************************/
+
+#define NOT_IMPLEMENTED(fct)					\
+asmlinkage long fct(struct pt_regs regs)			\
+{ printk(KERN_ERR #fct "not yet implemented\n"); return -1; }
+
+NOT_IMPLEMENTED(pms_sys_iopl)
+NOT_IMPLEMENTED(pms_sys_vfork)
+NOT_IMPLEMENTED(pms_sys_clone)
+NOT_IMPLEMENTED(pms_sys_rt_sigsuspend)
+NOT_IMPLEMENTED(pms_sys_sigaltstack)
diff --exclude=.git -Nru linux-2.6.28.7/hpc/copyuser.c linux-2.6.28.7-pms/hpc/copyuser.c
--- linux-2.6.28.7/hpc/copyuser.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/copyuser.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,465 @@
+/*
+ *	Copyright (C) 2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/in.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+
+/*******************************************************************************
+ * Deputy command part                                                         *
+ ******************************************************************************/
+
+/**
+ * deputy_copy_from_user - Copy from remote when running on deputy
+ * @to:     kernelspace address to copy to
+ * @from:   userspace address to copy from
+ * @n:      size of data to copy
+ **/
+unsigned long deputy_copy_from_user(void *to, const void __user *from
+                                   , unsigned long n)
+{
+	struct pmsp_usercopy_req u;
+	struct task_struct *p=current;
+        struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+	int err;
+
+	PMSDEBUG_CPYUSER(2, "user[0x%p]->[0x%p][%ld]\n",from, to, n);
+
+	if (in_atomic())
+		return n;
+
+	u.addr = (unsigned long) from;
+	u.len = n;
+
+
+        err = kcom_send_command(KCOM_L2_REQ_COPY_FROM_USER, sizeof(u), (char*)&u, 0
+                               ,dest_ptr, &pkt);
+
+        if (err<0)
+                return err;
+
+	if (pkt->data_len != n)
+	    goto error;
+
+	PMSDEBUG_CPYUSER(3, "copy_from_user answered from remote\n");
+
+	memcpy(to, pkt->data, n);
+        kcom_pkt_delete(pkt);
+
+	return 0;
+
+error:
+	PMSERR("remote copy_from_user unexpected data size\n");
+	kcom_pkt_delete(pkt);
+	return -EINVAL;
+}
+EXPORT_SYMBOL(deputy_copy_from_user);
+
+/**
+ * deputy_strncpy_from_user - strncpy on remote when running on deputy
+ * @dst:     kernelspace address to copy to
+ * @src:   userspace address to copy from
+ * @count:      size of data to copy
+ **/
+unsigned long deputy_strncpy_from_user(char *dst, const char __user *src
+				      ,long count)
+{
+        struct kcom_pkt *pkt;
+	struct pmsp_usercopy_req u;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+	int err;
+
+	PMSDEBUG_CPYUSER(2, "user[0x%p]->[0x%p][%ld]\n", src, dst, count);
+
+	u.addr = (unsigned long) src;
+	u.len = count;
+
+	printk(KERN_ERR "strncpy_from_user request [0x%p]->[0x%p][%ld]\n", (void *)u.addr, dst, u.len);
+        err = kcom_send_command(KCOM_L2_REQ_STRNCPY_FROM_USER, sizeof(u)
+			       ,(char*)&u, 0,dest_ptr, &pkt);
+        if (err<0)
+                return err;
+
+	printk(KERN_ERR "strncpy_from_user reply [0x%p]->[0x%p][%d] [%s]\n", (void *)u.addr, dst, pkt->data_len, pkt->data);
+
+	if (pkt->data_len < 0)
+		goto error;
+
+	if (likely(pkt->data_len))
+		memcpy(dst, pkt->data, pkt->data_len);
+	else
+		*dst = '\0';
+
+	printk(KERN_ERR "memcpy(0x%p,0x%p,%d) completed!\n", dst, pkt->data, pkt->data_len);
+        kcom_pkt_delete(pkt);
+	return 0;
+
+error:
+	PMSERR("[deputy] strncpy_from_user unexpected data size\n");
+	kcom_pkt_delete(pkt);
+	return -EINVAL;
+}
+
+/**
+ * deputy_copy_to_user - copy to remote when running on deputy
+ * @to:     userspace address to copy to
+ * @from:   kernelspace address to copy from
+ * @count:      size of data to copy
+ **/
+unsigned long deputy_copy_to_user(void __user *to, const void *from, unsigned long n)
+{
+	int err;
+	char *buf;
+	struct task_struct *p=current;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+
+	if (in_atomic())
+		return n;
+
+	PMSDEBUG_CPYUSER(2, "user[0x%p]<-[0x%p][%ld]\n",to, from, n);
+
+	buf=kzalloc(n, GFP_KERNEL);
+	memcpy(buf, from, n);
+
+        err = kcom_send_command(KCOM_L2_REQ_COPY_TO_USER, n, buf, (unsigned long) to
+			       ,dest_ptr, NULL);
+
+        kfree(buf);
+
+        return err;
+
+}
+EXPORT_SYMBOL(deputy_copy_to_user);
+
+/**
+ * deputy_strnlen_user - strnlen on remote when running on deputy
+ **/
+unsigned long deputy_strnlen_user(const char *s, long n)
+{
+	struct pmsp_usercopy_req u;
+	long ret;
+	int err;
+        struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+
+	PMSDEBUG_CPYUSER(2, "strlen user[0x%p][%ld]\n", s, n);
+	u.addr = (unsigned long) s;
+	u.len = n;
+
+        err = kcom_send_command(KCOM_L2_REQ_STRNLEN_USER, sizeof(u)
+			       ,(char*)&u, 0, dest_ptr, &pkt);
+        if (err < 0)
+                return err;
+
+	PMSDEBUG_CPYUSER(3, "strlen remote answered %ld\n", *(long*)pkt->data);
+
+        ret = *(long *)pkt->data;
+        kcom_pkt_delete(pkt);
+
+        return ret;
+}
+EXPORT_SYMBOL(deputy_strnlen_user);
+
+/**
+ * deputy_put_userX - put a value of 64 bit or less to remote
+ **/
+static inline long deputy_put_userX(s64 value, const void *addr, size_t size)
+{
+	struct pmsp_usercopy_emb u;
+	struct task_struct *p=current;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+
+	PMSDEBUG_CPYUSER(2, "put (%lld)->user[0x%p][%zd]\n", value, addr, size);
+
+	u.addr = (unsigned long) addr;
+	u.len = size;
+	u.val = value;
+
+        return kcom_send_command(KCOM_L2_REQ_PUT_USER, sizeof(u)
+				,(char*)&u, 0, dest_ptr, NULL);
+}
+
+/**
+ * deputy_put_user - put a (char to long) value to remote
+ **/
+long deputy_put_user(long value, const void *addr, size_t size)
+{
+	PMSDEBUG_CPYUSER(2, "put (%ld)->user[0x%p][%zd]\n", value, addr, size);
+
+	BUG_ON(size > sizeof(long));
+	return deputy_put_userX((s64) value, addr, size);
+}
+EXPORT_SYMBOL(deputy_put_user);
+
+#if BITS_PER_LONG < 64
+/**
+ * deputy_put_user - put a 64 bit value to remote
+ **/
+long deputy_put_user64(s64 value, const void *addr)
+{
+	return deputy_put_userX(value, addr, 8);
+}
+EXPORT_SYMBOL(deputy_put_user64);
+#endif
+
+/**
+ * deputy_get_userX - get a value of 64 bit or less from remote
+ **/
+static inline long deputy_get_userX(s64 *value, const void *addr, size_t size)
+{
+	struct task_struct *p=current;
+	struct pmsp_usercopy_req u;
+        struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+	int err;
+
+	PMSDEBUG_CPYUSER(2, "get user[0x%p][%zd]\n", addr, size);
+
+	u.addr = (unsigned long) addr;
+	u.len = size;
+
+        err = kcom_send_command(KCOM_L2_REQ_GET_USER, sizeof(u)
+			       ,(char*)&u, 0, dest_ptr, &pkt);
+
+        if (err<0)
+                return err;
+
+	PMSDEBUG_CPYUSER(3, "get user answered from remote\n");
+        *value = * (s64 *) pkt->data;
+
+        kcom_pkt_delete(pkt);
+        return 0;
+}
+
+/**
+ * deputy_get_user - get a long value from remote
+ **/
+long deputy_get_user(long *value, const void *addr, size_t size)
+{
+	BUG_ON(size > sizeof(long));
+	return deputy_get_userX((u64 *) value, addr, size);
+}
+EXPORT_SYMBOL(deputy_get_user);
+
+#if BITS_PER_LONG < 64
+/**
+ * deputy_get_user - get a 64 bit value from remote
+ **/
+long deputy_get_user64(s64 *value, const void *addr)
+{
+	return deputy_get_userX(value, addr, 8);
+}
+EXPORT_SYMBOL(deputy_get_user64);
+#endif
+
+/*******************************************************************************
+ * Remote handling part                                                        *
+ ******************************************************************************/
+
+/**
+ * remote_copy_from_user - Copy to or from user for deputy
+ **/
+int remote_copy_from_user(struct kcom_task *tsk
+                                ,const struct kcom_pkt *const pkt)
+{
+        struct task_struct *p = tsk->task;
+	struct pmsp_usercopy_req u;
+	void *buf = NULL;
+	int ret;
+
+        PMSDEBUG_CPYUSER(2, "[remote] received copy_from_user request\n");
+	memcpy(&u, pkt->data, pkt->data_len);
+
+	buf = kmalloc(u.len, GFP_KERNEL);
+	if (!buf)
+		goto out;
+
+	ret = copy_from_user(buf, (const void __user *) u.addr, u.len);
+
+	ret = kcom_send_resp(p, u.len, buf, pkt);
+        kfree(buf);
+        return ret;
+
+out:
+	PMSERR("Can't allocate answer space\n");
+        kcom_send_nack(p, pkt);
+	kfree(buf);
+	return -ENOMEM;
+}
+
+int remote_copy_to_user(struct kcom_task *tsk __attribute__((unused))
+		       ,const struct kcom_pkt * const pkt)
+{
+	int ret;
+
+	PMSDEBUG_CPYUSER(2, "[remote] received copy_to_user request\n");
+	ret=copy_to_user((void __user *) pkt->addr, pkt->data, pkt->data_len);
+	return ret;
+
+}
+
+/**
+ * remote_strncpy_from_user - strncpy from user for deputy
+ **/
+int remote_strncpy_from_user(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+        struct task_struct *p = tsk->task;
+	const struct pmsp_usercopy_req * const u = (struct pmsp_usercopy_req*) pkt->data;
+	void *buf = NULL;
+	int ret,len;
+
+	PMSDEBUG_CPYUSER(2, "[remote] received strncpy_from_user request\n");
+
+	len = strnlen_user((const char __user *) u->addr, u->len);
+	if (unlikely((len<=0)||(len>u->len))) {
+		PMSDEBUG_CPYUSER(1, "Can't determine string length\n");
+		goto out;
+	}
+
+	buf = kmalloc(len, GFP_KERNEL);
+	if (unlikely(!buf)) {
+		PMSDEBUG_CPYUSER(1, "Can't allocate answer space\n");
+		goto out;
+	}
+
+	ret = strncpy_from_user(buf, (const char __user *) u->addr, len);
+	if (unlikely(ret<0)) {
+		PMSDEBUG_CPYUSER(1, "Error strncpy_from_user %d\n",ret);
+		goto out;
+	}
+
+	ret = kcom_send_resp(p, len, buf, pkt);
+#if 0
+	buf = kmalloc(u->len, GFP_KERNEL);
+	if (unlikely(!buf)) {
+		PMSDEBUG_CPYUSER(1, "Can't allocate answer space\n");
+		goto out;
+	}
+
+	ret = strncpy_from_user(buf, (const char __user *) u->addr, u->len);
+	if (unlikely(ret<0)) {
+		PMSDEBUG_CPYUSER(1, "Error strncpy_from_user %d\n",ret);
+		goto out;
+	}
+
+	ret = kcom_send_resp(p, u->len, buf, pkt);
+#endif
+	if (unlikely(ret<0)) {
+		PMSDEBUG_CPYUSER(1, "Error kcom_send_resp %d\n",ret);
+		goto out;
+	}
+
+        kfree(buf);
+	return ret;
+
+out:
+	if(buf)
+		kfree(buf);
+	kcom_send_nack(p, pkt);
+	return -ENOMEM;
+}
+
+/**
+ * remote_strnlen_user - strnlen from user for deputy
+ **/
+int remote_strnlen_user(struct kcom_task* tsk, const struct kcom_pkt *const pkt)
+{
+	long ret_ptr;
+	const struct pmsp_usercopy_req * const u = (struct pmsp_usercopy_req*) pkt->data;
+
+	PMSDEBUG_CPYUSER(2, "[remote] received strlen_user request\n");
+
+	ret_ptr = (u->len)
+		? strnlen_user((const char __user *) u->addr, u->len)
+		: strlen_user((const char __user *) u->addr);
+
+	return kcom_send_resp(tsk->task, sizeof(ret_ptr), (char *)&ret_ptr, pkt);
+}
+
+/**
+ * remote_put_user - put user for deputy
+ **/
+int remote_put_user(struct kcom_task* tsk __attribute__((unused))
+			  ,const struct kcom_pkt *const pkt)
+{
+	long ret;
+	const struct pmsp_usercopy_emb * const u = (struct pmsp_usercopy_emb*) pkt->data;;
+
+	PMSDEBUG_CPYUSER(2, "[remote] received put_user request\n");
+
+        switch (u->len) {
+                case 1:
+                        ret = put_user(u->val, (u8 *) u->addr);
+                        break;
+                case 2:
+                        ret = put_user(u->val, (u16 *) u->addr);
+                        break;
+                case 4:
+                        ret = put_user(u->val, (u32 *) u->addr);
+                        break;
+                case 8:
+                        ret = put_user(u->val, (u64 *) u->addr);
+                        break;
+                default:
+			ret = -EFAULT;
+			break;
+        }
+
+	return ret;
+}
+
+/**
+ * remote_get_user - get user for deputy
+ **/
+int remote_get_user(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+        int err = 0;
+	s64 ret = 0;
+	const struct pmsp_usercopy_req * const u = (struct pmsp_usercopy_req*) pkt->data;
+
+	PMSDEBUG_CPYUSER(2, "[remote] received get_user request\n");
+
+        switch (u->len) {
+                case 1:
+                        err = get_user(ret, (u8 *) u->addr);
+                        break;
+                case 2:
+                        err = get_user(ret, (u16 *) u->addr);
+                        break;
+                case 4:
+                        err = get_user(ret, (u32 *) u->addr);
+                        break;
+        #if BITS_PER_LONG == 64
+                case 8:
+                        err = get_user(ret, (u64 *) u->addr);
+                        break;
+        #endif
+		default:
+			err = -EFAULT;
+			break;
+        }
+
+        if (likely(err>= 0)) {
+		return kcom_send_resp(tsk->task, sizeof(ret), (char *)&ret, pkt);
+	}
+
+	PMSDEBUG_CPYUSER(1, "get_user returned an error %d\n", err);
+        kcom_send_nack(tsk->task, pkt);
+        return err;
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/debug.c linux-2.6.28.7-pms/hpc/debug.c
--- linux-2.6.28.7/hpc/debug.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/debug.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,292 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/kallsyms.h>
+#include <asm/uaccess.h>
+#include <net/sock.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+
+#ifdef CONFIG_PMS_DEBUG
+/*
+        int debug_mig;
+        int debug_sys;
+        int debug_rino;
+        int debug_copyuser;
+        int debug_kcomd;
+        int debug_protocol;
+*/
+struct pms_options pms_opts = {1,2,6,1,1,1};
+EXPORT_SYMBOL_GPL(pms_opts);
+
+/*******************************************************************************
+ * Protocol debug, used to dump a packet                                       *
+ ******************************************************************************/
+
+int pms_debug_do_switch = 0;
+
+
+void pms_format_dflags(unsigned int dflags, char* buffer, size_t size)
+{
+	snprintf(buffer, size, "%s %s %s %s %s %s %s",
+	dflags & DDEPUTY ? "DDEPUTY" : "-" ,
+	dflags & DREMOTE ? "DREMOTE" : "-" ,
+	dflags & DINCOMING ? "DINCOMING" : "-" ,
+	dflags & DPASSING ? "DPASSING" : "-" ,
+	dflags & DSPLIT ? "DSPLIT" : "-" ,
+	dflags & DFINISHED ? "DFINISHED" : "-" ,
+	dflags & DREMOTEDAEMON ? "DREMOTEDAEMON" : "-" );
+}
+#define BUFSIZ 80
+void pms_dump_dflags(struct task_struct *p)
+{
+        char buffer[BUFSIZ];
+
+	pms_format_dflags(p->pms.dflags, buffer, BUFSIZ);
+
+        printk(KERN_DEBUG"[PMS] =========================== task dflags dump==============================\n");
+        printk(KERN_DEBUG"[PMS] task dflags=0x%x: %s\n", p->pms.dflags, buffer);
+        printk(KERN_DEBUG"[PMS] =========================== task dflags dump==============================\n");
+}
+
+/**
+ *
+ * pms_format_flags
+ *
+ * Description:
+ * format the flags of a packet in a human readable
+ * format
+ * @buffer the buffer to write to (need at least 57 chars)
+ **/
+
+void pms_format_flags(unsigned int flags, char* buffer)
+{
+        char *msg_mask_names[] = {
+                                [CASE_PKT_NEW_MSG]      = "new",
+                                [CASE_PKT_ACK]          = "ack",
+                                [CASE_PKT_ACK_PROGRESS] = "ackp",
+                                [CASE_PKT_NACK]         = "nack",
+                                [CASE_PKT_RESP]         = "resp"};
+
+        char *syn_flg[] = {"async", "SYNC"};
+        char *cpl_flg[] = {"simple", "COMPLEX"};
+        char *ack_flg[] = {"kcom_acked", "TSK_ACKED"};
+
+        char *dep_flg[] = {"dep", "DEP" };
+        char *mig_flg[] = {"mig", "MIG" };
+        char *rem_flg[] = {"rem", "REM" };
+
+        char *oob_flg[] = {"inband", "OUTBAND"};
+
+        sprintf(buffer, "%s %s %s:%s:%s %s:%s:%s"
+                        , oob_flg[ (flags&KCOM_PKT_OOB) ? 1 : 0 ]
+                        , msg_mask_names[__kcom_msg_flags(flags) >> 0]
+
+                        , syn_flg[(flags & KCOM_PKT_SYNC) ? 1 : 0]
+                        , cpl_flg[(flags & KCOM_PKT_CPLX) ? 1 : 0]
+                        , flags&KCOM_PKT_SYNC ? ack_flg[(flags & KCOM_PKT_TSK_ACKED) ? 1 : 0] : "not_acked"
+
+                        , rem_flg[(flags & KCOM_PKT_REM_FLG) ? 1 : 0]
+                        , mig_flg[(flags & KCOM_PKT_MIG_FLG) ? 1 : 0]
+                        , dep_flg[(flags & KCOM_PKT_DEP_FLG) ? 1 : 0]
+               );
+}
+
+
+/**
+ * hexdump
+ * Description
+ * Produces a hexdump of the given buffer
+ * @buff : raw data
+ * @len : length to display
+ **/
+void hexdump(const unsigned char* const const buff, int len)
+{
+        int i, dumped = 0;
+        int h = 0, a = 0;
+        int inc = 0;
+
+        char hexbuf[64];
+        char asciibuf[64];
+
+        if (!buff || len <= 0) return;
+
+        for (i = 0; i < len; i++) {
+                dumped = 0;
+
+                h += sprintf(hexbuf + h, "%02X", buff[i]);
+
+                if (0x20 <=buff[i] && 0x7f > buff[i]) asciibuf[a] = buff[i];
+                else asciibuf[a] = '.';
+
+                a++;
+
+               if (35==h) {
+                        asciibuf[a] = 0;
+                        hexbuf[h] = 0;
+                        printk(KERN_DEBUG"[PMS] dump |%s| |%s|\n", hexbuf, asciibuf);
+                        dumped = 1;
+                        a = 0;
+                        h = 0;
+                        inc = 0;
+
+                } else if (0 == ((h - inc)% 8)) {
+                        hexbuf[h++] = ' ';
+                        inc++ ;
+                }
+
+        }
+
+        if (!dumped) {
+                hexbuf[h] = 0;
+                asciibuf[a] = 0;
+                printk(KERN_DEBUG"[PMS] dump |%-35.35s| |%-16.16s|\n", hexbuf, asciibuf);
+        }
+
+}
+
+/**
+ * pms_dump_packet_hdr
+ *
+ * Description
+ * dump the packet to the console in a readable way
+ *
+ * @param pkt : the packet to dump
+ **/
+
+void pms_dump_packet_hdr(const struct kcom_pkt* const pkt)
+{
+
+        if (!pkt) {
+                PMSERR("packet is null, can't dump header\n");
+                return;
+        }
+
+
+        printk(KERN_DEBUG"[PMS] pktdump RAW header dump -------------------------------------\n");
+        hexdump((char*)pkt, KCOM_PKT_NET_SIZE);
+        printk(KERN_DEBUG"[PMS] pktdump RAW header dump -------------------------------------\n");
+
+}
+
+void pms_dump_packet_data(const struct kcom_pkt* const pkt)
+{
+        if (!pkt) {
+                PMSERR("packet is null, can't dump header\n");
+                return;
+        }
+
+        if (!pkt->data) {
+                PMSERR("packet data is NULL\n");
+                return;
+        }
+
+        printk(KERN_DEBUG"[PMS] pktdump data RAW dump ---------------------------------------\n");
+        hexdump(pkt->data, pkt->data_len);
+        printk(KERN_DEBUG"[PMS] pktdump data RAW dump ---------------------------------------\n");
+}
+
+/**
+ * pms_dump_packet
+ * Description:
+ *
+ * dump the packet content if the used pms_debug_do_switch is >= 4 dump data too
+ * @pkt: the packet to dump
+ */
+void pms_dump_packet(const struct kcom_pkt* const pkt)
+{
+
+        char buffer[64];
+        if (!pkt) {
+                PMSERR("packet is NULL ... can't dump it \n");
+                return;
+        }
+
+        pms_format_flags(pkt->flags, buffer);
+
+        printk(KERN_DEBUG"[PMS] ==========================pktdump header dump=============================\n");
+        printk(KERN_DEBUG"[PMS] pktdump type=%d: %s\n", pkt->type, __get_packet_name(pkt->type));
+        printk(KERN_DEBUG"[PMS] pktdump flgs=0x%x: %s\n", pkt->flags, buffer);
+        printk(KERN_DEBUG"[PMS] pktdump pid(%5d,%5d) msgid: %d len: %d addr: %p\n"
+                        , pkt->hpid, pkt->rpid, pkt->msgid, pkt->data_len, (void*)pkt->addr);
+
+
+
+        if (pms_debug_do_switch >= 4) {
+		printk(KERN_DEBUG"[PMS] pktdump magic:0x%x hdr_len:%d\n", pkt->magic, pkt->hdr_len);
+        }
+
+
+        printk(KERN_DEBUG"[PMS] ==========================pktdump header dump=============================\n");
+
+        if (pms_debug_do_switch >= 4) {
+                pms_dump_packet_hdr(pkt);
+                pms_dump_packet_data(pkt);
+        }
+
+}
+
+
+
+void debug_mlink(struct socket *sock)
+{
+	printk(KERN_DEBUG "mlink: socket @ = %p\n", sock);
+}
+
+
+void debug_page(unsigned long addr)
+{
+	unsigned long digest = 0;
+	char *ptr = (char *) addr;
+	int i;
+
+	for (i = 0; i < 4096; i++)
+		digest += ptr[i] * i;
+
+	printk(KERN_DEBUG "sum of 0x%p is %lu\n", (void *) addr, digest);
+}
+
+void debug_vmas(struct mm_struct *mm)
+{
+	struct vm_area_struct *vma;
+
+	if (!mm) {
+		PMSERR("debug_vma(): no mm !\n");
+		return;
+	}
+
+	printk(KERN_ERR "======== [LISTING VMA] ========\n");
+	for (vma = mm->mmap; vma; vma = vma->vm_next) {
+		printk(KERN_DEBUG "vma: [%.8lx:%.8lx]\n", vma->vm_start,
+							vma->vm_end);
+	}
+}
+
+void debug_signals(struct task_struct *p)
+{
+	struct signal_struct *signal;
+
+	signal = p->signal;
+
+	printk(KERN_DEBUG "=========== [DEBUG SIGNALS] ========\n");
+}
+
+#endif /* CONFIG_PMS_DEBUG */
diff --exclude=.git -Nru linux-2.6.28.7/hpc/debug-i386.c linux-2.6.28.7-pms/hpc/debug-i386.c
--- linux-2.6.28.7/hpc/debug-i386.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/debug-i386.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,115 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+
+#include <asm/uaccess.h>
+#include <asm/ptrace.h>
+#include <asm/desc.h>
+#include <asm/i387.h>
+#include <asm/uaccess.h>
+#include <asm/ptrace.h>
+#include <asm/pms.h>
+
+void pms_debug_regs(struct pt_regs *myreg)
+{
+	struct pt_regs *reg;
+
+	reg = (myreg) ? myreg : ARCH_TASK_GET_USER_REGS(current);
+
+	// KERN_DEBUG ?
+	printk(KERN_ERR "pt_regs:\n");
+	printk(KERN_ERR "bx: 0x%lx, cx: 0x%lx, dx: 0x%lx\n", reg->bx, reg->cx, reg->dx);
+	printk(KERN_ERR "si: 0x%lx, di: 0x%lx, bp: 0x%lx\n", reg->si, reg->di, reg->bp);
+	printk(KERN_ERR "ax: 0x%lx, xds: 0x%lx, xes: 0x%lx\n", reg->ax, reg->ds, reg->es);
+	printk(KERN_ERR "orig_ax: 0x%lx, ip: 0x%lx, cs: 0x%lx\n", reg->orig_ax, reg->ip, reg->cs);
+        printk(KERN_ERR "flags: 0x%lx, sp: 0x%lx, ss: 0x%lx\n", reg->flags, reg->sp, reg->ss);
+}
+
+
+void inline debug_thread(struct thread_struct *t)
+{
+	printk(KERN_ERR "thread_struct:\n");
+	printk(KERN_ERR "sp0: 0x%lx, sysenter_cs: 0x%lx\n",t->sp0, t->sysenter_cs);
+	printk(KERN_ERR "ip: 0x%lx, sp: 0x%lx", t->ip, t->sp);
+
+}
+
+/* shamelessly stolen, this is useful to debug a user space
+ * process when it dies on remote */
+void show_user_registers(struct task_struct *p)
+{
+	int i;
+	unsigned long sp;
+	unsigned short ss;
+	unsigned long prev_code;
+	struct pt_regs *regs;
+
+	if (!p->mm) {
+		printk(KERN_ERR "show_user_registers(): no mm !\n");
+		return;
+	}
+	/* regs = ((struct pt_regs *) (THREAD_SIZE + (unsigned long) p->thread_info)) - 1; */
+	regs = ARCH_TASK_GET_USER_REGS(p);
+
+	sp = regs->sp;
+	ss = regs->ss & 0xffff;
+
+	printk("CPU:    %d\nIP:    %04lx:[<%08lx>]    %s\nFLAGS: %08lx\n",
+		smp_processor_id(), 0xffff & regs->cs, regs->ip, print_tainted(), regs->flags);
+	print_symbol("IP is at %s\n", regs->ip);
+	printk("ax: %08lx   bx: %08lx   cx: %08lx   dx: %08lx\n",
+		regs->ax, regs->bx, regs->cx, regs->dx);
+	printk("si: %08lx   di: %08lx   bp: %08lx   sp: %08lx\n",
+		regs->si, regs->di, regs->bp, sp);
+	printk("ds: %04lx   es: %04lx   ss: %04x\n",
+		regs->ds & 0xffff, regs->es & 0xffff, ss);
+	printk("Process %s (pid: %d, BOGUSthreadinfo=%p task=%p)",
+		p->comm, p->pid, current_thread_info(), p);
+
+	printk("\nStack: ");
+	show_stack(NULL, (unsigned long*)sp);
+
+	prev_code = regs->ip - 20;
+
+	printk("code before eip: ");
+	for(i = 0; i < 20 ; i++)
+	{
+		unsigned char c;
+		if(__get_user(c, &((unsigned char*)prev_code)[i]))
+			break;
+		printk("%02x ", c);
+	}
+	printk("\n");
+
+
+	printk("Code: ");
+	for(i = 0; i < 20 ; i++)
+	{
+		unsigned char c;
+		if(__get_user(c, &((unsigned char*)regs->ip)[i])) {
+			printk(" Bad EIP value.");
+			break;
+		}
+		printk("%02x ", c);
+	}
+	printk("\n");
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/debug-ppc.c linux-2.6.28.7-pms/hpc/debug-ppc.c
--- linux-2.6.28.7/hpc/debug-ppc.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/debug-ppc.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,63 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <asm/uaccess.h>
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+#include <hpc/debug.h>
+#include <asm/ptrace.h>
+#include <asm/uaccess.h>
+#include <asm/ptrace.h>
+#include <asm/processor.h>
+#include <hpc/arch.h>
+
+void pms_debug_regs(struct pt_regs * myreg)
+{
+	struct pt_regs *regs;
+	int i;
+
+	regs = (myreg) ? myreg : ARCH_TASK_GET_USER_REGS(current);
+
+	printk("NIP: %08lX LR: %08lX SP: %08lX REGS: %p TRAP: %04lx\n",
+	       regs->nip, regs->link, regs->gpr[1], regs, regs->trap);
+	printk("MSR: %08lx EE: %01x PR: %01x FP: %01x ME: %01x IR/DR: %01x%01x\n",
+	       regs->msr, regs->msr&MSR_EE ? 1 : 0, regs->msr&MSR_PR ? 1 : 0,
+	       regs->msr & MSR_FP ? 1 : 0,regs->msr&MSR_ME ? 1 : 0,
+	       regs->msr & MSR_IR ? 1 : 0,
+	       regs->msr & MSR_DR ? 1 : 0);
+
+	for (i = 0; i < 32; i += 4) {
+		printk(KERN_ERR "GPR%02d: %08lx %08lx %08lx %08lx\n",
+					i, regs->gpr[i], regs->gpr[i + 1],
+					regs->gpr[i + 2], regs->gpr[i + 3]);
+	}
+
+}
+
+
+void inline debug_thread(struct thread_struct *t)
+{
+}
+
+
+/* shamelessly stolen, this is useful to debug a user space
+ * process when it dies on remote */
+void show_user_registers(struct task_struct *p)
+{
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/debug-x86_64.c linux-2.6.28.7-pms/hpc/debug-x86_64.c
--- linux-2.6.28.7/hpc/debug-x86_64.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/debug-x86_64.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,56 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <asm/uaccess.h>
+#include <linux/kallsyms.h>
+#include <linux/sched.h>
+#include <hpc/debug.h>
+#include <asm/ptrace.h>
+#include <asm/desc.h>
+#include <asm/i387.h>
+#include <asm/uaccess.h>
+#include <asm/ptrace.h>
+#include <hpc/arch.h>
+#include <hpc/task.h>
+
+void pms_debug_regs(struct pt_regs *myreg)
+{
+	struct pt_regs *reg;
+	reg = (myreg) ? myreg : ARCH_TASK_GET_USER_REGS(current);
+
+	printk("pt_regs:\n");
+	printk("r15: 0x%lx, r14: 0x%lx, r13: 0x%lx\n", reg->r15, reg->r14, reg->r13);
+	printk("r12: 0x%lx, rbp: 0x%lx, rbx: 0x%lx\n", reg->r12, reg->rbp, reg->rbx);
+	printk("r11: 0x%lx, r10: 0x%lx, r09: 0x%lx\n", reg->r11, reg->r10, reg->r9);
+	printk("r08: 0x%lx, rax: 0x%lx, rcx: 0x%lx\n", reg->r8, reg->rax, reg->rcx);
+	printk("rdx: 0x%lx, rsi: 0x%lx, rdi: 0x%lx\n", reg->rdx, reg->rsi, reg->rdi);
+	printk("orig_rax: 0x%lx, rip: 0x%lx,  cs: 0x%lx\n", reg->orig_rax, reg->rip, reg->cs);
+        printk("eflags: 0x%lx, rsp: 0x%lx,  ss: 0x%lx\n", reg->eflags, reg->rsp, reg->ss);
+}
+
+
+void inline debug_thread(struct thread_struct *t)
+{
+	printk("thread_struct:\n");
+}
+
+
+void show_user_registers(struct task_struct *p)
+{
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/deputy.c linux-2.6.28.7-pms/hpc/deputy.c
--- linux-2.6.28.7/hpc/deputy.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/deputy.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,507 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/signal.h>
+#include <linux/file.h>
+#include <linux/mount.h>
+#include <linux/acct.h>
+#include <linux/highmem.h>
+#include <asm/mmu_context.h>
+#include <asm/unistd.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/arch.h>
+
+
+/**
+ * deputy_undeputise - stop as deputy process, become normal local process
+ **/
+void deputy_undeputise(struct task_struct *p)
+{
+	PMSDEBUG_SYS(2, "[deputy]\n");
+
+	task_set_dflags(p, DINCOMING);	/* not strictly true, but we must lockout proc changes */
+	kcom_wait_sent(p->pid);
+	kcom_task_delete(p->pid);
+	task_heldfiles_clear(p);
+	/* do we, don't we, don't care if we do, DO CARE IF WE DON'T ! */
+	if(!task_test_dflags(p, DSPLIT))
+		memset(p->pms.whereto, 0, sizeof(struct sockaddr));
+        task_clear_dflags(p, DDEPUTY|DINCOMING);
+}
+
+/**
+ * deputy_do_syscall - process a syscall coming from remote
+ **/
+int deputy_do_syscall(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+        struct task_struct *p = tsk->task;
+	struct pmsp_syscall_req *s;
+	struct pmsp_syscall_ret r;
+
+	s = (struct pmsp_syscall_req*) pkt->data;
+	
+	PMSDEBUG_SYS(2, "[deputy] received request for syscall %d\n", s->n);
+
+        if (likely((s->n != __NR_exit) && (s->n != __NR_exit_group))) {
+		r.ret = arch_exec_syscall(s->n, (struct syscall_parameter *) &s->arg);
+		return kcom_send_resp(p, sizeof(struct pmsp_syscall_ret), (char*)&r, pkt);
+	}
+	else {
+		/* echo the exit value back to the remote, so it may terminate */
+		r.ret = (long)s->arg[0];
+		kcom_send_resp(p, sizeof(struct pmsp_syscall_ret), (char*)&r, pkt);
+		/* Mark that our (remote) partner task is dead */
+		task_set_dflags(p, DSPLIT);
+		deputy_undeputise(p);
+		p->exit_code = (int)s->arg[0];
+		return 0;
+	}
+}
+
+/**
+ * deputy_do_fork - process a fork coming from remote
+ **/
+
+int deputy_do_fork(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+        struct task_struct *p = tsk->task;
+	struct pmsp_fork_req *m;
+	struct pmsp_fork_ret r;
+	struct task_struct *child;
+
+        PMSDEBUG_SYS(2, "[deputy] remote fork\n");
+
+        m = (struct pmsp_fork_req*) pkt->data;
+
+	r.pid = do_fork(m->clone_flags, m->stack_start, &m->regs, m->stack_size,
+						0, 0);
+
+        read_lock(&tasklist_lock);
+	child = find_task_by_vpid(r.pid);
+        read_unlock(&tasklist_lock);
+
+	if (!child) {
+		printk(KERN_ERR "[PMS] error: child %d not found\n", r.pid);
+		kcom_send_nack(p, pkt);
+		return -ENODEV;
+	}
+	r.tgid = child->tgid;
+
+        return kcom_send_resp(p, sizeof(struct pmsp_fork_ret), (char*)&r, pkt);
+}
+
+/**
+ * deputy_do_readpage - process request a specific page
+ **/
+int deputy_do_readpage(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+        struct task_struct *p = tsk->task;
+	struct pmsp_page_req *m;
+	struct page *page = NULL;
+	struct vm_area_struct vma = { };
+	struct pms_held_file *heldfile;
+	void *kmpage;
+	struct vm_fault vmf;
+
+        PMSDEBUG_SYS(2, "[deputy] remote read page\n");
+
+        m = (struct pmsp_page_req *) pkt->data;
+
+	heldfile = task_heldfiles_find(p, m->file);
+	if (!heldfile)
+		goto out;
+		
+	memset(&vma, 0, sizeof(struct vm_area_struct));
+	vma.vm_end = m->offset + PAGE_SIZE;
+	vma.vm_file = (struct file *) m->file;
+
+	/* g_remlin: FIXME */
+	/*page = heldfile->nopage(&vma, m->offset, NULL);*/
+	if(heldfile->fault(&vma, &vmf)<0)
+		PMSERR("heldfile->fault(&vma, &vmf)\n");
+
+	kmpage = kmap((struct page *)&vmf.page);
+        return kcom_send_resp(p, PAGE_SIZE, (char*)kmpage, pkt);
+
+out:
+	PMSERR("file not found\n");
+	if (page) {
+		kunmap(page);
+		__free_page(page);
+	}
+        kcom_send_nack(p, pkt);
+	return -EBADF;
+}
+
+/**
+ * deputy_do_mmap_pgoff - really do a mmap on deputy
+ **/
+unsigned long deputy_do_mmap_pgoff(struct file * file, unsigned long addr,
+				unsigned long len, unsigned long prot,
+				unsigned long flags, unsigned long pgoff)
+{
+	int error;
+	struct vm_area_struct *vma;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+
+	if(file && ((!file->f_op) || (!file->f_op->mmap))) {
+		error = -ENODEV;
+		goto out;
+	}
+
+	vma = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
+	if (!vma) {
+		error = -ENOMEM;
+		goto out;
+	}
+	memset(vma, 0, sizeof(*vma));
+
+	vma->vm_mm = current->mm;
+	vma->vm_start = addr;
+	vma->vm_end = addr + len;
+	vma->vm_flags = flags;
+	vma->vm_page_prot = protection_map[flags & 0x0f];
+	vma->vm_pgoff = pgoff;
+	vma->vm_file = file;
+
+	if (file) {
+		error = file->f_op->mmap(file, vma);
+		if (error < 0)
+			goto out_freevma;
+	}
+
+	error = task_heldfiles_add(current, file, vma->vm_ops);
+
+	/* FIXME insert the vma ! */
+	return 0;
+out_freevma:
+	kmem_cache_free(vm_area_cachep, vma);
+out:
+	return error;
+}
+
+/**
+ * deputy_do_mmap - process request to mmap a file
+ **/
+int deputy_do_mmap(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+        struct task_struct *p = tsk->task;
+	struct pmsp_mmap_req *m;
+	struct pmsp_mmap_ret r;
+	struct file *file;
+	int err;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+
+	err = -EBADF;
+        m = (struct pmsp_mmap_req*) pkt->data;
+	file = fget(m->fd);
+	if (!file)
+		goto out;
+	
+	down_write(&p->mm->mmap_sem);
+	err = do_mmap_pgoff(file, m->addr, m->len, m->prot, m->flags, m->pgoff);
+	up_write(&p->mm->mmap_sem);
+	
+	r.file = file;
+	r.isize = file->f_path.dentry->d_inode->i_size;
+	fput(file);
+out:
+	r.ret = err;
+	return kcom_send_resp(p, sizeof(struct pmsp_mmap_ret), (char*)&r, pkt);
+
+}
+
+#if 0
+/* Not yet done, to be reviewed */
+
+static void bprm_drop(struct linux_binprm *bprm)
+{
+	int i;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+	if (!bprm)
+		return;
+	for (i = 0; i < MAX_ARG_PAGES; i++) {
+		struct page * page = bprm->page[i];
+		if (page)
+			__free_page(page);
+	}
+	if (bprm->security)
+		security_bprm_free(bprm);
+	if (bprm->mm)
+		mmdrop(bprm->mm);
+	if (bprm->file) {
+		allow_write_access(bprm->file);
+		fput(bprm->file);
+	}
+	kfree(bprm);
+}
+
+
+static int __deputy_do_execve(struct linux_binprm *bprm,
+                              struct pt_regs * regs)
+{
+	int retval;
+
+	retval = search_binary_handler(bprm,regs);
+	if (retval >= 0) {
+		// FIXME free_arg_pages(bprm);
+
+		/* execve success */
+		security_bprm_free(bprm);
+		acct_update_integrals(current);
+		kfree(bprm);
+		return retval;
+	}
+
+	bprm_drop(bprm);
+	return retval;
+}
+
+static struct linux_binprm *deputy_setup_bprm(char * filename,
+		                              int argc, char **argv,
+		                              int envc, char **envp)
+{
+	struct linux_binprm *bprm;
+	struct file *file;
+	int retval;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
+	if (!bprm)
+		return ERR_PTR(-ENOMEM);
+
+	file = open_exec(filename);
+	retval = PTR_ERR(file);
+	if (IS_ERR(file))
+		goto out;
+
+	bprm->p = PAGE_SIZE * MAX_ARG_PAGES - sizeof(void *);
+
+	bprm->file = file;
+	bprm->filename = filename;
+	bprm->interp = filename;
+	bprm->mm = mm_alloc();
+	retval = -ENOMEM;
+	if (!bprm->mm)
+		goto out;
+
+	retval = init_new_context(current, bprm->mm);
+	if (retval < 0)
+		goto out;
+
+	retval = bprm->argc = argc;
+	if (retval < 0)
+		goto out;
+
+	retval = bprm->envc = envc;
+	if (retval < 0)
+		goto out;
+
+	retval = security_bprm_alloc(bprm);
+	if (retval)
+		goto out;
+
+	retval = prepare_binprm(bprm);
+	if (retval < 0)
+		goto out;
+
+	retval = copy_strings_kernel(1, &bprm->filename, bprm);
+	if (retval < 0)
+		goto out;
+
+	bprm->exec = bprm->p;
+	retval = copy_strings_kernel(bprm->envc, envp, bprm);
+	if (retval < 0)
+		goto out;
+
+	retval = copy_strings_kernel(bprm->argc, argv, bprm);
+	if (retval < 0)
+		goto out;
+
+	return bprm;
+out:
+	bprm_drop(bprm);
+	return ERR_PTR(retval);
+}
+
+#endif
+/**
+ * deputy_do_execve - process request to execve a new executable
+ **/
+int deputy_do_execve(struct kcom_task* tsk, const struct kcom_pkt *const pkt)
+{
+
+	PMSERR("[deputy] received do_execve Not Implemented!\n");
+	return kcom_send_nack(tsk->task, pkt);
+#if 0
+        struct task_struct *p = tsk->task;
+	struct pmsp_execve_req *m;
+	struct pmsp_execve_ret r;
+	int error;
+	char **argv, **envp;
+	struct linux_binprm *bprm;
+	int sz;
+	char *data = NULL;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+        m = (struct pmsp_execve_req*)pkt->data;
+
+
+        /*FIXME the filename should be included in the packet */
+	sz = m->filelen + m->argvlen + m->envplen + 3;
+	data = kmalloc(sz, GFP_KERNEL);
+	if (!data)
+		goto error;
+
+        /* Should be receiving the filename */
+
+	argv = (char **) (data + m.filelen + 1);
+	envp = (char **) (data + m.filelen + m.argvlen + 2);
+
+	bprm = deputy_setup_bprm(filename, m.argc, argv,
+	                         m.envc, envp);
+	if (!bprm)
+		goto error;
+	
+	error = __deputy_do_execve(bprm, &m.regs);
+	if (error < 0)
+		goto error;
+
+        return kcom_send_resp(p, sizeof(struct pmsp_execve_ret), &r, pkt);
+
+error:
+        kcom_send_nack(p, pkt);
+	return error;
+#endif
+}
+
+/**
+ * deputy_do_sigpending - process signal pending
+ **/
+void deputy_do_sigpending(struct task_struct *p)
+{
+	siginfo_t info;
+	struct pmsp_signal s;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in*)p->pms.whereto;
+	int signr;
+        int err;
+	unsigned long flags;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+
+process_signal:
+
+	spin_lock_irqsave(&p->sighand->siglock, flags);
+	if (!signal_pending(p))
+		goto exit_unlock;
+
+	signr = dequeue_signal(p, &p->blocked, &info);
+	spin_unlock_irqrestore(&p->sighand->siglock, flags);
+
+	s.signr = signr;
+	memcpy(&s.siginfo, &info, sizeof(siginfo_t));
+
+	PMSDEBUG_SYS(3, "Signal %d to remote.\n", signr);
+
+	err = kcom_send_command(KCOM_L1_DEP_SIGNAL, sizeof(struct pmsp_signal)
+	     		       ,(char*)&s, 0, dest_ptr, NULL);
+
+	if (err < 0)
+		PMSERR("Sending signal %d\n", signr);
+
+	if (SIGKILL == signr) {
+		/* No need to send the rest */
+		while (signal_pending(p)) {
+		    dequeue_signal(p, &p->blocked, &info);
+		}
+		return;
+	}
+
+	goto process_signal;
+
+exit_unlock:
+	spin_unlock_irqrestore(&p->sighand->siglock, flags);
+
+}
+
+/**
+ * deputy_main_loop - process loop when process is deputy
+ **/
+int deputy_main_loop(void)
+{
+	struct task_struct *p=current;
+	struct kcom_task *mytsk;
+	int err=0;
+	struct kcom_pkt *pkt;
+
+        PMSDEBUG_SYS(2, "[deputy]\n");
+	mytsk=kcom_home_task_find(p->pid);
+	if (unlikely(!mytsk)) {
+		PMSERR("I am a taskless deputy O_o\n");
+		return(0);
+	}
+
+	PMS_VERBOSE_MIG("pid[%d] Deputy service routine started\n", p->pid);
+	do {
+		err = __kcom_wait_msg(mytsk, &pkt);
+		if(likely(err>=0)) {
+			err = kcomd_do_l2_state_machine(mytsk, pkt);
+			if(unlikely(task_test_dflags(p, DSPLIT))) {
+				break;
+			}
+			if (err < 0) {
+			    printk(KERN_ERR "[deputy][%d] error %d handling packet '%s'\n"
+				  ,p->pid, err, __get_packet_name(pkt->type));
+
+			}
+			kcom_pkt_delete(pkt);
+		}
+		else if (err == -EAGAIN) {
+			deputy_do_sigpending(p);
+		}
+		else {
+			printk(KERN_ERR "[deputy][%d] Got error %d while waiting for packet (ignoring)\n", p->pid, err);
+			schedule_timeout_interruptible(HZ);
+		}
+		if (task_dreqs_pending(p)) {
+			task_do_request();
+		}
+	}
+	while(likely(task_test_dflags(p, DDEPUTY)));
+	PMS_VERBOSE_MIG("pid[%d] Deputy service routine finished\n", p->pid);
+	return(0);
+}
+
+/* FIXME: not here */
+void exit_mm(struct task_struct *);
+
+/**
+ * deputy_startup - startup deputy process
+ **/
+void deputy_startup(struct task_struct *p)
+{
+	exit_mm(p);
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/files.c linux-2.6.28.7-pms/hpc/files.c
--- linux-2.6.28.7/hpc/files.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/files.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,292 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/fs.h>
+#include <linux/list.h>
+#include <linux/sched.h>
+#include <linux/file.h>
+#include <linux/mount.h>
+#include <linux/pagemap.h>
+#include <linux/mm.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/remote.h>
+
+struct address_space_operations remote_aops = { .readpage = remote_readpage, };
+struct file_operations remote_file_operations = { .mmap = remote_file_mmap, };
+
+int task_heldfiles_add(struct task_struct *p, struct file *file,
+				struct vm_operations_struct *vm_ops)
+{
+	struct pms_held_file *rfile;
+
+	rfile = kmalloc(sizeof(struct pms_held_file), GFP_KERNEL);
+	if (!rfile)
+		return -ENOMEM;
+
+	PMSDEBUG_RINO(2, "process [%d] adding file [0x%p], fault [0x%p]\n",
+			p->pid, file, (void *) vm_ops->fault);
+
+	get_file(file);
+	rfile->file = file;
+	rfile->nb = (unsigned long) file; /* FIXME */
+	rfile->fault = ( vm_ops ? vm_ops->fault : NULL);
+	list_add(&rfile->list, &p->pms.rfiles);
+	return 0;
+}
+
+void task_heldfiles_clear(struct task_struct *p)
+{
+	struct pms_held_file *rfile, *next;
+
+	PMSDEBUG_RINO(3, "process [%d] clearing list\n", p->pid);
+
+	list_for_each_entry_safe(rfile, next, &p->pms.rfiles, list) {
+		fput(rfile->file);
+		kfree(rfile);
+	}
+	INIT_LIST_HEAD(&p->pms.rfiles);
+}
+
+struct pms_held_file *task_heldfiles_find(struct task_struct *p, struct file *file)
+{
+	struct pms_held_file *heldfile;
+
+	PMSDEBUG_RINO(3, "process [%d]\n", p->pid);
+
+	list_for_each_entry(heldfile, &p->pms.rfiles, list) {
+		if (heldfile->file == file) {
+			PMSDEBUG_RINO(3, "process [%d] returning file [0x%p]\n", p->pid, file);
+			return heldfile;
+		}
+	}
+	PMSDEBUG_RINO(3, "process [%d] failed to find file [0x%p]\n", p->pid, file);
+	return NULL;
+}
+
+/*****************************************************************************/
+struct pms_remote_dentry
+{
+	struct list_head list;
+	struct dentry *dentry;
+};
+
+spinlock_t remote_dentries_lock = SPIN_LOCK_UNLOCKED;
+struct list_head remote_dentries = LIST_HEAD_INIT(remote_dentries);
+
+int rdentry_delete(struct dentry *dentry)
+{
+	struct list_head *ptr;
+	int ret = -ENOENT;
+
+	spin_lock(&remote_dentries_lock);
+	list_for_each(ptr, &remote_dentries) {
+		struct pms_remote_dentry *rd = list_entry(ptr, struct pms_remote_dentry, list);
+		if (rd->dentry == dentry) {
+			PMSDEBUG_RINO(3, "process [%d] deleting dentry [0x%p]\n", current->pid, dentry);
+			list_del(ptr);
+			kfree(rd);
+			ret = 0;
+		}
+	}
+	spin_unlock(&remote_dentries_lock);
+	if (ret)
+		PMSERR("not found\n");
+	return ret;
+}
+
+void rdentry_iput(struct dentry *dentry, struct inode *inode)
+{
+	PMSDEBUG_RINO(3, "process [%d]n", current->pid);
+	kfree(inode->i_private);
+	iput(inode);
+}
+
+struct dentry_operations remote_dentry_ops = {
+	.d_delete = rdentry_delete,
+	.d_iput = rdentry_iput,
+};
+
+struct super_operations rfile_dummy_block_ops = { };
+
+struct super_block rfiles_dummy_block =
+{
+	.s_op = &rfile_dummy_block_ops,
+	.s_inodes = LIST_HEAD_INIT(rfiles_dummy_block.s_inodes),
+};
+
+struct vfsmount remote_file_vfsmnt =
+{
+	.mnt_count = ATOMIC_INIT(1),
+	.mnt_hash = LIST_HEAD_INIT(remote_file_vfsmnt.mnt_hash),
+	.mnt_child = LIST_HEAD_INIT(remote_file_vfsmnt.mnt_child),
+	.mnt_mounts = LIST_HEAD_INIT(remote_file_vfsmnt.mnt_mounts),
+	.mnt_list = LIST_HEAD_INIT(remote_file_vfsmnt.mnt_list),
+	.mnt_expire = LIST_HEAD_INIT(remote_file_vfsmnt.mnt_expire),
+	.mnt_parent = &remote_file_vfsmnt,
+};
+
+static int rdentry_add_entry(struct dentry *dentry)
+{
+	struct pms_remote_dentry *rdentry;
+
+	rdentry = kmalloc(sizeof(struct pms_remote_dentry), GFP_KERNEL);
+	if (!rdentry)
+		return -ENOMEM;
+
+	PMSDEBUG_RINO(3, "process [%d] adding dentry [0x%p]\n", current->pid, dentry);
+	rdentry->dentry = dentry;
+	spin_lock(&remote_dentries_lock);
+	list_add(&rdentry->list, &remote_dentries);
+	spin_unlock(&remote_dentries_lock);
+	return 0;
+}
+
+static struct dentry * rdentry_create_dentry(struct rfile_inode_data *data)
+{
+	struct dentry *dentry;
+	struct inode *inode;
+	struct rfile_inode_data *tmp;
+
+	PMSDEBUG_RINO(3, "process [%d]\n",current->pid);
+	inode = new_inode(&rfiles_dummy_block);
+	if (!inode)
+		return NULL;
+
+	tmp = kmalloc(sizeof(struct rfile_inode_data), GFP_KERNEL);
+	if (!tmp)
+		goto error;
+
+	memcpy(tmp, data, sizeof(struct rfile_inode_data));
+
+	inode->i_private = tmp;
+
+	inode->i_mode = S_IFREG;
+	inode->i_size = data->isize;
+	inode->i_fop = &remote_file_operations;
+	inode->i_mapping->a_ops = &remote_aops;
+
+	dentry = d_alloc(NULL, &(const struct qstr){ .name = "/", .len = 1 });
+	if (!dentry)
+		goto error;
+
+	dentry->d_inode = inode;
+	dentry->d_parent = dentry;
+
+	rdentry_add_entry(dentry);
+
+	return dentry;
+error:
+	kfree(data);
+	iput(inode);
+	return NULL;
+}
+
+static inline struct rfile_inode_data * rfile_inode_get_data(struct inode *inode)
+{
+	return (struct rfile_inode_data *) inode->i_private;
+}
+
+struct file * rfiles_inode_get_file(struct inode *inode)
+{
+	return rfile_inode_get_data(inode)->file;
+}
+
+static inline int rfiles_inode_compare(struct inode *inode,
+					struct rfile_inode_data *data)
+{
+	return memcmp(inode->i_private, data, sizeof(struct rfile_inode_data)) == 0;
+}
+
+static struct dentry * rdentry_find(struct rfile_inode_data *data)
+{
+	struct pms_remote_dentry *ptr;
+	struct dentry *dentry = NULL;
+
+	spin_lock(&remote_dentries_lock);
+	list_for_each_entry(ptr, &remote_dentries, list) {
+		if (rfiles_inode_compare(ptr->dentry->d_inode, data)) {
+			dentry = ptr->dentry;
+			PMSDEBUG_RINO(3, "process [%d] found dentry [0x%p]\n", current->pid, dentry);
+			break;
+		}
+	}
+	spin_unlock(&remote_dentries_lock);
+	return dentry;
+}
+
+static struct file * rdentry_create_file(struct rfile_inode_data *data)
+{
+	struct file *file;
+	struct dentry *dentry;
+
+	PMSDEBUG_RINO(3, "process [%d]\n", current->pid);
+	file = get_empty_filp();
+	if (!file)
+		return NULL;
+
+	dentry = dget(rdentry_find(data));
+	if (!dentry) {
+		dentry = rdentry_create_dentry(data);
+		if (!dentry)
+			goto error;
+	}
+
+	file->f_mapping = dentry->d_inode->i_mapping;
+	file->f_dentry = dentry;
+	file->f_op = &remote_file_operations;
+	file->f_mode = FMODE_READ;
+	file->f_vfsmnt = &remote_file_vfsmnt;
+
+	return file;
+error:
+	PMSERR("failed\n");
+	put_filp(file);
+	return NULL;
+}
+
+struct file * task_rfiles_get(struct task_struct *p, struct file *origfile,
+				unsigned long node, loff_t isize)
+{
+	struct vm_area_struct *vma;
+	struct file *file;
+	struct rfile_inode_data rdata;
+
+	PMSDEBUG_RINO(3, "process [%d]\n", current->pid);
+
+	rdata.file = origfile;
+	rdata.node = node;
+	rdata.isize = isize;
+
+	for (vma = p->mm->mmap; vma; vma = vma->vm_next)
+	{
+		if (!vma->vm_file)
+			continue;
+		file = vma->vm_file;
+		if (rfiles_inode_compare(file->f_dentry->d_inode, &rdata)) {
+			PMSDEBUG_RINO(3, "process [%d] found file [0x%p]\n", p->pid, file);
+			get_file(file);
+			return file;
+		}
+	}
+
+	file = rdentry_create_file(&rdata);
+	return file;
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/FIXME linux-2.6.28.7-pms/hpc/FIXME
--- linux-2.6.28.7/hpc/FIXME	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/FIXME	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,12 @@
+
+The problem in a nutshell:
+
+remote sends "write" syscall using msgid=1
+deputy sends "copy_from_user" using msgid=2
+remote sends data reply to copy_from_user using msgid=2
+deputy sends "ok" reply to write syscall using msgid=1
+
+Check SMP Safety - Make SMP Safe
+
+Check PREEMPT Safety - Make PREEMPT Safe
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/kcom.c linux-2.6.28.7-pms/hpc/kcom.c
--- linux-2.6.28.7/hpc/kcom.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/kcom.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,1765 @@
+/*
+ *	Copyright (C) 2006 Matt Dew <matt@osource.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/socket.h>
+#include <linux/in.h>
+#include <linux/in6.h>
+#include <linux/net.h>
+#include <linux/syscalls.h>
+#include <linux/jiffies.h>
+#include <linux/ctype.h>
+#include <net/sock.h>
+#include <net/tcp.h>
+
+/* g_remlin: dodgy, must get this in first */
+#define _HPC_KCOMC_H 1
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/kcom.h>
+
+
+/**
+ * kcom_add_packet
+ *
+ * Description
+ * 	Add a packet to the list of packets to send and alert the kcomd daemon.
+ * @param tsk : the task sending the packet
+ * @param pkt : the packet to add
+ **/
+int kcom_add_packet(struct kcom_task *tsk, struct kcom_pkt *pkt)
+{
+	PMSDEBUG_KCOMD(2, "Adding packet\n");
+	PMSDEBUG_PROTOCOL_DO(5, pms_dump_packet(pkt));
+
+	if (unlikely(!kcomd_task)) {
+		PMSDEBUG_PROTOCOL(1,"Unable to signal kcomd\n");
+		return -ENODEV;
+	}
+
+	if (unlikely(!tsk)) {
+		PMSDEBUG_PROTOCOL(1,"Can't add packet to a NULL task\n");
+		return -ENODEV;
+	}
+
+	if (unlikely(!pkt)) {
+		PMSDEBUG_PROTOCOL(1,"Can't add a NULL packet\n");
+		return -ENODEV;
+	}
+
+	write_lock(&tsk->out_packs_lock);
+	list_add_tail(&pkt->list, &tsk->out_packs);
+	write_unlock(&tsk->out_packs_lock);
+
+	tsk->node->pkt_ready = 1;
+	send_sig(SIGHUP, kcomd_task, 0);
+
+	return 0;
+}
+
+/**
+ * pkt_data_read
+ *
+ * Description:
+ * 	read the data that was sent following the pkt header.
+ * 	wait until all data has been read.
+ * 	The ->len field = size of the data in bytes.
+ **/
+int pkt_data_read(const struct kcom_node* const node
+	         ,const struct kcom_pkt* const pkt
+	         ,int len, char *data)
+{
+	struct socket *sock=node->sock;
+	struct iovec iov;
+	struct msghdr msg = { NULL, 0, &iov, 1, NULL, 0, MSG_WAITALL | MSG_NOSIGNAL };
+	mm_segment_t oldfs;
+	int i;
+	unsigned long stop_jiffies;
+
+	PMSDEBUG_KCOMD(2, "KCOMD: reading data (%d B)... \n", len);
+
+	if (unlikely(!sock)) {
+		PMSDEBUG_PROTOCOL(1,"No socket!\n");
+		return -ENOENT;
+	}
+
+	iov.iov_base = data;
+	iov.iov_len = len;
+
+	oldfs = get_fs();
+	set_fs(KERNEL_DS);
+
+	stop_jiffies = jiffies + (HZ*60);
+	while (iov.iov_len > 0) {
+		PMSDEBUG_KCOMD(4, "KCOMD: (Re)Starting read loop\n");
+		i = sock_recvmsg(sock, &msg, iov.iov_len, msg.msg_flags);
+		if (i < 0) {
+			if ((i == -ENOSPC) || (i == -EAGAIN)) {
+				/* prevent infinite loop */
+				if (time_after(jiffies, stop_jiffies)) {
+					PMSERR( "read timeout");
+					len = -ETIMEDOUT;
+					break;
+				}
+				schedule_timeout(HZ/1000);
+				continue;
+			}
+			PMSERR( "error %d receiving data.\n", i);
+			len = i;
+			break;
+		}
+		iov.iov_base += i;
+ 	}
+	PMSDEBUG_KCOMD(4, "KCOMD: Exited read loop (len=%d)\n", len);
+	set_fs(oldfs);
+	if(unlikely(len<0))
+		PMSDEBUG_PROTOCOL(1, "len=%d\n", len);
+	return len;
+}
+EXPORT_SYMBOL_GPL(pkt_data_read);
+
+/**
+ * pkt_hdr_read
+ *
+ * Description:
+ * 	read the pkt header of the data transmission.
+ * 	The hdr indicates the type and size of the data.
+ * 	All packet headers are the same size.
+ * 	The packet is allocated; caller must free it
+ **/
+int pkt_hdr_read(const struct kcom_node* const node,
+		 struct kcom_pkt **recv_kcom_pkt)
+{
+	struct iovec iov;
+	struct msghdr msg = { NULL, 0, &iov, 1, NULL, 0, MSG_WAITALL | MSG_NOSIGNAL };
+	struct kcom_pkt *recv_pkt;
+	mm_segment_t oldfs;
+	struct socket *sock=node->sock;
+	int i;
+	int err = -1;
+ 	int first_loop = 1;
+ 	unsigned long stop_jiffies;
+
+ 	PMSDEBUG_KCOMD(2, "KCOMD: reading headers ... \n");
+
+	*recv_kcom_pkt = NULL;
+
+ 	if (unlikely(!sock)) {
+		PMSDEBUG_PROTOCOL(1, "KCOMD: No socket!\n");
+ 		return -ENODEV;
+	}
+
+ 	recv_pkt = kmem_cache_alloc(kcom_pkt_cachep, GFP_KERNEL);
+ 	if (unlikely(!recv_pkt)) {
+ 		PMSDEBUG_PROTOCOL(1, "Can't allocate receiving packet structure\n");
+ 		return -ENOMEM;
+ 	}
+
+ 	memset(recv_pkt, 0, sizeof(struct kcom_pkt));
+ 	INIT_LIST_HEAD(&recv_pkt->list);
+
+	iov.iov_base = recv_pkt;
+ 	iov.iov_len = KCOM_PKT_NET_SIZE;
+
+	oldfs = get_fs();
+	set_fs(KERNEL_DS);
+
+	stop_jiffies = jiffies + (HZ*60);
+ receive_fragment:
+
+ 	i = sock_recvmsg(sock, &msg, iov.iov_len, msg.msg_flags);
+ 	if (i < 0) {
+		if ((i == -ENOSPC) || (i == -EAGAIN)) {
+			if (first_loop && iov.iov_len == KCOM_PKT_NET_SIZE) {
+				err = i;
+				goto exit_error2;
+			}
+
+			if (time_after(jiffies, stop_jiffies))
+				goto receive_timeout;
+
+			first_loop = 0;
+			schedule_timeout(HZ/1000);
+			goto receive_fragment;
+		}
+		err = i;
+ 		goto exit_error;
+ 	}
+ 	iov.iov_base +=i;
+	first_loop = 0;
+
+ 	/* sock_revmsg update the iov struct, and len */
+ 	if (iov.iov_len > 0)
+ 		goto receive_fragment;
+
+	set_fs(oldfs);
+
+	/* Check for magic and header length */
+	if (PMS_PKT_MAGIC != recv_pkt->magic || KCOM_PKT_NET_SIZE != recv_pkt->hdr_len) {
+		err = -EINVAL;
+		goto exit_error;
+	}
+
+	*recv_kcom_pkt = recv_pkt;
+ 	return 0;
+
+receive_timeout:
+	PMSERR( "Can't receive header %d fragment, read timeout\n", i);
+	err = -ETIMEDOUT;
+exit_error:
+ 	kcom_pkt_delete(recv_pkt);
+exit_error2:
+ 	set_fs(oldfs);
+	PMSDEBUG_PROTOCOL(1, "KCOMD: err=%d\n", err);
+ 	return err;
+}
+EXPORT_SYMBOL_GPL(pkt_hdr_read);
+
+/**
+ *
+ * __pkt_read
+ *
+ * Description
+ *    Reads the packet header and, if exists, data,
+ *    Does the poorman job of receiving data itself,
+ *    if the node didn't hold a valid sock, __pkt_read
+ *    creates a new one
+ **/
+int __pkt_read(struct kcom_node *node, struct kcom_pkt **recv_kcom_pkt)
+{
+	int len;
+	int i;
+
+	PMSDEBUG_KCOMD(2, "KCOMD: Receiving packet \n");
+
+	/* In case of error, sockets may be deleted,
+	 * here we try to recover from this situation
+	 */
+	if (!node->sock) {
+		PMSDEBUG_KCOMD(2, "KCOMD: attempting reconnection\n");
+		__create_connection(&node->addr, node);
+		if (unlikely(!node->sock)) {
+			PMSDEBUG_PROTOCOL(1, "KCOMD: No socket!\n");
+			return -ENODEV;
+		}
+	}
+
+	/* read packet header first                   *
+	 * (pkt_hdr_read allocates the packet as well */
+	i = pkt_hdr_read(node, recv_kcom_pkt);
+	if (i<0)
+		return i;
+
+	if(unlikely(*recv_kcom_pkt == NULL)) {
+		PMSDEBUG_PROTOCOL(1, "KCOMD: No socket!\n");
+		return -ENOENT;
+	}
+
+        (*recv_kcom_pkt)->data = NULL;
+
+	/* read packet data if any */
+	len = (*recv_kcom_pkt)->data_len;
+	if (len > 0) {
+		(*recv_kcom_pkt)->data = kzalloc(len, GFP_KERNEL);
+		i = pkt_data_read(node, *recv_kcom_pkt, len, (*recv_kcom_pkt)->data);
+		if (unlikely(i < len)) {
+			PMSDEBUG_PROTOCOL(1, "KCOMD: incomplete data pkt!\n");
+			goto error_delete_packet;
+		}
+	}
+	INIT_LIST_HEAD(&((*recv_kcom_pkt)->list));
+	return 0;
+
+error_delete_packet:
+	/* Since the list may contain junk, we must init it */
+	INIT_LIST_HEAD(&((*recv_kcom_pkt)->list));
+	kcom_pkt_delete(*recv_kcom_pkt);
+	*recv_kcom_pkt = NULL;
+
+	PMSDEBUG_PROTOCOL(1, "KCOMD:\n");
+	return -ENOENT;
+}
+
+/**
+ * kcom_pkt_delete
+ *
+ * Description:
+ * destroy the packet and remove it from the list, this function does not
+ * lock any lock, so be sure to lock any needed lock before calling
+ *
+ * @pkt : the packet to delete
+ **/
+
+void kcom_pkt_delete(struct kcom_pkt *pkt)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	if (!pkt) {
+		PMSERR("Can not delete Null packet\n");
+		return;
+	}
+
+	if (!list_empty(&pkt->list)) {
+		list_del(&pkt->list);
+	}
+
+	if (pkt->data_len && pkt->data)
+		kfree(pkt->data);
+
+	kmem_cache_free(kcom_pkt_cachep, pkt);
+}
+EXPORT_SYMBOL_GPL(kcom_pkt_delete);
+
+/**
+ * alloc_fd_bitmap
+ *
+ * Description:
+ * 	Allocate a large enough file descriptor bitmap
+ * 	for the do_select function to operate correctly
+ * 	on all open sockets.
+ *    If more space needs to be allocated, it will be.
+ **/
+int alloc_fd_bitmap(int fd)
+{
+	struct kcom_node *node;
+	int size;
+	int n=fd;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	if (fd <= maxfds) {
+		PMSDEBUG_KCOMD( 4, "not allocating, returning\n");
+		return 0;
+	}
+
+	n = max(fd,max(fd4, fd6));
+	/* n = 0 is a valid possibility (qemu) */
+
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(node, &kcom_nodes, list)
+		n = max(node->fd, n);
+	read_unlock(&kcom_nodes_lock);
+
+	maxfds = n;
+
+	kfree(sockets_fds_bitmap);
+
+	size = FDS_BYTES(n+1);
+	sockets_fds_bitmap = kmalloc(6 * size, GFP_KERNEL);
+	if (unlikely(!sockets_fds_bitmap)) {
+		PMSDEBUG_PROTOCOL(1, "KCOMD:\n");
+		return -ENOMEM;
+	}
+
+	sockets_fds.in      = (unsigned long *)  sockets_fds_bitmap;
+	sockets_fds.out     = (unsigned long *) (sockets_fds_bitmap +   size);
+	sockets_fds.ex      = (unsigned long *) (sockets_fds_bitmap + 2*size);
+	sockets_fds.res_in  = (unsigned long *) (sockets_fds_bitmap + 3*size);
+	sockets_fds.res_out = (unsigned long *) (sockets_fds_bitmap + 4*size);
+	sockets_fds.res_ex  = (unsigned long *) (sockets_fds_bitmap + 5*size);
+
+	PMSDEBUG_KCOMD( 4, "allocated %dB for each fds set\n",size);
+	return 0;
+
+}
+EXPORT_SYMBOL_GPL(alloc_fd_bitmap);
+
+#ifdef CONFIG_PMS_DEBUG
+
+/**
+ * __kcom_pkt_check_flags - check that flags are appripriate, return 0 if ok
+ **/
+
+static int __kcom_pkt_check_flags(int type, int flags)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	if (__kcom_cmd_flags(flags)&KCOM_PKT_CPLX
+	   && !(__kcom_cmd_flags(flags)&KCOM_PKT_SYNC)) {
+	   	PMSDEBUG_PROTOCOL(1, "Complex commands can not be asynchronous!\n");
+	   	return -EFAULT;
+	}
+
+	if (!__kcom_node_flags(flags)) {
+		PMSDEBUG_PROTOCOL(1, "Creating packet without dest flags\n");
+		return -EFAULT;
+	}
+
+	return 0;
+}
+
+#endif /*CONFIG_PMS_DEBUG*/
+
+/**
+ * kcom_pkt_create - create a packet ready to be sent
+ **/
+int kcom_pkt_create(struct kcom_pkt** destpkt, int len, int type, int flags
+		   ,const char* const data, struct kcom_task *task)
+{
+	struct kcom_pkt *pkt;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	#ifdef CONFIG_PMS_DEBUG
+	{
+		int err;
+
+		/* flag sanity check is only useful for debug */
+		err = __kcom_pkt_check_flags(type, flags);
+		if (unlikely(err < 0)) {
+			PMSDEBUG_PROTOCOL(1, "KCOMD:\n");
+			return err;
+		}
+	}
+	#endif
+
+	PMSDEBUG_PROTOCOL(4, "creating packet (len %d type 0x%x flags %d)... \n"
+			, len, (unsigned)type, flags);
+
+	*destpkt = NULL;
+	pkt=(struct kcom_pkt*) kmem_cache_alloc(kcom_pkt_cachep, GFP_KERNEL);
+	if (!pkt) {
+		PMSDEBUG_PROTOCOL(1, "Can't allocate temp space for pkt header\n");
+		return -ENOMEM;
+	}
+
+	/* sanity fields */
+
+	memset(pkt, 0, sizeof(struct kcom_pkt));
+	INIT_LIST_HEAD(&pkt->list);
+
+	pkt->magic = PMS_PKT_MAGIC;
+	pkt->hdr_len = KCOM_PKT_NET_SIZE;
+
+	/* Types and stuffs */
+	pkt->type = type;
+	pkt->flags = flags;
+/*
+	pkt->rpid = rpid;
+	pkt->hpid = hpid;
+*/
+	/* packet data */
+	if (!len)
+		goto pkt_finished;
+
+	if (!data) {
+		PMSDEBUG_PROTOCOL(1, "Creating packet with NULL data, but len != 0\n");
+		kcom_pkt_delete(pkt);
+		return -EFAULT;
+	}
+
+	pkt->data = kmalloc(len, GFP_KERNEL);
+	if (!pkt->data) {
+		PMSDEBUG_PROTOCOL(1, "Can't allocate temp space for storing packet data!!\n");
+		kcom_pkt_delete(pkt);
+		return -ENOMEM;
+	}
+	pkt->data_len = len;
+	memcpy(pkt->data, data, len);
+
+pkt_finished:
+	/* Fill the result */
+
+	*destpkt = pkt;
+	return 0;
+}
+
+EXPORT_SYMBOL_GPL(kcom_pkt_create);
+
+/**
+ * __kcom_node_find
+ *
+ * Description:
+ * 	Does the actual work of finding, if it exists,
+ * 	an existing node connection.
+ *    The IP address is the determiner.
+ **/
+struct kcom_node *__kcom_node_find(const struct sockaddr* const saddr)
+{
+	struct kcom_node *tmp;
+	struct sockaddr_in *saddr_tmp;
+	struct sockaddr_in *saddr_in=(struct sockaddr_in *)saddr;
+	__be32 find_addr;
+	sa_family_t find_family;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	find_addr=saddr_in->sin_addr.s_addr;
+	find_family=saddr_in->sin_family;
+
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(tmp, &kcom_nodes, list) {
+		saddr_tmp=(struct sockaddr_in *)&tmp->addr;
+
+		if ((find_family == saddr_tmp->sin_family)
+		   && (find_addr == saddr_tmp->sin_addr.s_addr))
+			goto return_unlock;
+	}
+	tmp = NULL;
+
+return_unlock:
+	read_unlock(&kcom_nodes_lock);
+	return tmp;
+}
+
+
+/**
+ * kcom_node_find
+ *
+ * Description:
+ * 	calls __kcom_node_find
+ *    ,  which searches for a node
+ **/
+struct kcom_node *kcom_node_find(const struct sockaddr* const saddr)
+{
+	return __kcom_node_find(saddr);
+}
+EXPORT_SYMBOL_GPL(kcom_node_find);
+
+/**
+ * kcom_node_add
+ *
+ * Description:
+ * 	adds a new node connection.
+ *    signals kcomd that it needs to watch this node's socket.
+ *    the file descriptor belonging to this socket is mapped in
+ *    kcomd, but the function sock_map_fd. Due to a kernel security
+ *    check file descriptors are not shared between kernel threads.
+ **/
+struct kcom_node *kcom_node_add(struct socket *sock)
+{
+	struct kcom_node *node;
+
+	PMSDEBUG_KCOMD(2, "Adding new socket node\n");
+
+	node=kmem_cache_alloc(kcom_node_cachep, GFP_KERNEL);
+	if (!node) {
+		PMSDEBUG_PROTOCOL(1, "KCOMD: Unable to allocate node space.\n");
+		return NULL; //-ENOMEM;
+	}
+	INIT_LIST_HEAD(&node->list);
+	INIT_LIST_HEAD(&node->tasks);
+	INIT_LIST_HEAD(&node->process_list);
+
+	node->pkt_ready = 0;
+
+	rwlock_init(&node->tasks_lock);
+
+	node->sock=sock;
+	node->fd = 0; // kcomd will see this and assign a fd properly.
+
+	write_lock(&kcom_nodes_lock);
+	list_add_tail(&node->list, &kcom_nodes);
+	write_unlock(&kcom_nodes_lock);
+
+	if (kcomd_task)
+		send_sig(SIGHUP,kcomd_task,0);
+	else {
+		PMSDEBUG_PROTOCOL(1, "KCOMD: Unable to locate kcomd daemon.\n");
+		return NULL;
+	}
+	return node;
+
+}
+EXPORT_SYMBOL_GPL(kcom_node_add);
+
+/**
+ * __kcom_node_del
+ *
+ * Description:
+ * Delete a node and close its socket
+ **/
+
+void __kcom_node_del(struct kcom_node *node)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	write_lock(&kcom_nodes_lock);
+	list_del(&node->list);
+	write_unlock(&kcom_nodes_lock);
+
+	/* release and free structure */
+	sys_close(node->fd);
+	sock_release(node->sock);
+	kfree(node);
+}
+
+/**
+ * kcom_node_del
+ *
+ * Description:
+ * 	removes this node from the list of connected nodes.
+ *    releases the corresponding socket and file descriptor.
+ **/
+int kcom_node_del(struct sockaddr *addr)
+{
+	struct kcom_node *node;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	/* remove the node from the list */
+	node = __kcom_node_find(addr);
+	if (!node)
+		return -ENOENT;
+
+	__kcom_node_del(node);
+
+	return 0;
+}
+
+/**
+ * kcom_node_sock_release
+ *
+ * Description:
+ *    Remove the node (using kcom_node_del) if the task list
+ *    is empty, just reset the connection if the tasklist is
+ *    not empty... This function hold lock, so don't call it
+ *    with kcom_nodes_lock down
+ **/
+
+void kcom_node_sock_release(struct kcom_node *node)
+{
+	PMSDEBUG_KCOMD( 2, "KCOMD:\n");
+
+	if (!list_empty(&node->tasks)) {
+		PMSERR( "Resetting connection\n");
+		write_lock( &kcom_nodes_lock);
+		sock_release(node->sock);
+		node->sock = NULL;
+		node->fd = 0;
+		write_unlock(&kcom_nodes_lock);
+	} else {
+		PMSERR( "Killing connection\n");
+		__kcom_node_del(node);
+	}
+}
+
+/**
+ * set_sockopts
+ *
+ * Description:
+ * 	sets the socket options.  TCP_NODELAY (send tcp packet immediately),
+ *    keepalive intervals, retries, etc.
+ **/
+int set_sockopts(struct socket *sock)
+{
+	int val;
+	int ret = 0;
+	char __user *pval;
+	mm_segment_t oldfs;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	oldfs = get_fs();
+	set_fs(KERNEL_DS);
+
+	pval = (char __user *) &val;
+
+	val = 1;
+	ret = sock_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
+		pval, sizeof(val));
+	if (ret) {
+		PMSERR("unable to setsock SO_KEEPALIVE ERROR %d\n", ret);
+		goto exit;
+	}
+
+	/* FIXME: check on these, old COMM_MIGD */
+	val = PMS_CONNECTION_KEEPALIVE_INTERVAL;
+	ret = sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL,
+		pval, sizeof(val));
+	if (ret) {
+		PMSERR("Unable to setsock TCP_KEEPINTVL ERROR %d\n", ret);
+		goto exit;
+	}
+
+	val = PMS_CONNECTION_KEEPALIVE_MAXTRIES;
+	ret = sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT,
+		pval, sizeof(val));
+	if (ret) {
+		PMSERR("unable to setsock TCP_KEEPCNT ERROR %d\n", ret);
+		goto exit;
+	}
+
+	val = PMS_CONNECTION_KEEPALIVE_TOTAL;
+	ret = sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE,
+		pval, sizeof(val));
+	if (ret) {
+		PMSERR("unable to setsock TCP_KEEPIDLE ERROR %d\n", ret);
+		goto exit;
+	}
+
+	val=1;
+	ret = sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, pval, sizeof(val));
+	if (ret < 0) {
+		PMSERR("Unable to setsockopt ERROR: %d\n", ret);
+		goto exit;
+	}
+exit:
+	set_fs(oldfs);
+
+	/* Set timeout for send/recv */
+	sock->sk->sk_rcvtimeo = 60*HZ;
+	sock->sk->sk_sndtimeo = 60*HZ;
+
+	return ret;
+
+}
+
+/**
+ * __create_connection
+ *
+ * Description
+ *   This function creates the connection and stores it
+ *   in the node node. If the node is NULL, the node is
+ *   allocated This function may schedule and may hold
+ *   the kcom_nodes_lock
+ **/
+
+struct kcom_node *__create_connection(struct sockaddr *saddr
+				     ,struct kcom_node *node)
+{
+	struct socket *sock;
+	int ret;
+	int error;
+	DECLARE_WAITQUEUE(wait, current);
+	unsigned long timo=MAX_SCHEDULE_TIMEOUT;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	ret = sock_create(saddr->sa_family, SOCK_STREAM, IPPROTO_TCP, &sock);
+	if (ret < 0) {
+		PMSDEBUG_PROTOCOL(1, "Unable to sock_create.  error %d\n", ret);
+		return NULL;
+	}
+
+	error = sock->ops->connect(sock, saddr, sizeof(struct sockaddr_in), O_NONBLOCK);
+	add_wait_queue(sock->sk->sk_sleep, &wait);
+	while (sock->state != SS_CONNECTED) {
+		set_current_state(TASK_INTERRUPTIBLE);
+		error = sock->ops->connect(sock, saddr, sizeof(struct sockaddr_in), O_NONBLOCK);
+		if (error != -EALREADY || (error = sock_error(sock->sk)))
+			break;
+		timo = schedule_timeout(timo);
+		if (timo <= 0) {
+			error = -EAGAIN;
+			break;
+		}
+	}
+	remove_wait_queue(sock->sk->sk_sleep, &wait);
+	set_current_state(TASK_RUNNING);
+
+	if (error < 0) {
+		PMSDEBUG_PROTOCOL(1, "Unable to connect.  error %d\n", error);
+		return NULL;
+	}
+
+	if (!node) {
+		node = kcom_node_add(sock);
+		if (!node) {
+			PMSDEBUG_PROTOCOL(1, "Unable to add node\n");
+			return NULL;
+		}
+		memcpy(&node->addr, saddr, sizeof(*saddr));
+		ret=set_sockopts(node->sock);
+		if (ret) {
+			PMSDEBUG_PROTOCOL(1, "Unable to set socket options.\n");
+			return NULL;
+		}
+	} else {
+		PMSDEBUG_PROTOCOL(1, "Connection already exists. (resetting)\n");
+		node->sock = sock;
+	}
+
+	return node;
+}
+
+/**
+ * create_connection
+ *
+ * Description:
+ * 	First tries to find an existing connection, (the socket must
+ * 	be valid). If no connection is found, (or if the sock is NULL)
+ * 	a new connection is then created. (there should be only one
+ * 	connection per saddr) This function may schedule and may hold
+ * 	the kcom_nodes_lock
+ **/
+struct kcom_node *create_connection(struct sockaddr *saddr)
+{
+
+	struct kcom_node *node;
+
+	node = kcom_node_find(saddr);
+	if (node && node->sock) return node;
+
+	return __create_connection(saddr, node);
+
+}
+EXPORT_SYMBOL_GPL(create_connection);
+
+/**
+ * kcom_task_create
+ *
+ * Description:
+ * 	creates the kcom task related to this process.
+ *    initializes the linked lists for incoming and outgoing
+ *    pkts.  Also links this task to the corresponding node
+ *    since only migrated(ing) processes need kcom tasks.
+ **/
+struct kcom_task *kcom_task_create(struct kcom_node *node, int pid)
+{
+	struct kcom_task *kctask;
+	struct task_struct *p = NULL;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	kctask=kmem_cache_alloc(kcom_task_cachep, GFP_KERNEL);
+	if (kctask) {
+		read_lock(&tasklist_lock);
+		p = find_task_by_vpid(pid);
+		read_unlock(&tasklist_lock);
+
+		if (p) {
+			if (task_test_dflags(p, DREMOTE)) {
+				kctask->rpid = pid;
+				kctask->hpid = 0;
+			} else {
+				kctask->hpid = pid;
+				kctask->rpid = 0;
+			}
+		} else {
+			PMSERR("ERROR creating kcom task.\n");
+			return NULL;
+		}
+
+		INIT_LIST_HEAD(&kctask->list);
+		INIT_LIST_HEAD(&kctask->out_packs);
+		INIT_LIST_HEAD(&kctask->in_packs);
+		INIT_LIST_HEAD(&kctask->process_list);
+		INIT_LIST_HEAD(&kctask->egress_list);
+
+		rwlock_init(&kctask->in_packs_lock);
+		rwlock_init(&kctask->out_packs_lock);
+
+		spin_lock_init(&kctask->msgid_lock);
+
+		kctask->task = p;
+		kctask->node = node;
+		kctask->msgid = 0;
+
+		write_lock(&node->tasks_lock);
+		list_add_tail(&kctask->list, &node->tasks);
+		write_unlock(&node->tasks_lock);
+
+	} else
+		return NULL;
+	return kctask;
+}
+EXPORT_SYMBOL_GPL(kcom_task_create);
+
+/**
+ * kcom_wait_sent
+ *
+ * Description:
+ * Waits until all out packets have been queued for sending
+ **/
+int kcom_wait_sent(pid_t pid)
+{
+	struct kcom_task *tsk;
+
+	tsk=kcom_task_find(pid);
+	if (!tsk) {
+	    PMSERR("NULL task ! for pid %d\n", pid);
+	    return -ENODEV;
+	}
+
+	while (!list_empty(&tsk->out_packs))
+		schedule_timeout_interruptible(HZ/10);
+	return 0;
+}
+
+/**
+ * kcom_task_delete
+ *
+ * Description:
+ * 	deletes the kcom task and frees the memory.
+ *    Lookins that dflags to see if this is a process is a
+ *    remote process corresponding to a migrated process or
+ *    if its a 'home' process.
+ *    This is needed since both process ID's are kept in the
+ *    kcom task.
+ **/
+int kcom_task_delete(pid_t pid)
+{
+	struct kcom_node *tmp;
+	struct kcom_task *tmp2;
+	int offset;
+
+	if (task_test_dflags(current, DREMOTE))
+		offset = (int) &(((struct kcom_task*) 0)->rpid);
+	else
+		offset = (int) &(((struct kcom_task*) 0)->hpid);
+
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(tmp, &kcom_nodes, list) {
+
+		write_lock(&tmp->tasks_lock);
+		list_for_each_entry(tmp2, &tmp->tasks, list) {
+
+			if (pid != *((pid_t*)(((char*)tmp2)+offset)))
+				continue;
+			list_del(&tmp2->list);
+			kfree(tmp2);
+			tmp2 = NULL;
+			break;
+		}
+		write_unlock(&tmp->tasks_lock) ;
+	}
+	read_unlock(&kcom_nodes_lock);
+	return 0;
+}
+
+/**
+ * __kcom_task_find
+ *
+ * Description:
+ * 	Searches all nodes for a specific task, by pid.
+ *    Lookins that dflags to see if this is a process is a
+ *    remote process corresponding to a migrated process or
+ *    if its a 'home' process.
+ *    This is needed since both process ID's are kept in the
+ *    kcom task.
+ **/
+struct kcom_task *__kcom_task_find(pid_t pid, int where)
+{
+	struct kcom_node *tmp;
+	struct kcom_task *tmp2;
+	struct kcom_task *tsk_ret = NULL;
+	int pidoff = 0;
+	int look_for_remote = where - 1;
+
+	if (0 == pid) {
+	    PMSERR("No task can be pid 0!\n");
+	    return NULL;
+	}
+
+	/* Check if we are looking for a deputy or a remote ? */
+	if (0 == where) {
+
+		struct task_struct *p;
+
+		look_for_remote = 0;
+
+		read_lock(&tasklist_lock);
+		p = find_task_by_vpid(pid);
+		read_unlock(&tasklist_lock);
+
+		if (!p) {
+		    PMSERR("Unable to find pid %u\n", pid);
+		    return NULL;
+		}
+
+		if (task_test_dflags(p, DREMOTE))
+		    look_for_remote = 1;
+	}
+
+	/* Get the address of the field we are looking for */
+
+	if (look_for_remote) {
+		pidoff = (int) &(((struct kcom_task*) 0)->rpid);
+	} else {
+		pidoff = (int) &(((struct kcom_task*) 0)->hpid);
+	}
+
+	/* Parse all the list! */
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(tmp, &kcom_nodes, list) {
+		read_lock(&tmp->tasks_lock);
+		list_for_each_entry(tmp2, &tmp->tasks, list) {
+			if (likely(pid != *((pid_t*)(((char*)tmp2)+pidoff))))
+				continue;
+			read_unlock(&tmp->tasks_lock);
+			read_unlock(&kcom_nodes_lock);
+			return tmp2;
+		}
+		read_unlock(&tmp->tasks_lock);
+	}
+	read_unlock(&kcom_nodes_lock);
+	return tsk_ret;
+}
+
+/**
+ * kcom_task_find
+ *
+ * Description:
+ * 	calls __kcom_task_find, specifically looking
+ *    for a home pid.
+ **/
+struct kcom_task *kcom_home_task_find(pid_t pid)
+{
+	struct kcom_task *tmp;
+
+	tmp = __kcom_task_find(pid, 1);
+	return tmp;
+
+}
+EXPORT_SYMBOL_GPL(kcom_home_task_find);
+
+/**
+ * kcom_remote_task_find
+ *
+ * Description:
+ * 	calls __kcom_task_find, specifically looking
+ *    for a remote pid.
+ **/
+struct kcom_task *kcom_remote_task_find(pid_t pid)
+{
+	struct kcom_task *tmp;
+
+	tmp = __kcom_task_find(pid, 2);
+	return tmp;
+
+}
+EXPORT_SYMBOL_GPL(kcom_remote_task_find);
+
+
+/**
+ * kcom_task_find
+ *
+ * Description:
+ * 	calls __kcom_task_find,  which looks
+ *    at dflags to determine for itself if this is
+ *    a home or remote pid.
+ **/
+struct kcom_task *kcom_task_find(pid_t pid)
+{
+	struct kcom_task *tmp;
+
+	tmp = __kcom_task_find(pid, 0);
+	return tmp;
+}
+EXPORT_SYMBOL_GPL(kcom_task_find);
+
+
+unsigned int __get_dest_flags(struct kcom_task *tsk)
+{
+	if (task_test_dflags(tsk->task, DDEPUTY))
+		return KCOM_PKT_DEP_FLG;
+
+	if (task_test_dflags(tsk->task, DREMOTE))
+		return KCOM_PKT_REM_FLG;
+
+	/* task is probably migrating, but just to be sure : */
+
+	if (!tsk->rpid)
+		return KCOM_PKT_MIG_FLG;
+
+	if (tsk->rpid == tsk->task->pid)
+		return KCOM_PKT_REM_FLG;
+
+	if (tsk->hpid == tsk->task->pid)
+		return KCOM_PKT_DEP_FLG;
+
+	return 0;
+}
+
+/**
+ * kcom_task_send
+ *
+ * Description:
+ * 	Creates a packet to send and adds it to the task's outbound list.
+ **/
+int kcom_task_send(struct kcom_task *tsk, int type, int datasize, const char* const data
+		  ,unsigned long addr)
+{
+	struct kcom_pkt *pkt;
+	int ret;
+	unsigned int flags;
+
+	if (!tsk)
+		return -ENODEV;
+
+	PMSDEBUG_PROTOCOL(2, "sending task packet (type='%s', datasize=%d)\n"
+			,__get_packet_name(type), datasize);
+
+	flags = CASE_PKT_NEW_MSG | __get_default_flags(type) | __get_dest_flags(tsk);
+
+	/* put pkt in kcom_task */
+	ret = kcom_pkt_create(&pkt, datasize, type, flags, data, tsk);
+	if (ret<0) {
+		PMSERR("Can't create packet\n");
+		return ret;
+	}
+
+	/* Message ID depend on flags ... */
+	/* if (CASE_PKT_NEW_MSG==__kcom_msg_flags(flags)) { g_remlin: but it is broken... */
+		spin_lock(&tsk->msgid_lock);
+		++tsk->msgid;
+		pkt->msgid = tsk->msgid;
+		spin_unlock(&tsk->msgid_lock);
+	/* } */
+
+	pkt->hpid = tsk->hpid;
+	pkt->rpid = tsk->rpid;
+
+	pkt->addr = addr; // used by vma_pages
+
+	ret=kcom_add_packet(tsk,pkt);
+	if (ret < 0) {
+		kcom_pkt_delete(pkt);
+		return ret;
+	}
+
+	return pkt->msgid;
+}
+
+/**
+ * __kcom_find_or_create_task
+ *
+ * Description:
+ *   Attempts to find the task for the corresponding address and pid
+ *   if not found, it creates it or return -ENODEV or -ENOMEM in case of problem
+ *
+ *   The task pointer is filled in *tsk
+ **/
+
+int __kcom_find_or_create_task(const struct sockaddr_in *const saddr
+			      ,struct kcom_task **tsk, pid_t pid)
+{
+	struct kcom_node *node;
+
+	*tsk=kcom_task_find(pid);
+	if ((*tsk) && (*tsk)->node) {
+		if(((struct sockaddr_in *)&(*tsk)->node->addr)->sin_addr.s_addr == saddr->sin_addr.s_addr)
+                        return 0;
+                /* already connected to a different, not the requested, node */
+                PMSERR("ERROR: This task is already bound to a different node!\n");
+                return -EINVAL;
+	}
+
+	node=kcom_node_find((struct sockaddr *)saddr);
+	if (!node) {
+		node=create_connection((struct sockaddr *)saddr);
+		if (!node) {
+			PMSERR("ERROR: Unable to create new connection.\n");
+			return -ENODEV;
+		}
+	}
+
+	if (!*tsk) {
+		*tsk=kcom_task_create(node, pid);
+		if (!*tsk) {
+			PMSERR("ERROR: Unable to create task.\n");
+			return -ENOMEM;
+		}
+	}
+
+	return 0;
+}
+
+/**
+ * __kcom_send_answer
+ *
+ * Description
+ *    Send an answer corresponding to the packet and adding the flag
+ *
+ *    @flags_type: must be PKT_ACK or PKT_NACK
+ **/
+
+int __kcom_send_answer(struct task_struct *p, const struct kcom_pkt *const recv_pkt
+		      ,unsigned int flags, int len, char *buf) {
+
+	struct kcom_pkt *send_pkt;
+	struct kcom_task *send_tsk;
+	int err;
+
+	PMSDEBUG_KCOMD(2, "KCOMD: send answering packet (len=%d)\n", len);
+
+	if(!p) {
+	    	PMSERR("Null task!\n");
+	    	return -ENODEV;
+	}
+
+	send_tsk=kcom_task_find(p->pid);
+	if (!send_tsk) {
+		PMSERR("Can't locate task for %d\n", p->pid);
+		return -ENODEV;
+	}
+
+	flags |= __get_dest_flags(send_tsk);
+	err=kcom_pkt_create(&send_pkt, len, recv_pkt->type, flags, buf, send_tsk);
+
+	if (!send_pkt) {
+		PMSERR(KERN_ERR"Can't create packet\n");
+		return err;
+	}
+
+	/* FIXME: On early packets hpid/rpid are not set correctly, so answer
+	 * can have corrupted [rh]pid */
+	send_pkt->rpid = (recv_pkt->rpid) ? recv_pkt->rpid : send_tsk->rpid;
+	send_pkt->hpid = (recv_pkt->hpid) ? recv_pkt->hpid : send_tsk->hpid;
+
+	send_pkt->msgid=recv_pkt->msgid;
+
+	return kcom_add_packet(send_tsk, send_pkt);
+
+}
+/**
+ * kcom_send_nack
+ *
+ * Description
+ *    Send a nack to the other node.
+ *    An nack is a reply to a received kcom pkt that resulted in a fault.
+ **/
+int kcom_send_nack(struct task_struct *p, const struct kcom_pkt * const recv_pkt)
+{
+	PMSDEBUG_PROTOCOL(1, "protocol: sending NACK packet\n");
+	return __kcom_send_answer(p, recv_pkt, KCOM_NACK_FLAGS, 0, NULL);
+}
+EXPORT_SYMBOL(kcom_send_nack);
+
+
+/**
+ * kcom_send_ack
+ *
+ * Description:
+ *    Send an ack to the other node.
+ *    An ack is the acknowledgement that the kcom pkt was received correctly.
+ **/
+int kcom_send_ack(struct task_struct *p, const struct kcom_pkt * const recv_pkt)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD: sending ACK packet\n");
+	return __kcom_send_answer(p, recv_pkt, KCOM_ACK_FLAGS, 0, NULL);
+}
+EXPORT_SYMBOL(kcom_send_ack);
+
+/**
+ * kcom_send_ack
+ *
+ * Description:
+ *    Send an ack with progress to the other node.
+ *    An ack with progress is the acknowledgement that a kcom pkt was received
+ *    correctly, and are awaiting the next packet in the sequence.
+ **/
+int kcom_send_ack_progress(struct task_struct *p, const struct kcom_pkt * const recv_pkt)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD: sending ACK PTOGRESS packet\n");
+	return __kcom_send_answer(p, recv_pkt, KCOM_ACK_PROG_FLAGS, 0, NULL);
+}
+EXPORT_SYMBOL(kcom_send_ack_progress);
+
+/**
+ * kcom_send_resp
+ *
+ * Description:
+ *    Send an response to the other node.
+ *    A response is both the acknowledgement that the kcom pkt was received
+ *    correctly (or not) and the expected response data.
+ **/
+int kcom_send_resp(struct task_struct *p, int len, char *buf, const struct kcom_pkt * const recv_pkt)
+{
+	PMSDEBUG_KCOMD(2, "KCOMD: send response (len=%d)\n", len);
+	return __kcom_send_answer(p, recv_pkt, KCOM_RESPONSE_FLAGS, len, buf);
+}
+EXPORT_SYMBOL(kcom_send_resp);
+
+/**
+ * __kcom_wait_msg - wait for the next message comming on the task list
+ * this function does not trigger timeout only wait for inband packet
+ * and is used excusively by a deputy
+ **/
+int __kcom_wait_msg(struct kcom_task* tsk, struct kcom_pkt **answerpkt)
+{
+	unsigned long flags;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	if (!tsk)
+		return -ENODEV;
+
+retry_wait:
+
+	read_lock(&tsk->in_packs_lock);
+	if (!list_empty(&tsk->in_packs)){
+		*answerpkt = list_entry(tsk->in_packs.next, struct kcom_pkt, list);
+#if 0
+		if ((*answerpkt)->flags & KCOM_PKT_OOB) {
+		/* FIXME: handle out-of-band packet for THIS process, and then */
+			kcom_pkt_delete(*answerpkt);
+			continue;
+		}
+#endif
+		read_unlock(&tsk->in_packs_lock);
+		return 0;
+	}
+	read_unlock(&tsk->in_packs_lock);
+
+	set_current_state(TASK_INTERRUPTIBLE);
+	schedule();
+	set_current_state(TASK_INTERRUPTIBLE);
+
+	spin_lock_irqsave(&current->sighand->siglock, flags);
+	if (signal_pending(current))
+	{
+		spin_unlock_irqrestore(&current->sighand->siglock, flags);
+		return -EAGAIN;
+	}
+	spin_unlock_irqrestore(&current->sighand->siglock, flags);
+
+	goto retry_wait;
+}
+
+/**
+ * __kcom_wait_next_msg - wait for the next message comming with the given id
+ *
+ * Can timeout ...
+ **/
+int __kcom_wait_for_next_msg(struct kcom_task* tsk, int msgid, struct kcom_pkt **answerpkt)
+{
+	struct kcom_pkt *pkt;
+	long retry_period = 60*HZ;
+	*answerpkt = NULL;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+	do {
+		read_lock(&tsk->in_packs_lock);
+		list_for_each_entry(pkt, &tsk->in_packs, list) {
+#if 0
+			if (pkt->flags & KCOM_PKT_OOB) {
+			/* FIXME: handle out-of-band packet for THIS process, and then */
+				kcom_pkt_delete(pkt);
+				continue;
+			}
+#endif
+			if ((msgid == 0 || msgid==pkt->msgid)) {
+				*answerpkt = pkt;
+				read_unlock(&tsk->in_packs_lock);
+				return 0;
+			}
+		}
+		read_unlock(&tsk->in_packs_lock);
+
+		retry_period=schedule_timeout_interruptible(retry_period);
+		set_current_state(TASK_INTERRUPTIBLE);
+	}
+	while(retry_period>0) ;
+
+	PMSERR("pid[%d] wait for next message timeout\n", tsk->task->pid);
+	return -ETIMEDOUT;
+}
+
+/**
+ * __kcom_wait_for_ack - wait for an 'ACK' or 'NACK' on the misgid
+ * Returns 0 if ok, -ENACKED if NACK and something negative if
+ * error
+ **/
+int __kcom_wait_for_ack(struct kcom_task *tsk, int msgid)
+{
+	struct kcom_pkt* pkt = NULL;
+	int err;
+	unsigned int msgflags;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+
+get_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, msgid, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	msgflags = __kcom_pkt_msg_flags(pkt);
+	switch (msgflags) {
+		case CASE_PKT_ACK :
+			kcom_pkt_delete(pkt);
+			return 0;
+		case CASE_PKT_NACK :
+			kcom_pkt_delete(pkt);
+			return -ENACKED;
+		default:
+			PMSERR("received unexpected packet (type='%s') ... dropping\n" ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+			break;
+	}
+
+	goto get_packet;
+}
+
+/**
+ * __kcom_wait_for_answer - wait for any RESP packet or NACK check for answer size
+ **/
+int __kcom_wait_for_answer(struct kcom_task *tsk, int type, int msgid, struct kcom_pkt** answer)
+{
+	struct kcom_pkt* pkt = NULL;
+	int err;
+	unsigned int msgflags;
+	int size;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	if (answer)
+		*answer = NULL;
+get_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, msgid, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	msgflags = __kcom_pkt_msg_flags(pkt);
+	switch (msgflags) {
+		case CASE_PKT_RESP :
+			size = __get_answer_size(type);
+			if (size != KCOM_NO_SIZE_CHECK && size != pkt->data_len) {
+				kcom_pkt_delete(pkt);
+			PMSERR("received missized packet\n");
+				return -EINVAL;
+			}
+			if (answer) {
+				*answer = pkt;
+			} else {
+				PMSERR("answer received, but no place to store it ...\n");
+			}
+			return 0;
+
+		case CASE_PKT_NACK :
+			kcom_pkt_delete(pkt);
+			return -ENACKED;
+
+		default:
+			PMSERR("received unexpected packet (type='%s') ... dropping\n" ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+			break;
+	}
+
+	goto get_packet;
+	/* Not reached */
+	return -EFAULT;
+}
+
+int __kcom_wait_for_answer_cplx(struct kcom_task* tsk, int type, int msgid, struct kcom_pkt** answer)
+{
+	struct kcom_pkt* pkt = NULL;
+	int err;
+	unsigned int msgflags;
+	int size;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	if (answer)
+		*answer = NULL;
+
+	// Wait for a ACK_PROGRESS to continue, or ACK/NACK to terminate
+get_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, msgid, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	msgflags = __kcom_pkt_msg_flags(pkt);
+	switch (msgflags) {
+		case CASE_PKT_ACK_PROGRESS:
+			kcom_pkt_delete(pkt);
+			goto get_any_packet;
+			break;
+
+		case CASE_PKT_ACK:
+			kcom_pkt_delete(pkt);
+			return 0;
+
+		case CASE_PKT_NACK:
+			kcom_pkt_delete(pkt);
+			return -ENACKED;
+
+		default:
+			PMSERR("received unhandled packet (type='%s') ... dropping\n" ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+			break;
+	}
+	goto get_packet;
+
+	/* We got a CASE_PKT_ACK_PROGRESS ..., we can now activate the complex command */
+get_any_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, 0, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	msgflags = __kcom_pkt_msg_flags(pkt);
+
+	if (pkt->msgid == msgid) {
+		/* Message is related to the initial communication */
+		switch (msgflags) {
+			case CASE_PKT_ACK:
+				kcom_pkt_delete(pkt);
+				return 0;
+
+			case CASE_PKT_RESP:
+				size = __get_answer_size(type);
+				if (KCOM_NO_SIZE_CHECK != size && size != pkt->data_len) {
+					kcom_pkt_delete(pkt);
+					return -EINVAL;
+				}
+				if (answer) {
+					*answer = pkt;
+				} else {
+					PMSERR("answer received, but no place to store it ...\n");
+				}
+				return 0;
+
+			case CASE_PKT_NACK:
+				kcom_pkt_delete(pkt);
+				return -ENACKED;
+
+			default:
+				PMSERR("received unhandled packet (type='%s') ... dropping\n" ,__get_packet_name(pkt->type));
+				kcom_pkt_delete(pkt);
+				break;
+		}
+	} else {
+		/* Package is not linked to this id, new command ? */
+		if (CASE_PKT_NEW_MSG == msgflags) {
+			if (__is_kcom_l2_pkt_type(pkt->type))
+				kcomd_do_l2_state_machine(tsk, pkt);
+			else
+				PMSERR("received unexpected new message (type='%s') ... dropping\n" ,__get_packet_name(pkt->type));
+
+			kcom_pkt_delete(pkt);
+		} else {
+			PMSERR("received unhandled packet (type='%s') ... dropping\n"
+                        ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+		}
+	}
+	goto get_any_packet;
+
+	/* Not reached */
+	return -EFAULT;
+}
+
+int __kcom_wait_for_answer_cplx1(struct kcom_task* tsk, int type, int msgid, struct kcom_pkt** answer)
+{
+	struct kcom_pkt* pkt = NULL;
+	int err;
+	unsigned int msgflags;
+	/* int size; */
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	if (answer)
+		*answer = NULL;
+
+	/* Wait for a ACK_PROGRESS or ACK/NACK to continue or terminate : */
+get_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, msgid, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	msgflags = __kcom_pkt_msg_flags(pkt);
+	switch (msgflags) {
+		case CASE_PKT_ACK_PROGRESS:
+			kcom_pkt_delete(pkt);
+			return 666;
+
+		case CASE_PKT_ACK:
+			kcom_pkt_delete(pkt);
+			return 0;
+
+		case CASE_PKT_NACK:
+			kcom_pkt_delete(pkt);
+			return -ENACKED;
+
+		default:
+			PMSERR("cplx1 received unhandled packet (type='%s') ... dropping\n"
+				,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+			break;
+	}
+	goto get_packet;
+}
+
+int __kcom_wait_for_answer_cplx3(struct kcom_task* tsk, int type, int msgid, struct kcom_pkt** answer)
+{
+	struct kcom_pkt* pkt = NULL;
+	int err;
+	int size;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	if (answer)
+		*answer = NULL;
+
+	/* We got a CASE_PKT_ACK_PROGRESS ..., we can now activate the complex command */
+get_any_packet:
+
+	err = __kcom_wait_for_next_msg(tsk, 0, &pkt);
+	if (err < 0 || !pkt)
+		return err;
+
+	if (pkt->msgid == msgid) {
+		//PMSERR("cplx3 received '%s' pkt->msgid=%d valid!\n",__get_packet_name(pkt->type), pkt->msgid);
+		/* Message is related to the initial communication */
+		switch (__kcom_pkt_msg_flags(pkt)) {
+			case CASE_PKT_ACK:
+				kcom_pkt_delete(pkt);
+				return 0;
+
+			case CASE_PKT_RESP:
+				size = __get_answer_size(type);
+				if (KCOM_NO_SIZE_CHECK != size && size != pkt->data_len) {
+					kcom_pkt_delete(pkt);
+				PMSERR("received missized packet\n");
+					return -EINVAL;
+				}
+				if (answer) {
+					*answer = pkt;
+				} else {
+					PMSERR( "answer received, but no place to store it ...\n");
+				}
+				return 0;
+
+			case CASE_PKT_NACK:
+				kcom_pkt_delete(pkt);
+				return -ENACKED;
+
+			default:
+				PMSERR("cplx3 received unexpected packet (type='%s') ... dropping\n"
+					,__get_packet_name(pkt->type));
+				kcom_pkt_delete(pkt);
+				goto get_any_packet;
+				break;
+		}
+	} else {
+		PMSERR("cplx3 received (type='%s' pkt->msgid=%d) Beasting!!!\n"
+			,__get_packet_name(pkt->type), pkt->msgid);
+		if (answer) {
+			*answer = pkt;
+		} else {
+			PMSERR( "answer received, but no place to store it ...\n");
+		}
+		return 666;
+	}
+
+	/* Not reached */
+	return -EFAULT;
+}
+
+int __kcom_wait_for_answer_cplx4(struct kcom_task* tsk, int type, int msgid, struct kcom_pkt* pkt)
+{
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	if (pkt == NULL) {
+		PMSERR("lost the packet\n");
+		return -EINVAL;
+	}
+
+	/* Package is not linked to this id, new command ? */
+	if (CASE_PKT_NEW_MSG == __kcom_pkt_msg_flags(pkt)) {
+		if (__is_kcom_l2_pkt_type(pkt->type)) {
+			kcomd_do_l2_state_machine(tsk, pkt);
+			kcom_pkt_delete(pkt);
+		}
+		else {
+			PMSERR("cplx4 received unhandled new message packet (type='%s') ... dropping\n"
+                        ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+		}
+	}
+	else {
+		PMSERR("cplx4 received unhandled packet (type='%s') ... dropping\n"
+		,__get_packet_name(pkt->type));
+		kcom_pkt_delete(pkt);
+	}
+	return(0);
+}
+
+
+/**
+ * kcom_send_command
+ *
+ * Description:
+ *    Send the command and execute the packet processing loop according to the
+ *    command flags. return 0 in case of success, something negative if error
+ *    If the packet involves an answer, the ack goes to to the 'answer' pointer
+ **/
+int __kcom_send_command(struct kcom_task* tsk, int type, int datasize
+			, const char * const data, unsigned long addr
+		        ,const struct sockaddr_in * const saddr
+		        , struct kcom_pkt ** answer)
+{
+	unsigned int msgid;
+	unsigned int cmdflags;
+	int	ret;
+
+	PMSDEBUG_KCOMD(2, "Sending packet with response (type='%s', datasize=%d)\n"
+			, __get_packet_name(type), datasize);
+
+	msgid = kcom_task_send(tsk, type, datasize, data, addr);
+	if (msgid<0)
+		return msgid;
+
+	/* Now we have multiple choices, depending on the command cmds */
+
+	cmdflags = __get_default_flags(type);
+
+	if (cmdflags == KCOM_ASYNC_SIMPLE)
+		ret = 0;
+	else if (cmdflags & KCOM_PKT_CPLX) {
+		//ret = __kcom_wait_for_answer_cplx(tsk, type, msgid, answer);
+		ret = __kcom_wait_for_answer_cplx1(tsk, type, msgid, answer);
+		if(ret == 666) {
+agayn:
+			/* FIXME: we are coming here after completing in __kcom_wait_for_answer_cplx1,
+			 * the next message is sometimes a new message */
+			ret = __kcom_wait_for_answer_cplx3(tsk, type, msgid, answer);
+			if(ret == 666) {
+				ret = __kcom_wait_for_answer_cplx4(tsk, type, msgid, *answer);
+				if(!ret) {
+					goto agayn;
+				}
+			}
+		}
+	}
+	else if (cmdflags & KCOM_PKT_ANSWERED)
+		ret = __kcom_wait_for_answer(tsk, type, msgid, answer);
+	else if (cmdflags & KCOM_PKT_SYNC)
+		ret = __kcom_wait_for_ack(tsk, msgid);
+	else
+		ret = -EFAULT;
+
+#if 0
+	/* if the process has not been deleted */
+	if(tsk)
+		++tsk->msgid;
+#endif
+	if(unlikely(ret<0))
+		PMSERR("error=%d\n",ret);
+
+	return ret;
+
+}
+
+int kcom_send_command(int type, int datasize, const char * const data, unsigned long addr
+		     ,const struct sockaddr_in * const saddr, struct kcom_pkt ** answer)
+{
+	int ret;
+	struct kcom_task *tsk;
+
+	PMSDEBUG_KCOMD(2, "KCOMD:\n");
+	/* Send the command first ... */
+	ret = __kcom_find_or_create_task(saddr, &tsk, current->pid);
+	if (likely(ret>=0))
+		return __kcom_send_command(tsk, type, datasize, data, addr, saddr, answer);
+
+	PMSERR("failed to __kcom_find_or_create_task %d\n", ret);
+	return ret;
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/kcomd.c linux-2.6.28.7-pms/hpc/kcomd.c
--- linux-2.6.28.7/hpc/kcomd.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/kcomd.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,1455 @@
+/*
+ *	Copyright (C) 2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * kcomd thread by Matt Dew and Florian Delizy
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/socket.h>
+#include <linux/in.h>
+#include <linux/in6.h>
+#include <linux/net.h>
+#include <linux/syscalls.h>
+#include <linux/poll.h>
+#include <linux/inet.h>
+#include <linux/net.h>
+#include <linux/time.h>
+
+#include <net/sock.h>
+#include <net/tcp.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/kcom.h>
+#include <hpc/mig.h>
+#include <hpc/deputy.h>
+#include <hpc/remote.h>
+
+
+/*******************************************************************************
+ * Socket handling                                                             *
+ ******************************************************************************/
+
+
+/**
+ * socket_listen - Creates the network socket and maps it to a file descriptor
+ **/
+static int socket_listen(struct sockaddr *saddr, struct socket **res)
+{
+	struct socket *sock;
+	int fd, ret=0;
+
+	ret = sock_create_kern(saddr->sa_family, SOCK_STREAM, IPPROTO_TCP, &sock);
+	if (likely(ret >= 0)) {
+		fd = sock_map_fd(sock, O_NONBLOCK);
+		if (likely(fd >= 0)) {
+			ret = sock->ops->bind(sock, saddr, sizeof(*saddr));
+			if (likely(ret >= 0)) {
+				ret = sock->ops->listen(sock, SOMAXCONN);
+				if (likely(ret >= 0)) {
+					*res = sock;
+					return fd;
+				}
+				sock_release(sock);
+				--ret;
+			}
+			sys_close(fd);
+			--ret;
+		}
+		--ret;
+	}
+	*res = NULL;
+	--ret;
+	return ret;
+}
+
+static int socket_listen_ip4(int port, struct socket **res)
+{
+	struct sockaddr_in saddr4 = {
+		.sin_family = AF_INET,
+		.sin_addr.s_addr = INADDR_ANY,
+		.sin_port = htons(port),
+	};
+
+	return socket_listen((struct sockaddr *) &saddr4, res);
+}
+
+static int socket_listen_ip6(int port, struct socket **res)
+{
+	struct sockaddr_in6 saddr6 = {
+		.sin6_family = AF_INET6,
+		.sin6_port = htons(port),
+	};
+
+	return socket_listen((struct sockaddr *) &saddr6, res);
+}
+
+/*******************************************************************************
+ * Connection handling                                                         *
+ ******************************************************************************/
+
+/**
+ * accept_connection
+ *
+ * Description:
+ *    Once kcomd's sockets receive a new connection attempt,
+ *    the connection is accepted and accept_connection called, 
+ *    accept_connection then retreives the remote IP address,
+ *    maps the file descriptor and create the
+ *    kcom node with those information.
+ **/
+static int accept_connection(struct socket *lsock)
+{
+	struct socket *sock;
+	struct kcom_node *node;
+	int ret, fd;
+	int len;
+	struct sockaddr_in address;
+
+	sock = sock_alloc();
+	if (likely(sock)) {
+		sock->type = lsock->type;
+		sock->ops = lsock->ops;
+		ret = lsock->ops->accept(lsock, sock, 0);
+		if (likely(!ret)) {
+			ret = sock->ops->getname(sock, (struct sockaddr *)&address, &len, 1);
+			if (likely(!ret)) {
+				fd = sock_map_fd(sock, O_NONBLOCK);
+				if (likely(fd >= 0)) {
+					node = kcom_node_add(sock);
+					if (likely(node!=NULL)) {
+						// Store the IP addr.
+						memcpy(&node->addr, &address, sizeof(address));
+						node->fd=fd;
+						// Allocated file descriptor bitmap for do_select
+						alloc_fd_bitmap(fd);
+						return fd;
+					}
+					sys_close(fd);
+				}
+			}
+		}
+		sock_release(sock);
+	}
+	return -1;
+}
+
+/*******************************************************************************
+ * Stream Handling handling                                                    *
+ ******************************************************************************/
+
+/**
+ * data_send
+ *
+ * Description:
+ *    Sends the kcom pkt header and the data, if any.
+ *    return 0 on success, a negative value if not
+ *
+ *    This function may schedule
+ **/
+
+int data_send(struct socket *sock, struct kcom_pkt* pkt)
+{
+
+	struct msghdr msg;
+	struct kvec packet[2] = {{0},{0}};
+	int nvec = 1;
+	int total_data = 0;
+	int first_vec = 0;
+	int sent = 0;
+	int i;
+	int first_loop = 1;
+	int nb_retries = 0;
+
+	/* Sanity check */
+
+	if (!pkt) {
+	    PMSERR("Can not send null packet\n");
+	    return -EFAULT;
+	}
+
+	PMSDEBUG_KCOMD(2, "KCOMD: send packet type=%s len=%d\n"
+			,__get_packet_name(pkt->type), pkt->data_len);
+
+	PMSDEBUG_KCOMD_DO(5, pms_dump_packet(pkt));
+
+	/* Prepare packets */
+
+	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;
+
+	packet[0].iov_base = pkt;
+	packet[0].iov_len = KCOM_PKT_NET_SIZE;
+	if (pkt->data_len) {
+		packet[1].iov_len = pkt->data_len;
+		packet[1].iov_base = pkt->data;
+		if(!pkt->data) {
+			PMSERR("Packet has data length, but no data pointer");
+			return -EFAULT;
+		}
+		nvec++;
+
+	}
+
+	total_data = packet[0].iov_len + packet[1].iov_len;
+	while (total_data > 0) {
+
+		sent = kernel_sendmsg(sock, &msg, &packet[first_vec], 2 - first_vec, total_data);
+
+		/* kernel_sendmsg can fail if no space left on skbuff, or interrupted ... */
+		if (sent == -ENOSPC || sent == -EAGAIN || sent == 0) {
+
+			if (first_loop && total_data == packet[0].iov_len + packet[1].iov_len)
+				return -EAGAIN;
+
+			first_loop = 0;
+
+			if (HZ*60 < ++nb_retries)
+				return -ETIMEDOUT;
+
+			if (nb_retries%HZ == 0)
+				printk(KERN_WARNING"Can not send packet for now, retrying\n");
+
+			schedule_timeout(1);
+			continue;
+		}
+		first_loop = 0;
+
+		/* if something wrong happened :*/
+		if (sent < 0) {
+			PMSERR("Can not send data : error %d\n", sent);
+			return sent;
+		}
+
+		/* check all is sent and retry to send in case not */
+		total_data -= sent;
+		if (!total_data)
+			break;
+
+		/* Thanks to fs/cifs/transport.c !*/
+
+		for (i = first_vec; i < 2; i++) {
+			if (!packet[i].iov_len)
+				continue;
+			if (sent > packet[i].iov_len) {
+				sent -= packet[i].iov_len;
+				packet[i].iov_len = 0;
+			} else {
+				packet[i].iov_base += sent;
+				packet[i].iov_len  -= sent;
+				first_vec = i;
+				break;
+			}
+		}
+	}
+	return 0;
+}
+
+/**
+ * data_exception
+ *
+ * Description:
+ *    Dropped connections need to be cleaned up.  Memory freed,
+ *    file descriptors unmapped, etc.  This function does that.
+ *    FIXME:  Supposed to, but doesn't work yet.  Dropped connections
+ *    are seen as data, of length 0, is available for read.
+ **/
+int data_exception(struct kcom_node *node)
+{
+
+	sock_release(node->sock);
+	sys_close(node->fd);
+	/* kfree(node->sock);*/
+	list_del(&node->list);
+	kmem_cache_free(kcom_node_cachep, node);
+	/* kfree(node);*/
+	return 0;
+}
+
+/*******************************************************************************
+ * L1 Protocol Automat definition :                                            *
+ ******************************************************************************/
+
+/* FIXME/
+ * Out of band packets shall be ASYNC as the ACK/ANSWER will not wake up the
+ * right task ... (the task sending the packet is not the one issuing the command)
+ */
+
+struct kcom_pkt_l1_handler kcomd_l1_handlers[KCOM_L1_CMD_INDEX(KCOM_L1_CMD_MAX)] = {
+	[0] = { .handle_pkt = mig_do_l1_error },
+
+        /* Initiate a process migration */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_MIG_INIT)] = {
+		.handle_pkt = mig_do_receive_init,
+    	        .cmd_flags = KCOM_TSK_ANSWERED,
+    	        .answer_size = sizeof(pid_t),
+    	        .name = "Migration Init" },
+
+        /* Ask the remote to come home */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_MIG_COME_HOME)] = {
+		.handle_pkt = mig_do_come_home,
+		.cmd_flags = KCOM_SYNC,
+		.name = "Come Home Request"},
+
+        /* Send a signal to the remote */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_DEP_SIGNAL)] = {
+		.handle_pkt = remote_do_signal,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+                .recv_size = sizeof(struct pmsp_signal),
+		.name = "Signal"},
+
+	/************************************/
+	/*         Ptrace commands          */
+	/************************************/
+
+        /* Attach a remote process */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_PTRACE_ATTACH)] = {
+		.handle_pkt = remote_ptrace_attach,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+                .recv_size = sizeof(int),
+		.name = "Deputy Ptrace Attach"},
+
+        /* Get the remote task state */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_GET_TASK_STATE)] = {
+		.handle_pkt = remote_get_task_state,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+                .recv_size = 0,
+                .answer_size = sizeof(struct pmsp_get_task_state),
+		.name = "Get Remote Task State"},
+
+        /* Get the remote task state */
+	[KCOM_L1_CMD_INDEX(KCOM_L1_SET_TRACED)] = {
+		.handle_pkt = remote_set_traced,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+		.name = "Set Remote TASK_TRACED"},
+
+        /* detach the task*/
+	[KCOM_L1_CMD_INDEX(KCOM_L1_PTRACE_DETACH)] = {
+		.handle_pkt = remote_ptrace_detach,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+		.recv_size = sizeof( int ),
+		.name = "Deputy Ptrace Detach"},
+
+        /* attach the task*/
+	[KCOM_L1_CMD_INDEX(KCOM_L1_PTRACE_GETSET_LONG)] = {
+		.handle_pkt = remote_ptrace,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.recv_size = sizeof(struct pmsp_ptrace_getset_long),
+		.answer_size = sizeof(long),
+		.name = "Deputy Ptrace Get/Set Long"},
+
+};
+EXPORT_SYMBOL_GPL(kcomd_l1_handlers);
+
+
+
+/**
+ * __find_task_for_packet - Finds the kcom_task for the given packet
+ **/
+
+struct kcom_task * __find_task_for_packet(const struct kcom_pkt* const pkt
+					 ,struct kcom_node* node
+				         ,pid_t *dpid)
+{
+	struct kcom_task* tsk, *tskret=NULL;
+	int offset;
+	pid_t pid;
+
+	if (KCOM_PKT_DEP_FLG == __kcom_pkt_node_flags(pkt)) {
+		/* command from dep to remote? */
+		pid = pkt->rpid;
+		offset = (int) &(((struct kcom_task*) 0)->rpid);
+	} else {
+		pid = pkt->hpid;
+		offset = (int) &(((struct kcom_task*) 0)->hpid);
+	}
+
+	read_lock(&node->tasks_lock);
+
+	list_for_each_entry(tsk, &node->tasks, list) {
+		if (pid == *((pid_t*)(((char*)tsk)+offset))) {
+			tskret = tsk;
+			goto return_unlock;
+		}
+	}
+
+return_unlock:
+	read_unlock(&node->tasks_lock);
+
+	if (dpid)
+		*dpid = pid;
+	return tskret;
+}
+
+/**
+ * update_task_msgid
+ **/
+
+void update_task_msg_id(const struct kcom_pkt* const pkt, struct kcom_node* node)
+{
+	struct kcom_task *tsk = NULL;
+
+	tsk = __find_task_for_packet(pkt, node, NULL);
+	if (!tsk)
+		return;
+
+	spin_lock(&tsk->msgid_lock);
+	if(pkt->msgid > tsk->msgid) {
+		tsk->msgid = pkt->msgid;
+	}
+	spin_unlock(&tsk->msgid_lock);
+}
+
+/**
+ * pkt_read
+ *
+ * Description:
+ *      and put in appropriate task's
+ *    in_pack list.
+ *    All but 3 pkts can be handled by the task itself.
+ *    MIG_INIT creates a new process and task
+ *    MIG_GO/COME_HOME - migration command.
+ **/
+int pkt_read(struct kcom_node *node)
+{
+	struct kcom_pkt *pkt;
+	int i = 0;
+
+	i = __pkt_read( node, &pkt);
+	if (i<0)
+		return i;
+
+	PMSDEBUG_PROTOCOL_DO(5, pms_dump_packet(pkt));
+
+	if (CASE_PKT_NEW_MSG == __kcom_pkt_msg_flags(pkt)) {
+		struct kcom_task* tsk;
+		struct task_struct* p;
+		int pid;
+		int size;
+
+		/* Handle the automatic ack for new messages */
+		if (!(KCOM_PKT_SYNC & __kcom_pkt_cmd_flags(pkt)))
+			goto no_ack;
+
+		if (KCOM_PKT_TSK_ACKED & __kcom_pkt_cmd_flags(pkt)
+		   && !(KCOM_PKT_CPLX & __kcom_pkt_cmd_flags(pkt)))
+			goto no_ack;
+
+		update_task_msg_id(pkt, node);
+
+		tsk = __find_task_for_packet(pkt, node, &pid);
+		if(!tsk) {
+			PMSERR("Can't find process[%d] for packet...(type='%s') ... dropping\n", pid ,__get_packet_name(pkt->type));
+			/* FIXME Should NACK here */
+			kcom_pkt_delete(pkt);
+			return -ENODEV;
+		}
+
+		p = tsk->task;
+		if(!p) {
+			PMSERR("Unable to find process[%d], (type='%s') ... dropping\n", pid ,__get_packet_name(pkt->type));
+			kcom_pkt_delete(pkt);
+			return -ENODEV;
+		}
+
+		size = __get_receive_size(pkt->type);
+		if ((size != KCOM_NO_SIZE_CHECK) && (size != pkt->data_len)) {
+			PMSERR("received corrupted packet \n");
+			kcom_send_nack(p, pkt);
+			goto no_ack;
+		}
+
+		if (KCOM_PKT_CPLX & __kcom_pkt_cmd_flags(pkt)) {
+			kcom_send_ack_progress(p, pkt);
+		} else {
+			kcom_send_ack(p, pkt);
+		}
+	}
+
+no_ack:
+	/* Check if we must send the ack right away */
+
+	if (__is_kcom_l1_pkt(pkt) && __kcom_pkt_msg_flags(pkt) == CASE_PKT_NEW_MSG) {
+		int err;
+		PMSDEBUG_PROTOCOL(2, "KCOMD L1 packet '%s' received\n",
+				__get_packet_name(pkt->type));
+
+		err = kcomd_l1_handlers[KCOM_L1_CMD_INDEX(pkt->type)].handle_pkt(node, pkt);
+
+		if (err < 0 && KCOM_PKT_SYNC&__kcom_pkt_cmd_flags(pkt)) {
+			PMSERR(" kcomd L1: command %s failed\n"
+			      , __get_packet_name(pkt->type));
+		}
+
+		kcom_pkt_delete(pkt);
+		return 0;
+	} else {
+		append_in_packs(pkt, node);
+	}
+
+	return 0;
+
+}
+
+/*******************************************************************************
+ * L1 layer to L2 interface                                                    *
+ ******************************************************************************/
+
+
+/**
+ * append_in_packs
+ *
+ * Description:
+ *    Packets are either new pkts, or responses or (n)acks to new pkts.
+ *    If a pkt isn't new, a function is waiting on it (wait_for_ack/response),
+ *    so we can just add this pkt to the task in_packs list.
+ **/
+int append_in_packs(struct kcom_pkt *pkt, struct kcom_node* node)
+{
+	struct kcom_task *tsk;
+	struct task_struct *sltsk;
+	pid_t pid;
+
+	tsk = __find_task_for_packet(pkt, node, &pid);
+
+	if (!tsk) {
+		PMSERR("Unable to find process[%u] for packet...(type='%s') ... dropping\n", pid ,__get_packet_name(pkt->type));
+		kcom_pkt_delete(pkt);
+		return 0;
+	}
+
+	/* append the packet */
+	write_lock(&tsk->in_packs_lock);
+	list_add_tail(&pkt->list, &tsk->in_packs);
+	write_unlock(&tsk->in_packs_lock);
+
+	/* Find the real task */
+
+	read_lock(&tasklist_lock);
+	sltsk = find_task_by_vpid(pid);
+	read_unlock(&tasklist_lock);
+	/* Waking up the task */
+
+	if (sltsk) {
+	    wake_up_process(sltsk);
+	} else {
+	    PMSERR("Unable to find process [%u] to wake up\n", pid);
+	    return -ENODEV;
+	}
+	return 0;
+}
+
+/*******************************************************************************
+ * L2 protocol interface 	 					       *
+ ******************************************************************************/
+
+/*
+ * kcomd_do_l2_state_machine - execute the packet handler after checking
+ * permissions
+ **/
+
+int kcomd_do_l2_state_machine(struct kcom_task* tsk, const struct kcom_pkt* const pkt)
+{
+	int index;
+	int size;
+	int err = 0;
+
+	if(!pkt)
+		return -EFAULT;
+
+	if (!__is_kcom_l2_pkt_type(pkt->type))
+		return -EINVAL;
+
+	index = KCOM_L2_CMD_INDEX(pkt->type);
+	if (!kcomd_l2_handlers[index].perms&current->pms.dflags) {
+		PMSERR("Pid[%d] Received unallowed packet, sending NACK!\n", tsk->task->pid);
+		err = -EPERM;
+		goto error;
+	}
+
+	size = __get_receive_size(pkt->type);
+	if (KCOM_NO_SIZE_CHECK != size && size != pkt->data_len) {
+		PMSERR("Pid[%d] Received corrupted packet, sending NACK!\n", tsk->task->pid);
+		err = -EINVAL;
+		goto error;
+	}
+
+	err =  kcomd_l2_handlers[index].handle_pkt(tsk, pkt);
+	return err;
+
+error:
+	if (KCOM_ASYNC_SIMPLE != __kcom_cmd_flags(pkt->type))
+		kcom_send_nack(tsk->task, pkt);
+	return err;
+
+
+}
+
+
+struct kcom_pkt_l2_handler kcomd_l2_handlers[KCOM_L2_CMD_MAX-KCOM_L2_CMD_START]= {
+
+	/************************************/
+	/*        Migration commands        */
+	/************************************/
+
+
+	/* Send the mm struct of a process */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_MM)] = {
+		.handle_pkt = mig_do_receive_mm,
+		.cmd_flags = KCOM_SYNC,
+		.perms = KCOM_PERM_MIGRATION,
+		.recv_size = sizeof(struct pmsp_mig_mm),
+		.name = "Migration Send MM"},
+
+	/* Send the vma struct of a process */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_VMA)] = {
+		.handle_pkt = mig_do_receive_vma,
+		.cmd_flags = KCOM_SYNC,
+		.perms = KCOM_PERM_MIGRATION,
+		.recv_size = sizeof(struct pmsp_mig_vma),
+		.name = "Migration Send VMA"},
+
+	/* Send a page of a struct          */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_PAGE)] = {
+		.handle_pkt = mig_do_receive_page,
+		.cmd_flags = KCOM_SYNC,
+		.perms = KCOM_PERM_MIGRATION,
+		.recv_size = PAGE_SIZE,
+		.name = "Migration Send Page"},
+
+	/* Send the floating point struct */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_FP)] = {
+		.handle_pkt = mig_do_receive_fp,
+		.cmd_flags = KCOM_SYNC,
+		.recv_size = sizeof(struct pmsp_mig_fp),
+		.perms = KCOM_PERM_MIGRATION,
+		.name = "Migration Send FP"},
+
+#if 0
+	/* Send arch specific data          */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_ARCH)] = {
+		.handle_pkt = mig_do_receive_arch,
+		.cmd_flags = KCOM_SYNC,
+		.recv_size =  0,
+		.perms = KCOM_PERM_MIGRATION,
+		.name = "Migration Send Arch"},
+#endif
+
+	/* Send the task struct info        */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_TASK)] = {
+		.handle_pkt = mig_do_receive_proc_context,
+		.cmd_flags = KCOM_TSK_SYNC,
+		.recv_size = sizeof(struct pmsp_mig_task),
+		.perms = KCOM_PERM_MIGRATION,
+		.name = "Migration Send Task"},
+
+	/************************************/
+	/*       Processing commands        */
+	/************************************/
+
+        /* Tell the deputy that the remote is coming home */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_GO_HOME)] = {
+		.handle_pkt = mig_do_receive_home,
+		.cmd_flags = KCOM_SYNC,
+		.perms = DDEPUTY,
+		.name = "Coming Back Home"},
+
+        /* Tell the deputy that the remote is exiting */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_END_OF_PROCESS)] = {
+		.handle_pkt = mig_do_end_of_process,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+		.recv_size = sizeof(long),
+		.perms = DDEPUTY,
+		.name = "End Of Process"},
+
+        /* Remote syscall, deputy <-> remote */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_MIG_SYSCALL)] = {
+		.handle_pkt = deputy_do_syscall,
+		.cmd_flags = KCOM_COMPLEX_MSG | KCOM_PKT_ANSWERED,
+                .recv_size = sizeof(struct pmsp_syscall_req),
+                .answer_size = sizeof(struct pmsp_syscall_ret),
+		//.perms = DDEPUTY | DREMOTE,
+		.perms = DDEPUTY,
+		.name = "Remote Syscall"},
+
+        /* Remote strncopy from user */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_STRNCPY_FROM_USER)] = {
+		.handle_pkt = remote_strncpy_from_user,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = KCOM_PERM_SYSCALL,
+                .recv_size = sizeof(struct pmsp_usercopy_req),
+                .answer_size = KCOM_NO_SIZE_CHECK,
+		.name = "Remote strncpy"},
+
+        /* Remote copy from user */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_COPY_FROM_USER)] = {
+		.handle_pkt = remote_copy_from_user,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = KCOM_PERM_SYSCALL,
+                .recv_size =sizeof(struct pmsp_usercopy_req),
+                .answer_size =KCOM_NO_SIZE_CHECK,
+		.name = "Remote copy_from_user"},
+
+        /* Remote get_user */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_GET_USER)] = {
+		.handle_pkt = remote_get_user,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = KCOM_PERM_SYSCALL,
+                .recv_size =sizeof(struct pmsp_usercopy_req),
+                .answer_size =sizeof(s64),
+		.name = "Remote get_user"},
+
+	/* Request during syscalls */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_COPY_TO_USER)] = {
+		.handle_pkt =remote_copy_to_user,
+		.cmd_flags = KCOM_SYNC,
+		.perms = KCOM_PERM_SYSCALL,
+                .recv_size = KCOM_NO_SIZE_CHECK,
+                .answer_size =0,
+		.name = "Remote copy_to_user"},
+
+        /* Remote put_user */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_PUT_USER)] = {
+		.handle_pkt = remote_put_user,
+		.cmd_flags = KCOM_PKT_SYNC,
+		.perms = KCOM_PERM_SYSCALL,
+                .recv_size =sizeof(struct pmsp_usercopy_emb),
+		.name = "Remote put_user"},
+
+        /* Remote asked for a fork */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_DO_FORK)] = {
+		.handle_pkt = deputy_do_fork,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = DDEPUTY,
+                .recv_size =sizeof(struct pmsp_fork_req),
+                .answer_size =sizeof(struct pmsp_fork_ret),
+		.name = "Remote Fork"},
+
+        /* Read a page on the deputy and send it back */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_GET_PAGE)] = {
+		.handle_pkt = deputy_do_readpage,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = DDEPUTY,
+                .recv_size =sizeof(struct pmsp_page_req),
+                .answer_size = PAGE_SIZE,
+		.name = "Remote Read Page"},
+
+        /* Remote ask an mmap to its deputy */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_MMAP)] = {
+		.handle_pkt = deputy_do_mmap,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = DDEPUTY,
+                .recv_size = sizeof(struct pmsp_mmap_req),
+                .answer_size = sizeof(struct pmsp_mmap_ret),
+		.name = "Remote mmap"},
+
+        /* Remote informs ask execve */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_DO_EXECVE)] = {
+		.handle_pkt = deputy_do_execve,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = DDEPUTY,
+                .recv_size = sizeof(struct pmsp_execve_req),
+                .answer_size = sizeof(struct pmsp_execve_ret),
+		.name = "Remote execve"},
+
+        /* remote strlen user */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_REQ_STRNLEN_USER)] = {
+		.handle_pkt = remote_strnlen_user,
+		.cmd_flags = KCOM_TSK_ANSWERED,
+		.perms = DDEPUTY | DREMOTE,
+                .recv_size =sizeof(struct pmsp_usercopy_req),
+                .answer_size = sizeof(long),
+		.name = "Remote strlen_user"},
+
+	/* ptrace things : */
+	[KCOM_L2_CMD_INDEX(KCOM_L2_NOTIFY_CLDSTOP)] = {
+		.handle_pkt = deputy_do_notify_parent_cldstop,
+		.cmd_flags = KCOM_ASYNC_SIMPLE,
+		.perms = DDEPUTY,
+                .recv_size = sizeof(struct pmsp_do_notify_parent_cldstop),
+		.name = "Remote do_notify_parent_cldstop"},
+};
+
+
+/*******************************************************************************
+ * kcomd_thread daemon face                                                    *
+ ******************************************************************************/
+
+static int kcomd_done = 0;
+static int kcomd_module_exit = 0;
+static void kcomd_thread_free_ressources(void);
+
+/**
+ * kcomd_thread_initialize
+ *
+ * Description:
+ *    initialize caches for kcomd_thread function
+ **/
+
+static void kcomd_thread_initialize(void)
+{
+	/* pkt are allocated with SLAB for performance reasons */
+	kcom_pkt_cachep =kmem_cache_create("kcom_pkt_cache"
+					  ,sizeof(struct kcom_pkt)
+					  ,0, 0, NULL);
+
+	/* task descriptions are allocated by SLAB too */
+	kcom_task_cachep=kmem_cache_create("kcom_task_cache"
+					  , sizeof(struct kcom_task)
+					  , 0, 0, NULL);
+
+	/* FIXME This should not be allocated by SLAB */
+	kcom_node_cachep=kmem_cache_create("kcom_node_cache"
+					  , sizeof(struct kcom_node)
+					  , 0, 0, NULL);
+}
+
+
+/**
+ * kcomd_thread_set_fds
+ *
+ * Description:
+ *    Set the fd_set_bits properly for the select call (only used in kcomd_thread)
+ **/
+static void kcomd_thread_set_fds(int n)
+{
+	struct kcom_node *node;
+	struct kcom_task *task;
+	/* for each nodes (set fds.in && fds.out) and reset the waiting fds */
+
+	PMSDEBUG_KCOMD( 4, "Clearing select fdsets (%d fdsets)\n", n);
+
+	zero_fd_set(n, sockets_fds.in);
+	zero_fd_set(n, sockets_fds.out);
+	zero_fd_set(n, sockets_fds.ex);
+	PMSDEBUG_KCOMD( 4, "list_for_each_entry\n");
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(node, &kcom_nodes, list) {
+
+		if (node->fd < 0 || node->fd > maxfds) {
+			PMSERR( "KCOMD found invalid fd ?\n");
+			schedule_timeout_interruptible(HZ);
+			continue;
+		}
+
+		/* if a file descriptor is open, we want select to pay attention.*/
+		PMSDEBUG_KCOMD( 4, "Setting fd %d\n", node->fd );
+		set_bit(node->fd, sockets_fds.in);
+		set_bit(node->fd, sockets_fds.ex);
+
+		/* if there are packets to be sent, select should pay attention.*/
+		read_lock(&node->tasks_lock);
+		list_for_each_entry(task, &node->tasks, list)
+			if (!list_empty(&task->out_packs)) {
+				PMSDEBUG_KCOMD(4, "Setting out flag for fd %d\n", node->fd );
+				set_bit(node->fd, sockets_fds.out);
+			}
+		read_unlock(&node->tasks_lock);
+	}
+	read_unlock(&kcom_nodes_lock);
+
+	zero_fd_set(n, sockets_fds.res_in);
+	zero_fd_set(n, sockets_fds.res_out);
+	zero_fd_set(n, sockets_fds.res_ex);
+}
+
+/**
+ * kcomd_leave_cluster
+ *
+ * Description:
+ *    This function is called before the kcomd_thread daeomon quits
+ *    because of module unloading (FIXME or kernel stop ??) and
+ *    return 0 if kcomd_thread can stop operations.
+ *    This function is responsible for sending back all remote
+ *    and retreiving all deputies back ...
+ **/
+
+int kcomd_leave_cluster(void)
+{
+
+	int ret = 0;
+	struct kcom_node* node;
+
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry(node, &kcom_nodes, list) {
+
+	    if (!list_empty(&node->tasks)) {
+	    /*
+	     * fdy, FIXME: when exiting kcomd we should ask all tasks to comeback ...
+	     * send back all tasks, then prevent new one to comeback ... this needs an
+	     * upgrade of this thread ... Moreover, there seems to have kcache_*alloc
+	     * misusage, before exit ... (for now just prevent exit ..., with a message
+	     */
+
+		PMSERR("kcomd FIXME, there are still remote/deputy "
+		       "tasks, I can't die now!\n");
+		ret = 1;
+		break;
+	    }
+
+	}
+
+	read_unlock(&kcom_nodes_lock);
+
+
+	return ret;
+}
+
+/**
+ * kcomd_node_increment_error
+ *
+ * Description:
+ *    Increment both permanent and consecutive error count,
+ *    if the error count reach a critical level, delete all
+ *    tasks and delete the node ...
+ *
+ *    Returns the new consecutive error count
+ *
+ *    FIXME: the node deletion is not yet done, but should be!!
+ **/
+int kcomd_node_increment_error(struct kcom_node *node)
+{
+        if (!node)
+                return -ENODEV;
+
+        node->error_count++;
+        node->error_total++;
+
+#ifdef CONFIG_PMS_DEBUG
+        dump_stack();
+#endif
+
+        if (60 < node->error_count) {
+                /*FIXME This should expel all tasks, and delete the node ... should be ...*/
+                PMSERR( "FIXME: A node had reached a critical error count level,"
+                       "but we don't delete it yet :(\n");
+        }
+        return node->error_count;
+}
+
+/**
+ * kcomd_node_clear_error
+ *
+ * Description:
+ *    Clear the consecutive error count, but not the total error count
+ *
+ *    Consecutive error count should be cleared every time a socket write success
+ **/
+void kcomd_node_clear_error(struct kcom_node *node)
+{
+        if (!node)
+                return;
+
+        node->error_count = 0;
+}
+
+/**
+ * __kcomd_thread_do_read
+ *
+ * Description:
+ *    this function (only called from kcomd_thread_handle_streams) is responsible
+ *    for reading packets out of the process_list
+ *
+ *    This function may schedule or hold locks
+ */
+void __kcomd_thread_do_read(struct list_head* process_list)
+{
+	struct kcom_node *node, *node_next;
+	int nb_retries = 0;
+	int err = 0;
+	/* Once we have built our read list, we must now use it */
+
+do_process_list:
+
+	list_for_each_entry_safe(node, node_next, process_list, process_list) {
+
+		err=pkt_read(node);
+
+		if (-ENOSPC == err|| -EAGAIN == err)
+			continue;
+
+		list_del(&node->process_list);
+		INIT_LIST_HEAD(&node->process_list);
+
+		/* If we got an error that far ... we must kill the offending connection */
+		if (err < 0) {
+			kcomd_node_increment_error(node);
+			kcom_node_sock_release(node);
+			PMSERR("receiving data => ignoring packet.\n");
+		}
+
+		kcomd_node_clear_error(node);
+
+	}
+	if (!list_empty(process_list)) {
+		/* Prevent infinite loop 60s */
+		if (60*HZ < ++nb_retries) {
+			PMSERR("too many retries\n");
+			goto clear_list_exit;
+		}
+		schedule_timeout(1);
+		goto do_process_list;
+	}
+
+	/* Clear the process_list and intialize each element, if we find an
+	 * offensive node in it, just delete the socket ... */
+
+clear_list_exit:
+	list_for_each_entry_safe(node, node_next, process_list, process_list) {
+		list_del( &node->process_list);
+		INIT_LIST_HEAD(&node->process_list);
+		kcomd_node_increment_error(node);
+	}
+}
+
+/**
+ * __kcomd_thread_do_write
+ *
+ * Description:
+ *    only called from kcomd_thread_handle_streams, read the list, and write
+ *    all pending packets. Handle the error count of nodes as well
+ *
+ *    This function may schedule or hold locks ...
+ **/
+
+void __kcomd_thread_do_write(struct list_head* process_list)
+{
+	struct kcom_task* task, *task_next;
+	struct kcom_pkt* pkt, *pkt_next;
+	struct kcom_node* node = NULL;
+	int err = 0;
+	int nb_retries = 0;
+	struct socket* sock = NULL;
+
+do_process_list:
+
+	list_for_each_entry_safe(task, task_next, process_list, process_list){
+
+		node = task->node;
+		if (!node)
+			goto next_task_del;
+		/* First check all socks are ok */
+		if(!node->sock)
+			__create_connection(&node->addr, node);
+
+		sock = node->sock;
+
+		if(!sock)
+			goto next_task_error;
+
+		/* Now send all packets on the egress_list */
+
+		list_for_each_entry_safe(pkt, pkt_next, &task->egress_list, list) {
+
+			err = data_send(sock, pkt);
+
+			/* If EAGAIN or ENOSPC, we will wait after trying all packets only*/
+			if (-EAGAIN==err || -ENOSPC==err)
+				goto next_task;
+
+			/* if any other error, reset the offending connection,
+			 * and get the task out of the proces_list */
+			if (err<0) {
+				kcom_node_sock_release(node);
+				goto next_task_error;
+			}
+
+			kcom_pkt_delete(pkt);
+			kcomd_node_clear_error(node);
+		}
+
+		/* If we arrive here, all packets are sent */
+
+	/* Next task removing the task from process_list */
+	next_task_del:
+		list_del(&task->process_list);
+		INIT_LIST_HEAD(&task->process_list);
+	/* Next task without removing the task from process_list */
+	next_task:
+		continue;
+
+	/* Next task incrementing the error count */
+	next_task_error:
+		list_del(&task->process_list);
+		INIT_LIST_HEAD(&task->process_list);
+		/* This function may delete the node */
+		kcomd_node_increment_error(node);
+		/* FIXME: in the future, if the node is deleted,
+		 *        we should find all occurences of the node
+		 *        in the process_list to remove relative tasks as well
+		 */
+
+	}
+
+	/* We passed once, but we may have been interrupted ... so check */
+
+	if (!list_empty(process_list)) {
+		/* Prevent infinite loop 60s */
+		if (60*HZ < ++nb_retries) {
+			PMSERR("too many retries\n");
+			goto clear_list_exit;
+		}
+		schedule_timeout(1);
+		goto do_process_list;
+	}
+
+clear_list_exit:
+	list_for_each_entry_safe(task, task_next, process_list, process_list) {
+		list_del( &task->process_list);
+		INIT_LIST_HEAD(&node->process_list);
+		kcomd_node_increment_error(task->node);
+	}
+}
+
+/**
+ * __kcomd_thread_prepare_task
+ *
+ * Description:
+ *    Move all packets from out_packs list to egress_list for sending
+ **/
+
+static void __kcomd_thread_prepare_task(struct kcom_task* task)
+{
+	struct kcom_pkt *pkt, *pkt_next;
+
+	write_lock(&task->out_packs_lock);
+	list_for_each_entry_safe(pkt, pkt_next, &task->out_packs, list){
+		list_move_tail(&pkt->list, &task->egress_list);
+	}
+	write_unlock(&task->out_packs_lock);
+}
+
+/**
+ * kcomd_thread_handle_streams:
+ *
+ * Description:
+ *    kcomd_thread_handle_streams handle the read/write on the opened sockets
+ *    it is uniquely called from kcomd_thread (and should be called without
+ *    holding any locks). This function may schedule or sleep.
+ *
+ *    This function creates two lists, one for write one for read, and use
+ *    __kcomd_thread_do_read/__kcomd_thread_do_write to handle the work.
+ **/
+
+void kcomd_thread_handle_streams(void)
+{
+
+	struct kcom_node *node;
+	struct kcom_task *task;
+	struct list_head process_list;
+	struct list_head write_process_list;
+	int loop_again;
+
+do_it_again:
+
+	loop_again = 0;
+	INIT_LIST_HEAD(&process_list);
+	INIT_LIST_HEAD(&write_process_list);
+
+	/* for each nodes { test bit, in, out and do stuff } */
+	/*
+	 * If we need to read from a socket, we might schedule or sleep ...
+	 * this we must not hold any locks, therefore we must build
+	 * a second list for reading ...
+	 */
+
+	read_lock(&kcom_nodes_lock);
+	list_for_each_entry (node, &kcom_nodes, list) {
+
+		INIT_LIST_HEAD(&node->process_list);
+
+		/* Build read list */
+		if (test_bit(node->fd, sockets_fds.res_in)) {
+			PMSDEBUG_KCOMD( 3, "KCOMD: receiving on fd %d\n", node->fd );
+			list_add_tail( &node->process_list, &process_list );
+			clear_bit(node->fd, sockets_fds.res_in);
+			loop_again = 1;
+		}
+
+		/* Build write list */
+		if (node->fd!=-1 && (node->pkt_ready || test_bit(node->fd, sockets_fds.res_out))) {
+			PMSDEBUG_KCOMD( 3, "KCOMD: sending on fd %d\n", node->fd );
+			read_lock(&node->tasks_lock);
+			list_for_each_entry(task, &node->tasks, list){
+
+				INIT_LIST_HEAD(&task->process_list);
+
+				if (!list_empty(&task->out_packs)
+				   || !list_empty(&task->egress_list)) {
+					list_add_tail(&task->process_list, &write_process_list);
+					__kcomd_thread_prepare_task(task);
+					loop_again = 1;
+				}
+			}
+			read_unlock(&node->tasks_lock);
+			node->pkt_ready = 0;
+		}
+	}
+	read_unlock(&kcom_nodes_lock);
+
+	if (!loop_again)
+		return;
+
+	/* Since the above function may schedule or hold locks, we need
+	 * separate lists */
+	if (!list_empty(&write_process_list))
+		__kcomd_thread_do_write(&write_process_list);
+
+	if (!list_empty(&process_list))
+		__kcomd_thread_do_read(&process_list);
+	/* Since some packets may generate other packets,
+	 * we must make sure that all packet list are sent */
+
+	goto do_it_again;
+}
+
+/**
+ * kcomd_thread
+ *
+ * Description:
+ *    kcomd - kernel thread that handles the communications.
+ *    Creates the memory slabs.
+ *    Once the pkt has been sent, its memory is freed.
+ *    Maps new connections to file descriptors.
+ *    Waits for incoming data, signals from processes
+ *    or any data that is ready to be sent.
+ *    Also cleans up memory and any open sockets and
+ *    file descriptors on exit.
+ **/
+static int kcomd_thread(void *nothing)
+{
+	int ret;
+	struct kcom_node *node;
+	siginfo_t info; /* matt*/
+	int sig;
+	struct timeval;
+
+	fd4=-1;
+	fd6=-1;
+	kcomd_done=0;
+	printk(KERN_INFO "HPC: PMS Communication Kernel Daemon Start\n");
+
+	kcomd_thread_initialize();
+
+        //INIT_LIST_HEAD(&kcom_nodes);
+
+	daemonize("kcomd", 0);
+	sigfillset(&current->blocked);
+
+	kcomd_task=current;
+
+retry_listen:
+	PMSDEBUG_KCOMD( 3, "KCOMD: Creating (retrying) sockets\n" );
+
+	fd4 = socket_listen_ip4(DAEMON_IP4_PORT, &lsock4);
+	fd6 = socket_listen_ip6(DAEMON_IP6_PORT, &lsock6);
+
+	if (fd4 < 0 && fd6 < 0) {
+		schedule_timeout_interruptible(HZ);
+		goto retry_listen;
+	}
+
+	alloc_fd_bitmap(max(fd4, fd6));
+
+	while (kcomd_done==0)
+	{
+		PMSDEBUG_KCOMD( 4, "KCOMD: Entering (restarting) loop\n" );
+
+ 		/* Check if we must leave ... */
+ 		if (kcomd_module_exit) {
+ 			if (0 == kcomd_leave_cluster()) {
+				PMSDEBUG_KCOMD( 4, "KCOMD: kcomd_leave_cluster\n" );
+				kcomd_done = 1;
+				continue;
+			}
+ 		}
+
+		kcomd_thread_set_fds( maxfds );
+
+		PMSDEBUG_KCOMD( 4, "KCOMD: add listening sockets to the set\n" );
+		/* add listening sockets to the set */
+		if (fd4>=0)
+			set_bit(fd4, sockets_fds.in);
+		if (fd6>=0)
+			set_bit(fd6, sockets_fds.in);
+
+
+		PMSDEBUG_KCOMD( 3, "KCOMD: Waiting for events ...\n");
+		allow_signal (SIGHUP);
+		/* Now wait for a signal or packet to arrive */
+		ret = do_select(maxfds + 1, &sockets_fds, NULL);
+		spin_lock_irq(&current->sighand->siglock);
+		if (ret == 0 && !signal_pending(current)) {
+		    PMSERR( "KCOMD: do_select returned 0 but no signal pending !\n" );
+		    spin_unlock_irq(&current->sighand->siglock);
+		    continue;
+		} else {
+		    /* SIGHUP is sent to wake up kcomd so it can take the appropriate action */
+		    sig = dequeue_signal (current, &current->blocked, &info);
+		    PMSDEBUG_KCOMD( 3, "KCOMD: got signal %d\n", sig);
+		}
+		spin_unlock_irq(&current->sighand->siglock);
+		disallow_signal (SIGHUP);
+
+		if (ret == 0) { /* -1=error; 0=signal*/
+			/* New kernel security, prohibits sharing file descriptors between kernel threads.*/
+			/* We have to allocate them here.*/
+			/* We'll do that for the signal so we don't have to do it every iteration.*/
+
+			read_lock(&kcom_nodes_lock);
+			list_for_each_entry(node, &kcom_nodes, list)
+			if (node->fd==0) { /* unmapped*/
+				PMSDEBUG_KCOMD( 3, "Found unmapped fd %d\n", node->fd );
+				node->fd = sock_map_fd(node->sock, O_NONBLOCK);
+				alloc_fd_bitmap(node->fd);
+			}
+			read_unlock(&kcom_nodes_lock);
+			continue;
+
+		} else if (ret < 0) {/* -1=error; 0=signal*/
+			PMSERR("do_select returned an error (%d). \n", ret);
+			schedule_timeout_interruptible(HZ);
+			continue;
+		}
+
+		kcomd_thread_handle_streams();
+
+		/* test listening sockets */
+		if (fd4 >= 0 && test_bit(fd4, sockets_fds.res_in)) {
+			accept_connection(lsock4);
+		}
+
+		if (fd6 >= 0 && test_bit(fd6, sockets_fds.res_in)) {
+			accept_connection(lsock6);
+		}
+	}
+
+/* DONE*/
+ 	printk(KERN_INFO "[PMS] kcomd: kernel communication daemon cleaning up.\n");
+
+	if (fd4>=0)
+		sys_close(fd4);
+
+	if (fd6>=0)
+		sys_close(fd6);
+
+	kcomd_thread_free_ressources();
+
+	kcomd_task=NULL;
+	printk(KERN_INFO "kcomd: exit\n");
+	return 0;
+}
+
+
+/**
+ * kcomd_thread_free_ressources
+ *
+ * Description:
+ * Free the kcomd_thread ressources
+ */
+static void kcomd_thread_free_ressources(void)
+{
+	struct kcom_task *task, *task_next;
+	struct kcom_node *node, *node_next;
+
+	write_lock(&kcom_nodes_lock);
+	list_for_each_entry_safe(node, node_next, &kcom_nodes, list) {
+
+		write_lock(&node->tasks_lock);
+		list_for_each_entry_safe(task, task_next, &node->tasks, list) {
+
+ 			write_lock(&task->in_packs_lock);
+
+ 			while(!list_empty(&task->in_packs)){
+ 				kcom_pkt_delete(list_entry(task->in_packs.next
+ 							  , struct kcom_pkt, list));
+ 			}
+
+ 			write_unlock(&task->in_packs_lock);
+
+ 			write_lock(&task->out_packs_lock);
+ 			while(!list_empty(&task->out_packs)){
+ 				kcom_pkt_delete(list_entry(task->out_packs.next
+ 							  , struct kcom_pkt, list));
+			}
+ 			write_unlock(&task->out_packs_lock);
+
+		}
+		write_unlock(&node->tasks_lock);
+
+		sock_release(node->sock);
+		sys_close(node->fd);
+		list_del(&node->list);
+		kmem_cache_free(kcom_node_cachep, node);
+	}
+	write_unlock(&kcom_nodes_lock);
+
+	/* spin_unlock(&kcom_nodes_lock);*/
+	kfree(sockets_fds_bitmap);
+
+	kmem_cache_destroy(kcom_pkt_cachep);
+	kmem_cache_destroy(kcom_task_cachep);
+	kmem_cache_destroy(kcom_node_cachep);
+
+}
+
+static int __init kcomd_init(void)
+{
+	long ret;
+
+	ret = kernel_thread(kcomd_thread, NULL, CLONE_FS | CLONE_FILES);
+	return ret;
+}
+
+
+/*
+ * Set the exit condition and signal kcomd
+ * kcomd cleans up after itself
+ */
+static void __exit kcomd_exit(void)
+{
+	int retries = 0;
+
+	if (!kcomd_task) {
+		PMSERR("Unable to find the kcomd_thread task !!\n");
+		return;
+	}
+
+	PMSDEBUG_KCOMD(2, "asking kcomd to exit gracefuly\n");
+
+	kcomd_module_exit = 1;
+	send_sig(SIGHUP, kcomd_task, 0);
+
+wait_for_kcomd:
+	schedule_timeout(HZ);
+	if (kcomd_done == 0) {
+		if (likely(++retries < 120))
+			goto wait_for_kcomd;
+		goto retire_kcomd;
+	}
+
+	PMSDEBUG_KCOMD(2, "module unloading ... \n");
+	return;
+
+retire_kcomd:
+	/* g_remlin SIGKILL an option ??? */
+	PMSBUG("kcomd did not gracefully exit, forcing exit !\n");
+	kcomd_done = 1;
+	send_sig(SIGHUP, kcomd_task, 0);
+	schedule_timeout(HZ);
+}
+
+module_init(kcomd_init);
+module_exit(kcomd_exit);
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Vincent Hanquez");
diff --exclude=.git -Nru linux-2.6.28.7/hpc/Kconfig linux-2.6.28.7-pms/hpc/Kconfig
--- linux-2.6.28.7/hpc/Kconfig	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/Kconfig	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,62 @@
+#
+# HPC configuration 
+#
+
+menu "HPC options"
+
+config KCOMD
+	tristate "PMS Communication daemon"
+	default y
+	help
+          Say Y will add support for the communication daemon
+
+config PMS
+	bool "Enable PMS clustering"
+	depends on KCOMD
+	default y
+	help
+	  Say Y to support process migration within a cluster
+
+config PMS_VERBOSE
+	bool "Enable PMS to be more verbose"
+	depends on PMS
+	default n
+
+config PMS_MIGRATION_VERBOSE
+	bool "Add some message when migrating"
+	depends on PMS_VERBOSE
+	default n
+	help
+	  Say Y will throw message about migration into syslog
+
+config PMS_DEBUG
+	bool "Enable PMS debug"
+	depends on PMS
+	default n
+
+config PMS_MIGRATION_DEBUG
+	bool "Add lots of message and print step when migrating"
+	depends on PMS_DEBUG
+	default n
+	help
+	  Say Y will throw lot of debug message about migration into syslog
+
+config PMS_DEBUG_FS
+	tristate "Add debug files on debugfs"
+	depends on PMS_DEBUG 
+	select SYSFS
+	select DEBUG_FS
+	default n
+	help
+	  Export some variables through an pms directory in debugfs for debugging
+	  (Selecting this also enables the sysfs virtual filesystem dependancy).
+
+config PMS_CTRL_FS
+	tristate "control filesystem for PMS"
+	depends on  PMS
+	default n
+	help
+	  Add a pmsctrlfs to control PMS features and have statistics
+	  about tasks.
+
+endmenu
diff --exclude=.git -Nru linux-2.6.28.7/hpc/kernel.c linux-2.6.28.7-pms/hpc/kernel.c
--- linux-2.6.28.7/hpc/kernel.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/kernel.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,206 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/smp_lock.h>
+#include <linux/mm.h>
+#include <asm/mmu_context.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/deputy.h>
+#include <hpc/remote.h>
+
+/**
+ * obtain_mm - obtain an mm context
+ *
+ * Description:
+ * Get an mm_struct and initialize it. Associate
+ * with our process.
+ **/
+int obtain_mm(struct task_struct *p)
+{
+	struct mm_struct *mm, *active_mm;
+	int err;
+
+	if (p->mm && !task_test_dflags(p, DDEPUTY))
+		panic("pms: task->mm already allocated");
+	/*
+	if (p->mm && task_test_dflags(p, DDEPUTY))
+		exit_mm(p);
+	*/
+	mm = mm_alloc();
+	if (!mm)
+		return -ENOMEM;
+	err = init_new_context(p, mm);
+	if (err) {
+		task_unlock(p);
+		mmdrop(mm);
+		return err;
+	}
+
+	spin_lock(&mmlist_lock);
+	list_add(&mm->mmlist, &init_mm.mmlist);
+	spin_unlock(&mmlist_lock);
+
+	task_lock(p);
+	active_mm = p->active_mm;
+	p->mm = mm;
+	p->active_mm = mm;
+	task_unlock(p);
+
+	activate_mm(active_mm, mm);
+	mmdrop(active_mm);
+	return 0;
+}
+
+/******************* All functions below are kernel called ********************/
+
+void pms_unstay_mm(struct mm_struct *mm)
+{
+	struct task_struct *p;
+
+	if (atomic_read(&mm->mm_realusers) == 1 && mm == current->mm)
+	{
+		task_set_dreqs(current, DREQ_CHECKSTAY);
+		return;
+	}
+	read_lock(&tasklist_lock);
+	for_each_process(p)
+		if (p->mm == mm)
+			task_set_dreqs(p, DREQ_CHECKSTAY);
+	read_unlock(&tasklist_lock);
+}
+
+int pms_pre_clone(int flags)
+{
+	struct task_struct *p = current;
+	struct mm_struct *mm = p->mm;
+
+	if (!(flags & CLONE_VM))
+		return 0;
+	if (mm)
+		atomic_inc(&mm->mm_realusers);
+
+	task_set_stay(p, DSTAY_CLONE);
+	return 0;
+}
+
+void pms_post_clone(int flags)
+{
+	struct task_struct *p = current;
+	struct mm_struct *mm = p->mm;
+
+	if (!(flags & CLONE_VM))
+		return;
+	if (mm && atomic_read(&mm->mm_realusers) == 1)
+		task_clear_stay(p, DSTAY_CLONE);
+}
+
+/**
+ * task_maps_inode - Check if a task @p maps the inode @ip
+ **/
+inline static int task_maps_inode(struct task_struct *p, struct inode *ip)
+{
+	return 0;
+}
+
+void pms_no_longer_monkey(struct inode *ip)
+{
+	struct task_struct *p;
+
+	read_lock(&tasklist_lock);
+	for_each_process(p)
+		if (task_maps_inode(p, ip))
+			task_set_dreqs(p, DREQ_CHECKSTAY);
+	read_unlock(&tasklist_lock);
+}
+
+int pms_stay_me_and_my_clones(int reasons)
+{
+	struct task_struct *p, *me = current;
+	struct mm_struct *mm = me->mm;
+
+	task_lock(me);
+	task_set_stay(me, reasons);
+	task_unlock(me);
+	if (atomic_read(&mm->mm_realusers) > 1) {
+		read_lock(&tasklist_lock);
+		for_each_process(p) {
+			if (p->mm == mm && p != me) {
+				task_lock(p);
+				task_set_stay(p, reasons);
+				task_unlock(p);
+			}
+		}
+		read_unlock(&tasklist_lock);
+	}
+	return 0;
+}
+
+/**
+ * pms_pre_usermode - process some pre usermode events for current
+ **/
+asmlinkage int pms_pre_usermode(struct pt_regs regs)
+{
+	unsigned long flags;
+	int ret= -EFAULT;
+	struct thread_info *ti = current_thread_info();
+
+	/* clear the flag that sent us here */
+	clear_ti_thread_flag(ti, TIF_PMS_PENDING );
+
+	local_save_flags(flags);
+	local_irq_enable();
+
+	PMS_VERBOSE_MIG("pid[%d] pms_pre_usermode activated\n", current->pid);
+	/* most likely a request to migrate somewhere */
+	if (likely(task_test_dreqs(current, ~0))) {
+		PMS_VERBOSE_MIG("pid[%d] pms_pre_usermode task_do_request activated\n", current->pid);
+		task_do_request();
+	}
+	/* we will now most probably qualify for one of below */
+	if (likely(task_test_dflags(current, DMIGRATED))) {
+		PMS_VERBOSE_MIG("pid[%d] pms_pre_usermode main_loop activated\n", current->pid);
+		if (task_test_dflags(current, DREMOTE)) {
+			remote_main_loop();
+		}
+		if (task_test_dflags(current, DDEPUTY)) {
+			deputy_main_loop();
+		}
+	}
+	local_irq_restore(flags);
+	/* If we are one of a task pair split-apart, our life is over, mourn me :>( */
+	if (task_test_dflags(current, DSPLIT))
+		do_exit(current->exit_code);
+
+	flush_signals(current);
+	/* Return, to continue execution as a normal local process */
+	return ret;
+}
+
+/**
+ * pms_init - Init all global variables and subsystem at boot
+ **/
+static int __init pms_init(void)
+{
+	/* kick off the kernel threads: */
+	return 0;
+}
+
+subsys_initcall(pms_init);
diff --exclude=.git -Nru linux-2.6.28.7/hpc/Makefile linux-2.6.28.7-pms/hpc/Makefile
--- linux-2.6.28.7/hpc/Makefile	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/Makefile	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,18 @@
+# communication part
+obj-$(CONFIG_KCOMD)     	+= kcomd.o
+
+# core part
+obj-$(CONFIG_PMS)		+= kernel.o task.o kcom.o ptrace.o
+obj-$(CONFIG_PMS)		+= remote.o deputy.o copyuser.o files.o syscalls.o
+obj-$(CONFIG_PMS)		+= migrecv.o migsend.o migctrl.o
+obj-$(CONFIG_PMS)		+= arch-$(ARCH).o
+
+# legacy
+obj-$(CONFIG_PMS)		+= proc.o
+
+# new ctrl fs
+obj-$(CONFIG_PMS_CTRL_FS)	+= pmsctrlfs.o
+
+# debug
+obj-$(CONFIG_PMS_DEBUG)		+= debug.o debug-$(ARCH).o
+obj-$(CONFIG_PMS_DEBUG_FS)	+= pmsdebugfs.o
diff --exclude=.git -Nru linux-2.6.28.7/hpc/migctrl.c linux-2.6.28.7-pms/hpc/migctrl.c
--- linux-2.6.28.7/hpc/migctrl.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/migctrl.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,241 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ * - kcomd thread by Matt Dew and Florian Delizy
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/errno.h>
+#include <linux/mm.h>
+#include <linux/mman.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/mig.h>
+#include <hpc/deputy.h>
+#include <hpc/remote.h>
+
+/**
+ * task_remote_expel - call from REMOTE to send a task to DEPUTY
+ * @p:		task which will come back
+ **/
+inline static int task_remote_expel(struct task_struct *p)
+{
+	int err;
+
+	PMSDEBUG_MIG(3, "pid %d task expeled !!!\n", p->pid);
+
+	PMS_VERBOSE_MIG("pid[%d] task_remote_expel Remote sending process home\n", p->pid);
+	err = mig_do_send(p);
+	if (err<0) {
+		goto failed;
+	}
+
+	remote_unremotise(p);
+	PMS_VERBOSE_MIG("pid[%d] task_remote_expel Remote sent process home\n", p->pid);
+	/* g_remlin, not the place */
+	do_exit(0);
+	/*NOTREACHED */
+
+failed:
+	PMSERR("pid [%d] mig_do_send failed (%d)\n", p->pid, err);
+	return err;
+}
+
+/**
+ * task_local_send - Send a local task to remote
+ * @p:		task to send
+ **/
+inline static int task_local_send(struct task_struct *p)
+{
+	int err = 0;
+	PMSDEBUG_MIG(3, "pid %d Sending task!\n", p->pid);
+
+	PMS_VERBOSE_MIG("pid[%d] task_local_send Deputy sending process\n", p->pid);
+	task_set_dflags(p, DDEPUTY);
+	err=mig_do_send(p);
+	if (err < 0) {
+		goto failed;
+	}
+
+	PMS_VERBOSE_MIG("pid[%d] task_local_send Deputy sent process\n", p->pid);
+	deputy_startup(p);
+	return 0;
+
+failed:
+	PMSERR("failed\n");
+	task_clear_dflags(p, DDEPUTY);
+	return err;
+}
+
+/**
+ * task_local_bring - Receive task back in the deputy stub
+ * @p:		deputy task to receive
+ **/
+inline static int task_local_bring(struct task_struct *p)
+{
+	int error;
+	PMSDEBUG_MIG(3, "pid %d\n", p->pid);
+
+	PMS_VERBOSE_MIG("pid[%d] task_local_bring Deputy receiving returning process\n", p->pid);
+	if (obtain_mm(p)) {
+		printk(KERN_ERR "unable to obtain mm\n");
+		goto failed;
+	}
+
+	/* receive the process back */
+	error = mig_do_receive(p);
+	if (error)
+		goto failed;
+
+	deputy_undeputise(p);
+	PMS_VERBOSE_MIG("pid[%d] task_local_bring Deputy received returning process\n", p->pid);
+
+	set_current_state(TASK_RUNNING);
+	schedule();
+	return 0;
+failed:
+	PMSERR("failed\n");
+	return -1;
+}
+
+/**
+ * task_move_remote2remote - migrate a task from remote to remote
+ * @p:		task to send
+ * @whereto:	whereto
+ * @reason:	reason to send (if any)
+ **/
+#if 0
+static int task_move_remote2remote(struct task_struct *p, struct sockaddr * whereto,
+								int reason)
+{
+	PMSERR("not implemented.\n");
+	return 0;
+}
+#endif
+
+/**
+ * __task_move_to_node - move a task 
+ * @p:		task to send
+ **/
+static int __task_move_to_node(struct task_struct *p)
+{
+int err;
+
+	PMSDEBUG_MIG(2, "pid %d\n", p->pid);
+
+	/*
+	 * Ok, if DREMOTE flag set, then this is a remote process
+	 * if DDEPUTY is set, then this is a deputy
+	 * if neither is set, then this is a home process going out.
+	 * FIXME:  remote to remote?
+	 */
+
+	task_set_dflags(p, DPASSING);
+
+	if (task_test_dflags(p, DREMOTE))
+		err = task_remote_expel(p);
+	else if (task_test_dflags(p, DDEPUTY)) 
+		/* g_remlin: if s_addr == 0 */
+		err = task_local_bring(p);
+		/* else remote2remote */
+	else
+		err = task_local_send(p);
+
+	task_clear_dflags(p, DPASSING);
+
+	return err;
+}
+
+/**
+ * mig_task_request - move a task
+ **/
+int mig_task_request(struct task_struct *p)
+{
+        PMSDEBUG_MIG(3, "pid %d changing nodes\n", p->pid);
+
+/*
+ * FIXME:
+ *  1) home -> remote - fresh migration; *
+ *  2) home -> remote - redundant migration; *
+ *  3) home -> 'home';
+ *  4) home -> new remote;
+ *  5) remote -> 'home' - fresh migration; *
+ *  6) remote -> home ip address;
+ *  7) remote -> remote ip address;
+ *  8) remote -> new remote - initiated from remote;
+ *  9) remote -> new remote - initiated from home;
+ *  10) remote -> home - bring home initiated from home;
+ */
+
+        task_clear_dreqs(p, DREQ_MOVE);
+
+	if (task_test_stay(p, DSTAY)) {
+		PMSDEBUG_MIG(2, "Task can't move. check stay reason\n");
+		return -1;
+	}
+	__task_move_to_node(p);
+	return 0;
+}
+
+#if 0
+/**
+ * task_go_home - Migrate task to home
+ **/
+int task_go_home(struct task_struct *p)
+{
+	PMSDEBUG_MIG(3, "pid %d Moving task home!\n", p->pid);
+
+	PMS_VERBOSE_MIG("pid[%d] task_go_home Remote sending process home\n", p->pid);
+
+	if (!task_test_dflags(p, DMIGRATED)) {
+		printk(KERN_INFO "PMS: task %d at home: ignoring request.\n",
+				p->pid);
+		return -1;
+	}
+
+	__task_move_to_node(p);
+
+	if (task_test_dflags(p, DMIGRATED))
+		printk(KERN_ERR "PMS: task %d fail to go back home\n", p->pid);
+
+	PMS_VERBOSE_MIG("pid[%d] task_go_home Remote sent process home\n", p->pid);
+	return 0;
+}
+#endif
+
+/**
+ * task_go_home_for_reason - Migrate back a task for a reason
+ **/
+int task_go_home_for_reason(struct task_struct *p, int reason)
+{
+	int ret;
+	PMSDEBUG_MIG(3, "pid %d task must go home :( for reason %d!\n", p->pid, reason);
+
+	if (task_test_stay(p, reason) && task_test_dflags(p, DMIGRATED))
+		printk(KERN_ERR "PMS: task should had migrated back earlier\n");
+	task_set_stay(p, reason);
+
+	if (!task_test_dflags(p, DMIGRATED))
+		return 0;
+
+	ret = __task_move_to_node(p);
+	if (!ret)
+		task_clear_stay(p, reason);
+	return ret;
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/migrecv.c linux-2.6.28.7-pms/hpc/migrecv.c
--- linux-2.6.28.7/hpc/migrecv.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/migrecv.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,568 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ * Kcomd protocol by Matt Dew and Florian Delizy
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/errno.h>
+#include <linux/mm.h>
+#include <linux/rmap.h>
+#include <linux/mman.h>
+#include <linux/stddef.h>
+#include <linux/highmem.h>
+#include <linux/personality.h>
+#include <linux/syscalls.h>
+#include <linux/swap.h>
+#include <linux/inet.h>  /* in_aton*/
+
+#include <asm/mmu_context.h>
+#include <asm/tlbflush.h>
+#include <asm/page.h>
+
+#include <hpc/prototype.h>
+#include <hpc/protocol.h>
+#include <hpc/debug.h>
+#include <hpc/arch.h>
+#include <hpc/mig.h>
+#include <hpc/kcom.h>
+#include <linux/swap.h>
+
+
+int mig_do_l1_error(struct kcom_node* node __attribute__((unused))
+		   ,const struct kcom_pkt* const pkt __attribute__((unused)))
+{
+	PMSERR("Invalid L1 packet!\n");
+	return -EFAULT;
+}
+
+int mig_do_come_home(struct kcom_node *node, const struct kcom_pkt * const pkt)
+{
+	struct kcom_task *tsk;
+	PMSDEBUG_PROTOCOL(2, "KCOMD: it's a MIG_COME_HOME packet ... \n");
+
+	tsk = __find_task_for_packet(pkt, node, NULL);
+	if (!tsk) {
+		PMSERR("Unable to find task %d\n", pkt->rpid);
+		return -ENODEV;
+	}
+
+	if (!task_test_dflags(tsk->task, DREMOTE)) {
+		printk(KERN_ERR "[PMS] Can not bring task [%d] home, it's not a remote process\n", tsk->rpid);
+		return -EPERM;
+	}
+
+	task_register_migration(tsk->task);
+	return 0;
+}
+
+/**
+ * mig_do_end_of_process
+ *
+ * Description:
+ * The deputy/remote process we are linked to has terminated unexpectedly, tidy up and exit.
+ * Delete the received packet and all associated task resources WITHOUT flushing the send
+ * packet queue as there is no longer anything the other end to receive them.
+ **/
+int mig_do_end_of_process(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+	/* should always == current */
+	struct task_struct *p = tsk->task;
+	struct kcom_pkt *hack = (struct kcom_pkt *) pkt;
+	long val = *(long*)hack->data;
+
+	kcom_pkt_delete(hack);
+	task_set_dflags(p, DSPLIT);
+#if 0
+	/* g_remlin: ? */
+	if (task_test_dflags(p, DDEPUTY)) {
+		/* deputy_undeputise(tsk->task); without sending */
+		task_set_dflags(p, DINCOMING);  /* not strictly true, but we must lockout proc */
+		kcom_task_delete(p->pid);
+		task_heldfiles_clear(p);
+		memset(p->pms.whereto, 0, sizeof(struct sockaddr));
+		task_clear_dflags(p, DDEPUTY|DINCOMING);
+	}
+	if (task_test_dflags(p, DREMOTE)) {
+		/* remote_unremotise(tsk->task); without sending */
+		task_set_dflags(p, DPASSING);   /* not strictly true, but we must lockout proc */
+		kcom_task_delete(p->pid);
+		task_heldfiles_clear(p);
+		memset(p->pms.whereto, 0, sizeof(struct sockaddr));
+		task_clear_dflags(p, DREMOTE|DPASSING);
+	}
+#endif
+	do_exit(val);
+	/*NOTREACHED*/
+}
+
+/**
+ * mig_do_receive_home
+ *
+ * Description:
+ *    Called by kcomd when it receives a MIG_GO_HOME pkt.
+ *    Task_register_migration is called to inform the process that the
+ *    remote process is coming home.
+ **/
+int mig_do_receive_home(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+	PMSDEBUG_MIG(2, "receiving program home (home sweet home) ^^\n");
+
+       if (!task_test_dflags(tsk->task, DDEPUTY)) {
+               printk(KERN_ERR "[PMS] Can not receive task [%d] home, not a deputy process\n", tsk->hpid);
+               return -EPERM;
+       }
+
+	task_register_migration(tsk->task);
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(mig_do_receive_home);
+
+/**
+ * mig_do_receive_init
+ *
+ * Description:
+ *    Called by kcomd when it receives a MIG_INIT pkt.
+ *    Creates a new process and then answer the deputy node
+ **/
+int mig_do_receive_init(struct kcom_node *node, const struct kcom_pkt * const pkt)
+{
+	volatile pid_t rpid = 0;
+	struct kcom_task *tsk;
+
+	PMSDEBUG_MIG(3, "receiving init packet\n");
+
+	user_thread(mig_handle_migration, &rpid, 0);
+
+	while (!rpid)
+		schedule_timeout_interruptible(HZ/10);
+
+	if (rpid < 0)
+		return rpid;
+
+	tsk=kcom_task_create(node, rpid);
+	if (!tsk) {
+	    PMSERR("ERROR: Unable to create task.\n");
+	    return -ENOMEM;
+	}
+
+	tsk->hpid = pkt->hpid;
+	tsk->rpid = rpid;
+
+	kcom_send_resp(tsk->task, sizeof(pid_t), (char *)&rpid, pkt);
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(mig_do_receive_init);
+
+
+/*****************************************************************************/
+
+/**
+ * mig_do_receive_mm
+ *
+ * Description:
+ *    Receives the process mmap info.
+ **/
+int mig_do_receive_mm(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+	struct task_struct *p = tsk->task;
+	PMSDEBUG_MIG(3, "pid %d receiving mm struct packet\n", p->pid);
+
+	down_write(&p->mm->mmap_sem);
+	memcpy(&p->mm->start_code, pkt->data, pkt->data_len);
+	p->mm->exec_vm=0; /* MSD debug*/
+	up_write(&p->mm->mmap_sem);
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(mig_do_receive_mm);
+
+/**
+ * mig_do_receive_vma
+ *
+ * Description:
+ *    Receives the process vma info.
+ **/
+int mig_do_receive_vma(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+	struct task_struct *p = tsk->task;
+	struct pmsp_mig_vma *a;
+	unsigned long result, prot, flags;
+	struct file *file = NULL;
+
+	int ret = 0;
+
+ 	PMSDEBUG_MIG(3, "pid %d receiving vmas struct packet\n", p->pid);
+
+	a = (struct pmsp_mig_vma *)pkt->data;
+
+#ifdef CONFIG_PMS_DEBUG
+	pms_dump_dflags(p);
+#endif
+
+	if (a->vm_file) {
+		if(task_test_dflags(p, DREMOTE)) {
+			file = task_rfiles_get(p, a->vm_file, -1, a->i_size);
+		}
+		else {
+			file = a->vm_file;
+		}
+	}
+
+	if (file && (!file->f_op || !file->f_op->mmap))
+		file = NULL;
+
+	/* unconvert prot+flags: */
+	flags = MAP_FIXED | MAP_PRIVATE;
+	if (a->vm_flags & VM_GROWSDOWN)
+		flags |= MAP_GROWSDOWN;
+	if (a->vm_flags & VM_DENYWRITE)
+		flags |= MAP_DENYWRITE;
+	if (a->vm_flags & VM_EXECUTABLE)
+		flags |= MAP_EXECUTABLE;
+
+	/* copy VM_(READ|WRITE|EXEC) bits to prot */
+	prot = (a->vm_flags & (VM_READ | VM_WRITE | VM_EXEC));
+
+	/* mmap stuff */
+	down_write(&p->mm->mmap_sem);
+	result = do_mmap_pgoff(file, a->vm_start, a->vm_size, prot, flags, a->vm_pgoff);
+	up_write(&p->mm->mmap_sem);
+
+	if (IS_ERR((const void *) result)) {
+		ret = PTR_ERR((const void *) result);
+		PMSERR("Can't mmap on process [%u]\n", p->pid);
+		return ret;
+	}
+
+	if (a->vm_flags & VM_READHINTMASK) {
+
+		int behavior = (a->vm_flags & VM_SEQ_READ)
+			? MADV_RANDOM
+			: MADV_SEQUENTIAL;
+
+		ret=sys_madvise(a->vm_start, a->vm_size, behavior);
+		if (ret < 0)
+			PMSERR("sys_madvise returned an error\n");
+	}
+
+	return ret;
+
+}
+EXPORT_SYMBOL_GPL(mig_do_receive_vma);
+
+/* g_remlin: do_anonymous_page */
+void install_arg_page(struct vm_area_struct *vma,
+                        struct page *page, unsigned long address)
+{
+        struct mm_struct *mm = vma->vm_mm;
+        pte_t * pte;
+        spinlock_t *ptl;
+
+        if (unlikely(anon_vma_prepare(vma)))
+                goto out;
+
+        flush_dcache_page(page);
+        pte = get_locked_pte(mm, address, &ptl);
+        if (!pte)
+                goto out;
+        if (!pte_none(*pte)) {
+                pte_unmap_unlock(pte, ptl);
+                goto out;
+        }
+        inc_mm_counter(mm, anon_rss);
+        lru_cache_add_active_anon(page);
+        set_pte_at(mm, address, pte, pte_mkdirty(pte_mkwrite(mk_pte(page, vma->vm_page_prot))));
+        page_add_new_anon_rmap(page, vma, address);
+        pte_unmap_unlock(pte, ptl);
+
+        /* no need for flush_tlb */
+        return;
+out:
+        __free_page(page);
+        force_sig(SIGKILL, current);
+}
+
+
+/**
+ * mig_do_receive_page
+ *
+ * Description:
+ *    Receives one process memory page.
+ **/
+int mig_do_receive_page(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+	struct task_struct *p = tsk->task;
+	struct mm_struct *mm = p->mm;
+	struct vm_area_struct *vma;
+	struct page *recv_page = NULL;
+	unsigned long addr = 0xdeadc0de;
+	void *kmpage;
+
+ 	PMSDEBUG_MIG(3, "pid %d receiving pages struct packet\n", p->pid);
+
+	addr=pkt->addr;
+	vma = find_vma(mm, addr);
+	if (!vma) {
+		PMSERR("vma not found (addr: %p)\n", (void *) addr);
+		return -ENODEV;
+	}
+
+	recv_page=__alloc_zeroed_user_highpage(0, vma, addr);
+	kmpage=kmap(recv_page);
+	memcpy(kmpage, pkt->data, pkt->data_len);
+	kunmap(recv_page);
+
+	/* add the page at correct place */
+	down_write(&mm->mmap_sem);
+	install_arg_page(vma, recv_page, pkt->addr);
+	up_write(&mm->mmap_sem);
+
+	return 0;
+}
+
+/**
+ * mig_do_receive_fp
+ * @p:		task
+ * @pkt: ->data: floating point registers.
+ *
+ * Description:
+ *    Receive floating points registers
+ **/
+int mig_do_receive_fp(struct kcom_task *tsk, const struct kcom_pkt *const pkt)
+{
+	struct task_struct *p = tsk->task;
+	struct pmsp_mig_fp *fp;
+
+ 	PMSDEBUG_MIG(3, "pid %d receiving fp struct packet\n", p->pid);
+
+	fp = (struct pmsp_mig_fp *)pkt->data;
+
+	PMSDEBUG_MIG(2, "MIG_FP\n");
+	set_used_math();
+
+	arch_mig_receive_fp(p, fp);
+
+	return 0;
+}
+
+/**
+ * mig_do_receive_misc
+ **/
+/**
+ * mig_do_receive_proc_context
+ * @p:		task
+ * @pkt:		->data: normal registers, limits.
+ *
+ * Description:
+ *    Receive normal registers, limits
+ **/
+int mig_do_receive_proc_context(struct kcom_task *tsk, const struct kcom_pkt * const pkt)
+{
+	struct pmsp_mig_task *m;
+	struct task_struct *p = tsk->task;
+
+ 	PMSDEBUG_MIG(3, "pid %d receiving proc_context\n", p->pid);
+
+	m=(struct pmsp_mig_task *)pkt->data;
+
+	/* arch specific proc receive context */
+	arch_mig_receive_proc_context(p, m);
+
+	/* copy id */
+	p->pms.pid = m->pid;
+	p->pms.tgid = m->tgid;
+
+	/* copy credentials */
+ 	p->uid = m->uid;
+ 	p->euid = m->euid;
+ 	p->suid = m->suid;
+ 	p->fsuid = m->fsuid;
+ 	p->gid = m->gid;
+ 	p->egid = m->egid;
+ 	p->sgid = m->sgid;
+ 	p->fsgid = m->fsgid;
+
+ 	p->ptrace = m->ptrace;
+
+	/* signals stuffs */
+	p->blocked = m->blocked;
+	p->real_blocked = m->real_blocked;
+	p->sas_ss_sp = m->sas_ss_sp;
+	p->sas_ss_size = m->sas_ss_size;
+	memcpy(p->sighand->action, m->sighand, sizeof(struct k_sigaction)
+								* _NSIG);
+
+  	/* FIXME we don't trust the other node anyway so copy rlimit from node[nr] */
+
+  	memcpy(p->comm, m->comm, sizeof(m->comm));
+ 	p->personality = m->personality;
+	arch_pick_mmap_layout(p->mm);
+
+	task_clear_dflags(p, DINCOMING);
+	flush_tlb_mm(p->mm); /* for all the new pages */
+
+	set_current_state(TASK_RUNNING);
+
+	kcom_send_ack(p, pkt);
+	return 0;
+}
+
+/**
+ * mig_do_receive
+ * @p:		task
+ *
+ * Description:
+ *    Main loop to receive all process stuff (mm, pages, fpr, ..)
+ **/
+int mig_do_receive(struct task_struct *p)
+{
+	struct kcom_task *mytsk=NULL;
+	struct kcom_pkt *pkt;
+	int ret = 0;
+	int retries = 0;
+
+	/* Sanity Check */
+	if (!p) {
+	    PMSERR("Null task !\n");
+	    return -ENODEV;
+	}
+
+wait_for_task:
+
+	mytsk = kcom_task_find(p->pid);
+	if (!mytsk) {
+		if (60*10*HZ<retries++) {			/* g_remlin - these timeout's don't correlate */
+			PMSERR("task not created... \n");
+			return -ETIMEDOUT;
+		}
+
+		if (0 == retries % HZ) {
+			printk(KERN_WARNING"[PMS] waiting for kcomd_thread task creation... %ds\n", retries/HZ);
+		}
+		schedule_timeout_interruptible(HZ/10);
+		goto wait_for_task;
+	}
+
+
+	task_set_dflags(p, DINCOMING);
+	PMSDEBUG_MIG(2, "pid[%d] receiving process ??\n", p->pid);
+
+	/* Initialize remote proc's whereto*/
+	if (task_test_dflags(p, DREMOTE)) {
+		memcpy(p->pms.whereto, &mytsk->node->addr, sizeof(mytsk->node->addr));
+	}
+
+	PMSDEBUG_MIG(3, "pid[%d] kcomd did his work, all fine !\n", p->pid);
+
+	/* Handle the migration protocol */
+
+handle_migration:
+
+	set_current_state(TASK_INTERRUPTIBLE);
+
+	/* Receiving packet */
+	//ret = __kcom_wait_for_next_msg(mytsk, &pkt);
+	ret = __kcom_wait_for_next_msg(mytsk, 0, &pkt);
+	if (ret < 0) {
+		printk(KERN_ERR "pid[%d] Error %d while waiting for migration packet\n", p->pid, ret);
+		return ret;
+	}
+	/* Executing packet */
+	if (__is_kcom_l2_pkt_type(pkt->type)) {
+		ret = kcomd_do_l2_state_machine(mytsk, pkt);
+	}
+	else
+		printk(KERN_ERR"[PMS] received unexpected message ... dropping\n");
+
+	/* Deleting packet */
+	kcom_pkt_delete(pkt);
+
+	/* Checking error */
+	if (ret<0) {
+		printk(KERN_ERR"[PMS] pid[%d] can not execute pkt request ... aborting\n", p->pid);
+		return ret;
+	}
+
+	/* Looping till the process has migrated */
+	if(task_test_dflags(p, DINCOMING))
+		goto handle_migration;
+
+ 	PMSDEBUG_MIG(3, "Process[%d] received\n", p->pid);
+	return 0;
+}
+
+/**
+ * mig_handle_migration
+ * @*pid:		address to pid used in mig_do_receive_init.
+ *             mig_do_receive_init waits until pid!=0, before setting
+ *             up task and sending ack back to home node.
+ *
+ * Description:
+ *    This is the newly created process.
+ **/
+//KCOMD_NSTATIC NORET_TYPE void mig_handle_migration(void *param)
+KCOMD_NSTATIC int mig_handle_migration(void *param)
+{
+	pid_t *pid = (pid_t *) param;
+	struct task_struct *p = current;
+	int err;
+
+	/* 
+	 * reparent before anything real happens to 
+	 * the process so nothing gets re-initialized.
+	 */
+	reparent_to_kthreadd();
+
+	err = obtain_mm(p);
+	if (err)
+		goto fail;
+
+	task_set_dflags(p, DREMOTE);
+
+	PMS_VERBOSE_MIG("pid[%d] Remote receiving new process\n", p->pid);
+
+	/* indicate to mig_do_receive_init() that it can proceed */
+	*pid = p->pid;
+
+	err = mig_do_receive(p);
+	if (err)
+		goto fail;
+
+	PMS_VERBOSE_MIG("pid[%d] Remote starting process\n", p->pid);
+
+	arch_kickstart(p);
+	/*NOTREACHED*/
+
+	PMSERR("pid[%d], waking up. YOU SHOULD NOT SEE THIS!!!!!\n", p->pid);
+	// loop just in case someone else tries to revive us...
+	while (1) {
+		// go comatose 
+		set_current_state(TASK_UNINTERRUPTIBLE);
+		schedule();
+	}
+
+fail:
+	printk(KERN_ERR "pid[%d] mig_handle_migration failed with %d\n", p->pid, err);
+	do_exit(-1);
+	/*NOTREACHED*/
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/migsend.c linux-2.6.28.7-pms/hpc/migsend.c
--- linux-2.6.28.7/hpc/migsend.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/migsend.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,272 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ * - kcomd thread by Matt Dew and Florian Delizy
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/errno.h>
+#include <linux/mm.h>
+#include <linux/mman.h>
+#include <linux/stddef.h>
+#include <linux/highmem.h>
+#include <linux/personality.h>
+#include <linux/in.h>
+#include <asm/tlbflush.h>
+#include <asm/mmu_context.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/arch.h>
+
+/**
+ * mig_send_mm
+ *
+ * Description:
+ *    Sends the process memory map information to the other node.
+ *    Wait for an acknowledgement
+ **/
+inline static int mig_send_mm(struct task_struct *p)
+{
+	struct sockaddr_in *dest_ptr=(void *)p->pms.whereto;
+
+	PMSDEBUG_MIG(3, "sending process %d\n", p->pid);
+
+	/* save for may_attach usage */
+	current->pms.old_dumpable = get_dumpable(current->mm);
+	return kcom_send_command(KCOM_L2_MIG_MM, sizeof(struct pmsp_mig_mm)
+				,(char *)&p->mm->start_code, 0, dest_ptr, NULL);
+}
+
+/**
+ * mig_send_vmas
+ *
+ * Description:
+ *    loops through and sends all process vmas to the other node.
+ *    vma's are the virtual memory structs.  They hold the lists of
+ *    mapped pages and page permissions.
+ **/
+inline static int mig_send_vmas(struct task_struct *p)
+{
+	struct vm_area_struct *vma;
+	struct pmsp_mig_vma m;
+	int ret = 0;
+	struct sockaddr_in *dest_ptr;
+
+	PMSDEBUG_MIG(2, "sending process %d\n", p->pid);
+
+	dest_ptr=(void *)p->pms.whereto;
+	for (vma = p->mm->mmap; vma; vma = vma->vm_next)
+	{
+		m.vm_start= vma->vm_start;
+		m.vm_size = vma->vm_end - vma->vm_start;
+		m.vm_flags = vma->vm_flags;
+		m.vm_file = vma->vm_file;
+		m.vm_pgoff = vma->vm_pgoff;
+		if (vma->vm_file)
+		{
+			struct inode *inode = vma->vm_file->f_path.dentry->d_inode;
+
+			m.i_size = inode->i_size;
+			if (task_test_dflags(p, DREMOTE)) {
+				/* OK so who set i_private ? */
+				m.vm_file = ((struct rfile_inode_data *)(inode->i_private))->file;
+			} else {
+				m.vm_file = vma->vm_file;
+				m.vm_dentry = vma->vm_file->f_path.dentry;
+			}
+		}
+
+		ret = kcom_send_command(KCOM_L2_MIG_VMA, sizeof(m), (char *)&m, 0, dest_ptr, NULL);
+		if (ret < 0) {
+			PMSERR("ERROR sending vmas\n");
+			return ret;
+		}
+	}
+	return ret;
+}
+
+
+/**
+ * mig_send_pages
+ *
+ * Description:
+ *    loops through and sends all process pages to the other node.
+ *    All the process's memory space is sent, one page at a time.
+ **/
+inline static int mig_send_pages(struct task_struct *p)
+{
+	struct vm_area_struct * vma;
+	unsigned long addr;
+	struct sockaddr_in *dest_ptr;
+	int ret;
+
+	PMSDEBUG_MIG(2, "sending process %d\n", p->pid);
+
+	dest_ptr=(void *)p->pms.whereto;
+	for (vma = p->mm->mmap; vma; vma = vma->vm_next)
+	{
+ 		PMSDEBUG_MIG(4, "+ checking readable vma %d\n", p->pid);
+		if (!(vma->vm_flags & VM_READ))
+			continue;
+
+ 		PMSDEBUG_MIG(4, "+ VM_READ!  %d\n", p->pid);
+		for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
+ 			PMSDEBUG_MIG(4, "++ sending page %d\n", p->pid);
+                        ret = kcom_send_command(KCOM_L2_MIG_PAGE, PAGE_SIZE, (char *)addr, addr, dest_ptr, NULL);
+                        if (ret<0)
+                        	return ret;
+                }
+	}
+	return 0;
+}
+
+inline static int mig_send_fp(struct task_struct *p)
+{
+	struct pmsp_mig_fp m;
+	struct sockaddr_in *dest_ptr;
+
+	if (!used_math()) {
+		PMSDEBUG_MIG(4, "Skipping FP for process %d\n", p->pid);
+		return 0;
+	}
+
+	PMSDEBUG_MIG(3, "Sending FP for process %d\n", p->pid);
+	arch_mig_send_fp(p, &m);
+	dest_ptr=(void *)p->pms.whereto;
+	return kcom_send_command(KCOM_L2_MIG_FP, sizeof(m), (char *)&m, 0, dest_ptr, NULL);
+}
+
+/**
+ * mig_send_proc_context - Sends the 'important' part of the process context.
+ *
+ **/
+inline static int mig_send_proc_context(struct task_struct *p)
+{
+	struct pmsp_mig_task m;
+	struct sockaddr_in* dest_ptr;
+
+	PMSDEBUG_MIG(2, "sending process %d\n", p->pid);
+	dest_ptr=(void *)p->pms.whereto;
+
+	m.ptrace = p->ptrace;
+
+	m.pid = p->pid;
+	m.tgid = p->tgid;
+
+	/* credentials */
+	m.uid = p->uid;
+	m.euid = p->euid;
+	m.suid = p->suid;
+	m.fsuid = p->fsuid;
+
+	m.gid = p->gid;
+	m.egid = p->egid;
+	m.sgid = p->sgid;
+	m.fsgid = p->fsgid;
+
+	/* signals */
+	m.blocked = p->blocked;
+	m.real_blocked = p->real_blocked;
+	m.sas_ss_sp = p->sas_ss_sp;
+	m.sas_ss_size = p->sas_ss_size;
+	memcpy(m.sighand, p->sighand->action, sizeof(struct k_sigaction) * _NSIG);
+
+	/* others */
+	m.nice = task_nice(p);
+	m.caps = p->cap_effective;
+	p->pms.remote_caps = m.caps;
+
+	m.personality = p->personality;
+
+	memcpy(m.comm, p->comm, sizeof(m.comm));
+
+	arch_mig_send_proc_context(p, &m);
+
+	return kcom_send_command(KCOM_L2_MIG_TASK, sizeof(m), (char *)&m, 0, dest_ptr, NULL);
+
+}
+
+/**
+ * mig_do_send
+ *
+ * Description:
+ *    Main loop for sending the process to the other node.
+ *
+ **/
+int mig_do_send(struct task_struct *p)
+{
+	int err = 0;
+	struct sockaddr_in* dest_ptr=(void *)p->pms.whereto;
+		struct kcom_pkt *pkt;
+		struct kcom_task *tsk;
+
+	arch_mig_send_pre(p);
+
+	if (!p)
+		goto fail_mig;
+
+	if (task_test_dflags(p, DREMOTE))  {
+		PMSDEBUG_MIG(3, "Migrating remote process %d home\n", p->pid);
+		err = kcom_send_command(KCOM_L2_MIG_GO_HOME, 0, NULL, 0, dest_ptr, NULL);
+		if (err < 0) {
+			printk(KERN_ERR "[PMS] [%d] Error informing deputy migrating remote process home\n", p->pid);
+			goto fail_mig;
+		}
+	} else {
+		PMSDEBUG_MIG(3, "Sending migrate home process %d initialisation command\n", p->pid);
+		err = kcom_send_command(KCOM_L1_MIG_INIT, 0, NULL, 0, dest_ptr, &pkt);
+		if (err < 0)
+			goto fail_mig;
+		if (!pkt) {
+			err = -EINVAL;
+			goto fail_mig;
+		}
+		tsk = kcom_task_find(p->pid);
+		tsk->rpid = * ((pid_t*) pkt->data);
+		PMSDEBUG_MIG(2, "Remote PID %d allocated for home PID %d\n" ,tsk->rpid, p->pid);
+		kcom_pkt_delete(pkt);
+	}
+
+	if ((err = mig_send_mm(p)) < 0)
+		goto fail_mig;
+
+	if ((err = mig_send_vmas(p)) < 0)
+		goto fail_mig;
+
+	if ((err = mig_send_pages(p)) < 0)
+		goto fail_mig;
+
+	if ((err = mig_send_fp(p)) < 0)
+		goto fail_mig;
+
+	if ((err = arch_mig_send_specific(p)) < 0)
+		goto fail_mig;
+
+	if ((err = mig_send_proc_context(p)) < 0)
+		goto fail_mig;
+
+	PMSDEBUG_MIG(3, "sending process[%d] done\n", p->pid);
+
+	arch_mig_send_post(p);
+
+	return 0;
+fail_mig:
+	PMSERR("Migration of process[%u] failed with error %d\n", p->pid, err);
+	return err;
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/pmsctrlfs.c linux-2.6.28.7-pms/hpc/pmsctrlfs.c
--- linux-2.6.28.7/hpc/pmsctrlfs.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/pmsctrlfs.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,59 @@
+/*
+ *	Copyright (C) 2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+#include <linux/module.h>
+#include <linux/fs.h>
+#include <linux/mount.h>
+
+#define CTRLFS_MAGIC	0x29012508
+
+static struct vfsmount *ctrlfs_mount;
+static int ctrlfs_mount_count;
+
+static int ctrlfs_fill_super(struct super_block *sb, void *data, int silent)
+{
+	static struct tree_descr debug_files[] = {{""}};
+
+	return simple_fill_super(sb, CTRLFS_MAGIC, debug_files);
+}
+
+static int ctrlfs_get_sb(struct file_system_type *fs_type,
+                                         int flags, const char *dev_name,
+                                         void *data, struct vfsmount *foo)
+{
+	return get_sb_single(fs_type, flags, data, ctrlfs_fill_super, ctrlfs_mount);
+}
+
+static struct file_system_type ctrl_fs_type = {
+	.owner =	THIS_MODULE,
+	.name =		"pmsctrlfs",
+	.get_sb =	ctrlfs_get_sb,
+	.kill_sb =	kill_litter_super,
+};
+
+int __init pms_ctrlfs_init(void)
+{
+	return register_filesystem(&ctrl_fs_type);
+}
+
+void __exit pms_ctrlfs_exit(void)
+{
+	simple_release_fs(&ctrlfs_mount, &ctrlfs_mount_count);
+	unregister_filesystem(&ctrl_fs_type);
+}
+
+module_init(pms_ctrlfs_init);
+module_exit(pms_ctrlfs_exit);
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Vincent Hanquez");
diff --exclude=.git -Nru linux-2.6.28.7/hpc/pmsdebugfs.c linux-2.6.28.7-pms/hpc/pmsdebugfs.c
--- linux-2.6.28.7/hpc/pmsdebugfs.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/pmsdebugfs.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,67 @@
+/*
+ *	Copyright (C) 2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+#include <linux/module.h>
+#include <linux/debugfs.h>
+
+#include <hpc/debug.h>
+
+
+static struct dentry *pms_debugfs_dir;
+
+static struct {
+	char *name;
+	int mode;
+	void *ptr;
+} file_entries[] = {
+	{ "migration", 0644, &pms_opts.debug_mig },
+	{ "syscall", 0644, &pms_opts.debug_sys },
+	{ "rinode", 0644, &pms_opts.debug_rino },
+	{ "copyuser", 0644, &pms_opts.debug_copyuser },
+	{ "kcomd", 0644, &pms_opts.debug_kcomd },
+	{ "protocol", 0644, &pms_opts.debug_protocol },
+};
+
+static struct dentry * dfs_dentries[ARRAY_SIZE(file_entries)];
+
+int __init pms_debugfs_init(void)
+{
+	int i;
+
+	pms_debugfs_dir = debugfs_create_dir("pms", NULL);
+	if (!pms_debugfs_dir)
+		return 1;
+
+	for (i = 0; i < ARRAY_SIZE(file_entries); i++)
+		dfs_dentries[i] = debugfs_create_u8(file_entries[i].name,
+		                                    file_entries[i].mode,
+		                                    pms_debugfs_dir,
+		                                    file_entries[i].ptr);
+	return 0;
+}
+
+void __exit pms_debugfs_exit(void)
+{
+	int i;
+
+	for (i = 0; i < ARRAY_SIZE(file_entries); i++)
+		debugfs_remove(dfs_dentries[i]);
+	debugfs_remove(pms_debugfs_dir);
+}
+
+module_init(pms_debugfs_init);
+module_exit(pms_debugfs_exit);
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Vincent Hanquez\n Florian Delizy");
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/proc.c linux-2.6.28.7-pms/hpc/proc.c
--- linux-2.6.28.7/hpc/proc.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/proc.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,542 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ * - kcomd thread by Matt Dew and Florian Delizy
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/errno.h>
+#include <linux/proc_fs.h>
+#include <linux/socket.h>
+#include <linux/ctype.h>
+#include <linux/inet.h>
+#include <linux/in.h>
+#include <asm/uaccess.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/version.h>
+#include <hpc/proc.h>
+
+/*
+ * Private structure declarations
+ */
+struct proc_pms_pid_entry {
+        int type;
+        int len;
+        char *name;
+        mode_t mode;
+        int (*set)(struct task_struct *t, char *dummy, size_t);
+        int (*get)(struct task_struct *t, char *dummy, size_t);
+};
+
+
+/*
+ *	PID set/get accessor
+ */
+static int proc_pms_pid_set_where(struct task_struct *p, char *buf, size_t size)
+{
+	size_t n = size;
+	struct in_addr saddr = {
+		.s_addr = 0,
+	};
+
+	PMSDEBUG_MIG(2, "asking process %d migration ?\n", p->pid);
+
+	if(task_test_dflags(p, (DPASSING|DINCOMING))) {
+		printk(KERN_ERR "[PMS] Can't migrate pid %d, process is currently in transition\n", p->pid );
+		return -EAGAIN;
+	}
+
+	/* ensure no trailing crap in 'where' file*/
+	while(n && buf[n-1] == '\n')
+		--n;
+	buf[n]='\0';
+	if (n < 4)
+		goto malformed;
+
+	if (n != 4 || strnicmp(buf, "home", 4)) {
+		int addr[4];
+
+		/* Sanity Check FIXME: Only accepting ipv4 addresses for now */
+		n = sscanf( buf, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3] );
+		if (n!=4)
+			goto malformed;
+		while(n) {
+			--n;
+			if(addr[n]>254 || addr[n]<0)
+				goto malformed;
+		} ;
+		/* The IP notation "0.0.0.0" also means the "home" node. */
+		saddr.s_addr = in_aton(buf);
+	}
+
+	if (task_test_dflags(p, DDEPUTY)) { 
+		struct kcom_task *tsk;
+
+		/* g_remlin: use task_register_migration ? */
+
+		tsk=kcom_task_find(p->pid);
+		if (!tsk) {
+			PMSERR("Deputy process pid %d without task!\n", p->pid);
+			return -ENODEV;
+		}
+
+		if (saddr.s_addr == 0) {
+			struct sockaddr_in* dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+
+			PMSDEBUG_MIG(3, "Deputy %d asking remote process %d to migrate home\n", p->pid,tsk->rpid);
+			__kcom_send_command(tsk, KCOM_L1_MIG_COME_HOME, 0, NULL, 0, dest_ptr, NULL);
+		}
+		else {
+			/* rule out current state, redundant migration */
+			if (saddr.s_addr != ((struct sockaddr_in *)&tsk->node->addr)->sin_addr.s_addr) {
+				PMSDEBUG_MIG(3, "Deputy %d asking remote process %d to migrate to another remote\n", p->pid,tsk->rpid);
+				/* FIXME:  remote to remote migration by deputy */
+				PMSERR("Remote to remote migration by deputy Not Implemented!\n");
+			} 
+			else {
+				int *addr = (int *)saddr.s_addr;
+				sprintf( buf, "Deputy process %d has already migrated to %d.%d.%d.%d as remote process %d\n",
+						p->pid,	addr[0], addr[1], addr[2], addr[3], tsk->rpid);
+				PMSDEBUG_MIG(3, buf);
+			}
+		}
+
+	} else if (task_test_dflags(p, DREMOTE)) {
+
+		if (likely(saddr.s_addr)) {
+			struct kcom_task *tsk;
+
+			tsk=kcom_task_find(p->pid);
+			if (!tsk) {
+				PMSERR("Remote process pid %d without task!\n", p->pid);
+				return -ENODEV;
+			}
+			/* test for migrate home by deputy's IP */
+			if (saddr.s_addr == ((struct sockaddr_in *)&tsk->node->addr)->sin_addr.s_addr) {
+				PMSDEBUG_MIG(3, "Remote asking migrated process %d to return home\n", p->pid);
+				task_register_migration(p);
+			} 
+			/* FIXME: rule out current state, redundant migration */
+			/* FIXME: remote to remote migration by remote */
+			PMSDEBUG_MIG(3, "Remote asking migrated process %d to migrate to another remote\n", p->pid);
+			PMSERR("Remote to remote migration by remote is not yet implemented\n");
+		} else {
+			PMSDEBUG_MIG(3, "Remote asking migrated process %d to return home\n",  p->pid);
+			task_register_migration(p);
+		}
+
+	} else {
+
+		if (likely(saddr.s_addr)) {
+			struct sockaddr_in* dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+
+			/* FIXME ???:  currently permits migration to self (connect fails) */
+			PMSDEBUG_MIG(3, "Asking process %d to migrate (Initial)\n", p->pid);
+			dest_ptr->sin_family=AF_INET;
+			dest_ptr->sin_port=htons(DAEMON_IP4_PORT);
+			dest_ptr->sin_addr.s_addr=saddr.s_addr;
+			task_register_migration(p);
+		}
+		else {
+			PMSERR("Can not migrate pid %d' home', it's not a migrated process\n", p->pid);
+		}
+
+	}
+	return size;
+
+malformed:
+	PMSERR("Can not move pid %d to '%s' (string length %d), malformed location\n", p->pid, buf, (int)size );
+	return -EINVAL;
+}
+
+static int proc_pms_pid_get_where(struct task_struct *p, char *buf, size_t size)
+{
+	int length;
+	unsigned int addr = 0;
+
+	if (task_test_dreqs(p, DREQ_MOVE)) {
+		length = sprintf(buf, "queued\n");
+	} else if (task_test_dflags(p, DPASSING|DINCOMING)) {
+		length = sprintf(buf, "migrating\n");
+	} else if (task_test_dflags(p, DMIGRATED)) {
+		if(p->pms.whereto) {
+			addr=((struct sockaddr_in *)p->pms.whereto)->sin_addr.s_addr;
+		}
+		length=sprintf(buf, "%u.%u.%u.%u\n", (0x000000FF & addr), (0x0000FF00 & addr)>>8,
+						     (0x00FF0000 & addr)>>16, (0xFF000000 & addr) >> 24);
+	} else
+		length = sprintf(buf, "home\n");
+
+	return length;
+}
+
+static char *stayreason_string[32] = {
+	"monkey",	"mmap_dev",	"VM86_mode",	NULL,
+	"priv_inst",	"mem_lock",	"clone_vm",	"rt_sched",
+	"direct_io",	"system",	NULL,		NULL,
+	NULL,		NULL,		NULL,		NULL,
+	NULL,		NULL,		NULL,		NULL,
+	NULL,		NULL,		NULL,		NULL,
+	"extern_1",	"extern_2",	"extern_3",	"extern_4",
+	NULL,		NULL,		NULL,		"user_lock"
+};
+
+static int proc_pms_pid_get_stay(struct task_struct *p, char *buf, size_t size)
+{
+	int length, i;
+
+	length = 0;
+	for (i = 0; i < 31; i++)
+		if (task_test_stay(p, 1 << i))
+			length += snprintf(buf + length, size - length,
+					"%s\n", stayreason_string[i]);
+	if (!length)
+		buf[0] = 0;
+	return length;
+}
+
+static int proc_pms_pid_get_debug(struct task_struct *p, char *buf, size_t size)
+{
+	int length;
+
+	length = sprintf(buf, "debug: dflags: 0x%.8x\n", p->pms.dflags);
+	return length;
+}
+
+static int proc_pms_pid_set_0(struct task_struct *p, char *value, size_t size)
+{
+	return -EINVAL;
+}
+
+/* Currently unused, commented out to silence compiler whinges
+static int proc_pms_pid_get_0(struct task_struct *p, char *value, size_t size)
+{
+	return -EINVAL;
+}
+*/
+
+/* create /proc/${pid}/ entry */
+#define E(name,s,g) {0,sizeof(name)-1,(name),0, \
+			proc_pms_pid_set_##s, \
+			proc_pms_pid_get_##g}
+
+static struct proc_pms_pid_entry proc_pms_entry_pid[] =
+{
+	E("where", where, where),
+	E("stay", 0, stay),
+	E("debug", 0, debug),
+};
+
+#undef E
+
+/**
+ * proc_pms_pid_getattr - Get attributes from task
+ * @p: the task we want attributes
+ * @name: name of the attributes
+ * @buf: the page to write the value to
+ * @size: unused
+ **/
+int proc_pms_pid_getattr(struct task_struct *p,
+			char *name, void *buf, size_t size)
+{
+	int length, i;
+
+	if (!size)
+		return -ERANGE;
+
+	length = -EINVAL;
+	for (i = 0; i < ARRAY_SIZE(proc_pms_entry_pid); i++)
+	{
+		struct proc_pms_pid_entry * tmpentry = &proc_pms_entry_pid[i];
+		if (!strncmp(name, tmpentry->name, tmpentry->len))
+		{
+			length = (tmpentry->get)(p, buf, size);
+			break;
+		}
+	}
+	return length;
+}
+
+/**
+ * proc_pms_pid_setattr - Set attributes to task
+ * @p: the task we want attributes
+ * @name: name of the attributes
+ * @buf: the page to get the value from
+ * @size: size bytes to read
+ **/
+int proc_pms_pid_setattr(struct task_struct *p,
+			char *name, void *buf, size_t size)
+{
+	int err, i;
+
+	err = -EINVAL;
+	for (i = 0; i < ARRAY_SIZE(proc_pms_entry_pid); i++)
+	{
+		struct proc_pms_pid_entry * tmpentry = &proc_pms_entry_pid[i];
+		if (!strncmp(name, tmpentry->name, tmpentry->len))
+		{
+			err = (tmpentry->set)(p, buf, size);
+			break;
+		}
+	}
+	return err;
+}
+
+#if 0
+
+struct proc_pms_entry {
+        int type;
+        int len;
+        char *name;
+        mode_t mode;
+        int (*set)(char *dummy, size_t);
+        int (*get)(char *dummy, size_t);
+};
+
+static int proc_pms_admin_set_bring(char *buf, size_t size)
+{
+	return size;
+}
+
+static int proc_pms_admin_set_expel(char *buf, size_t size)
+{
+	return size;
+}
+
+static int proc_pms_admin_get_version(char *buf, size_t size)
+{
+	int length;
+
+	length = sprintf(buf, "PMS version: %d.%d.%d\n",
+			PMS_VERSION_TUPPLE);
+	return length;
+}
+
+static int proc_pms_admin_set_0(char *value, size_t size)
+{
+	return -EINVAL;
+}
+
+static int proc_pms_admin_get_0(char *value, size_t size)
+{
+	return -EINVAL;
+}
+
+/* create /proc/hpc/admin/ entry */
+#define E(name,mode,s,g) {0,sizeof(name)-1,(name),(mode), \
+				proc_pms_admin_set_##s, \
+				proc_pms_admin_get_##g }
+
+static struct proc_pms_entry proc_pms_entry_admin[] =
+{
+	E("bring", S_IFREG|S_IRUGO|S_IWUGO, bring, 0),
+	E("expel", S_IFREG|S_IRUGO|S_IWUGO, expel, 0),
+	E("version", S_IFREG|S_IRUGO|S_IWUGO, 0, version),
+};
+
+#undef E
+
+/**
+ * proc_pms_callback_read - read an attribute and return to userspace
+ *
+ * Handle page creation and correct verification then call the callback
+ **/
+static ssize_t proc_pms_callback_read(struct file * file, char * buf,
+				  size_t count, loff_t *ppos,
+				  struct proc_pms_entry *entry)
+{
+	unsigned long page;
+	ssize_t length;
+	ssize_t end;
+	char *name;
+	int i;
+
+	if (count > PAGE_SIZE)
+		count = PAGE_SIZE;
+	if (!(page = __get_free_page(GFP_KERNEL)))
+		return -ENOMEM;
+
+	name = (char *) file->f_dentry->d_name.name;
+
+	length = -EINVAL;
+	/* browse entry to find callback for file name */
+	for (i = 0; entry[i].name; i++)
+	{
+		struct proc_pms_entry * tmpentry = &entry[i];
+		if (!strncmp(name, tmpentry->name, tmpentry->len))
+		{
+			length = (tmpentry->get)((char *) page, count);
+			break;
+		}
+	}
+
+	if (length < 0) {
+		free_page(page);
+		return length;
+	}
+	/* Static 4kB (or whatever) block capacity */
+	if (*ppos >= length) {
+		free_page(page);
+		return 0;
+	}
+	if (count + *ppos > length)
+		count = length - *ppos;
+	end = count + *ppos;
+	if (copy_to_user(buf, (char *) page + *ppos, count))
+		count = -EFAULT;
+	else
+		*ppos = end;
+	free_page(page);
+	return count;
+}
+
+/**
+ * proc_pms_callback_write - set an attribute from userspace buf
+ *
+ * Handle page creation and correct verification then call the callback
+ **/
+static ssize_t proc_pms_callback_write(struct file * file, const char * buf,
+				   size_t count, loff_t *ppos,
+				   struct proc_pms_entry *entry)
+{
+	char *page, *name;
+	ssize_t length;
+	int i;
+
+	if (count > PAGE_SIZE)
+		count = PAGE_SIZE;
+	if (*ppos != 0) {
+		/* No partial writes. */
+		return -EINVAL;
+	}
+	page = (char*)__get_free_page(GFP_USER);
+	if (!page)
+		return -ENOMEM;
+	length = -EFAULT;
+	if (copy_from_user(page, buf, count))
+		goto out;
+
+	name = (char *) file->f_dentry->d_name.name;
+
+	/* browse entry to find callback for file name */
+	for (i = 0; entry[i].name; i++)
+	{
+		struct proc_pms_entry * tmpentry = &entry[i];
+		if (!strncmp(name, tmpentry->name, tmpentry->len))
+		{
+			length = (tmpentry->set)(page, count);
+			break;
+		}
+	}
+
+out:
+	free_page((unsigned long) page);
+	return length;
+}
+
+
+/*
+ * PMS proc dir file_ops handler
+ */
+#define PROC_PMS_SUBSYS_READ(subsys)					\
+	static ssize_t proc_pms_read_##subsys(struct file * file,	\
+						char *buf,		\
+						size_t count,		\
+						loff_t *ppos)		\
+	{								\
+		return proc_pms_callback_read(file, buf, count,		\
+				ppos, proc_pms_entry_##subsys);		\
+	}
+
+#define PROC_PMS_SUBSYS_WRITE(subsys)					\
+	static ssize_t proc_pms_write_##subsys(struct file * file,	\
+						const char *buf,	\
+						size_t count,		\
+						loff_t *ppos)		\
+	{								\
+		return proc_pms_callback_write(file, buf, count,		\
+				ppos, proc_pms_entry_##subsys);		\
+	}
+
+PROC_PMS_SUBSYS_READ(admin)
+PROC_PMS_SUBSYS_WRITE(admin)
+
+#undef PROC_PMS_SUBSYS_READ
+#undef PROC_PMS_SUBSYS_WRITE
+
+static struct file_operations proc_pms_admin_operations = {
+	.read = proc_pms_read_admin,
+	.write = proc_pms_write_admin,
+};
+
+/**
+ * proc_pms_create_entry - create @entry in @dir with their callbacks
+ * @dir:	directory to create the entries into
+ * @entry:	entries to add into directory
+ * @r:		read callback
+ * @w:		write callback
+ */
+inline static void proc_pms_create_entry(struct proc_dir_entry *dir,
+					struct proc_pms_entry *entry,
+					struct file_operations *fileops)
+{
+	struct proc_dir_entry *de;
+	int i;
+
+	for (i = 0; entry[i].name; i++)
+	{
+		struct proc_pms_entry * tmp = &entry[i];
+		de = create_proc_entry(tmp->name, tmp->mode, dir);
+		if (!de) {
+			PMSERR("unable to create entry\n");
+			continue;
+		}
+		de->proc_fops = fileops;
+	}
+}
+
+/*
+ * init hpc proc directory
+ */
+void proc_pms_init(void)
+{
+	struct proc_dir_entry *dir_root, *dir_admin;
+
+	dir_root = proc_mkdir("hpc", NULL);
+	if (!dir_root) {
+		PMSERR("unable to create root directory\n");
+		return;
+	}
+
+	dir_admin = proc_mkdir("hpc/admin", NULL);
+
+	if (!dir_admin) {
+		PMSERR("unable to create admin directory\n");
+		return;
+	}
+	proc_pms_create_entry(dir_admin, proc_pms_entry_admin,
+					&proc_pms_admin_operations);
+}
+
+#endif
+
+void proc_pms_init(void)
+{
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/ptrace.c linux-2.6.28.7-pms/hpc/ptrace.c
--- linux-2.6.28.7/hpc/ptrace.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/ptrace.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,354 @@
+/*
+ *	Copyright (C) 2006-2007 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+
+/**
+ * deputy_may_attach - check if the deputy can be attached (send a
+ * request to the remote to check some fields)
+ **/
+
+#include <linux/kernel.h>
+#include <linux/ptrace.h>
+#include <linux/signal.h>
+
+#include <hpc/prototype.h>
+
+void deputy_ptrace_attach(struct task_struct *task)
+{
+	struct sockaddr_in *dest_ptr=(void *)task->pms.whereto;
+	struct kcom_task *tsk;
+	int cple = capable(CAP_SYS_PTRACE);
+
+	write_unlock_irq(&tasklist_lock);
+	local_irq_enable();
+	task_unlock(task);
+
+	tsk = kcom_home_task_find(task->pid);
+	if (!tsk)
+		return;
+
+	__kcom_send_command(tsk, KCOM_L1_PTRACE_ATTACH, sizeof(int), (char*)&cple, 0, dest_ptr, NULL);
+
+repeat:
+	/* (from kernel/ptrace.c)
+	 * Nasty, nasty.
+	 *
+	 * We want to hold both the task-lock and the
+	 * tasklist_lock for writing at the same time.
+	 * But that's against the rules (tasklist_lock
+	 * is taken for reading by interrupts on other
+	 * cpu's that may have task_lock).
+	 */
+	task_lock(task);
+	local_irq_disable();
+	if (!write_trylock(&tasklist_lock)) {
+		local_irq_enable();
+		task_unlock(task);
+		do {
+			cpu_relax();
+		} while (!write_can_lock(&tasklist_lock));
+		goto repeat;
+	}
+
+
+}
+
+
+int remote_ptrace_attach(struct kcom_node *node, const struct kcom_pkt * const pkt)
+{
+	int *capable = (int *) pkt->data;
+	struct kcom_task *task;
+
+	task = __find_task_for_packet(pkt, node, NULL);
+
+	if (!task)
+		return -ESRCH;
+
+repeat:
+	/* (from kernel/ptrace.c) :
+	 * Nasty, nasty.
+	 *
+	 * We want to hold both the task-lock and the
+	 * tasklist_lock for writing at the same time.
+	 * But that's against the rules (tasklist_lock
+	 * is taken for reading by interrupts on other
+	 * cpu's that may have task_lock).
+	 */
+	task_lock(task->task);
+	local_irq_disable();
+	if (!write_trylock(&tasklist_lock)) {
+		local_irq_enable();
+		task_unlock(task->task);
+		do {
+			cpu_relax();
+		} while (!write_can_lock(&tasklist_lock));
+		goto repeat;
+	}
+
+	task->task->ptrace |= PT_PTRACED | PT_ATTACHED;
+	if (*capable)
+		task->task->ptrace |= PT_PTRACE_CAP;
+
+	force_sig_specific(SIGSTOP, task->task);
+
+	write_unlock_irq(&tasklist_lock);
+	task_unlock(task->task);
+
+	return 0;
+}
+
+
+void remote_do_notify_parent_cldstop(struct task_struct *tsk, int why)
+{
+	struct pmsp_do_notify_parent_cldstop s;
+	struct kcom_task *task = kcom_task_find( tsk->pid );
+	struct sockaddr_in *dest_ptr=(void *)tsk->pms.whereto;
+
+	if (!task)
+		return;
+
+	s.why = why;
+	s.utime = tsk->utime;
+	s.stime = tsk->stime;
+	s.state = tsk->state;
+	s.ptrace = tsk->ptrace;
+	s.exit_code = tsk->exit_code;
+	s.exit_state = tsk->exit_state;
+
+ 	switch (why) {
+ 	case CLD_CONTINUED:
+ 		s.sig_status = SIGCONT;
+ 		break;
+ 	case CLD_STOPPED:
+ 		s.sig_status = tsk->signal->group_exit_code & 0x7f;
+ 		break;
+ 	case CLD_TRAPPED:
+ 		s.sig_status = tsk->exit_code & 0x7f;
+ 		break;
+ 	}
+	kcom_send_command(KCOM_L2_NOTIFY_CLDSTOP, sizeof(s), (char *)&s, 0, dest_ptr, NULL);
+}
+
+int deputy_do_notify_parent_cldstop(struct kcom_task* tsk, const struct kcom_pkt * const pkt)
+{
+	struct pmsp_do_notify_parent_cldstop *s;
+	struct task_struct *p = tsk->task;
+
+	s = (struct pmsp_do_notify_parent_cldstop *) pkt->data;
+
+	p->utime = s->utime;
+	p->stime = s->stime;
+	p->pms.sig_status = s->sig_status;
+	p->pms.sig_status_ready = 1;
+	p->pms.remote_state = s->state;
+	p->pms.remote_ptrace = s->ptrace;
+	p->pms.remote_exit_state = s->exit_state;
+	p->exit_code = s->exit_code;
+
+	do_notify_parent_cldstop(p, s->why);
+	return 0;
+}
+
+int deputy_get_remote_task_state(struct task_struct *child, struct pmsp_get_task_state *s)
+{
+	struct kcom_task *task;
+	struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(void *)child->pms.whereto;
+	int ret = -ENODEV;
+
+	task = kcom_home_task_find(child->pid);
+
+	if (!task)
+		goto notask;
+
+	ret = __kcom_send_command(task, KCOM_L1_GET_TASK_STATE, 0, NULL, 0, dest_ptr, &pkt);
+
+	if (ret || !pkt)
+		goto notask;
+
+	memcpy(s, pkt->data, sizeof(*s));
+
+	kcom_pkt_delete(pkt);
+
+notask:
+	return ret;
+}
+int remote_get_task_state(struct kcom_node* node, const struct kcom_pkt *const pkt)
+{
+	struct kcom_task *tsk = __find_task_for_packet(pkt, node, NULL);
+	struct pmsp_get_task_state s;
+
+	if (!tsk)
+		goto err;
+
+	s.state = tsk->task->state;
+	s.ptrace = tsk->task->ptrace;
+
+	kcom_send_resp(tsk->task, sizeof(s), (char *)&s, pkt);
+
+	return 0;
+err:
+	return -ESRCH;
+}
+
+void deputy_set_remote_traced(struct task_struct *child)
+{
+	struct kcom_task *task;
+	struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(void *)child->pms.whereto;
+	int ret;
+
+	task = kcom_home_task_find(child->pid);
+
+	if (!task)
+		return;
+
+	ret = __kcom_send_command(task, KCOM_L1_SET_TRACED, 0, NULL, 0, dest_ptr, &pkt);
+}
+
+int remote_set_traced(struct kcom_node *node, const struct kcom_pkt *const pkt)
+{
+	struct task_struct *child;
+	struct kcom_task *tsk = __find_task_for_packet(pkt, node, NULL);
+
+	if (!tsk)
+		return -ESRCH;
+
+	child = tsk->task;
+
+	read_lock(&tasklist_lock);
+	spin_lock_irq(&child->sighand->siglock);
+	child->state = TASK_TRACED;
+	spin_unlock_irq(&child->sighand->siglock);
+	read_unlock(&tasklist_lock);
+	return 0;
+}
+
+void deputy_ptrace_detach(struct task_struct *child, unsigned int data)
+{
+	struct kcom_task *task;
+	struct sockaddr_in *dest_ptr=(void *)child->pms.whereto;
+	int ret;
+
+	task = kcom_home_task_find(child->pid);
+
+	if (!task)
+		return;
+
+	ret = __kcom_send_command(task, KCOM_L1_PTRACE_DETACH, sizeof(data), (char*)&data, 0, dest_ptr, NULL);
+}
+
+/* This function is x86_64 and i386 compatible, dk about others ... */
+extern void ptrace_disable(struct task_struct *child);
+
+int remote_ptrace_detach(struct kcom_node *node, const struct kcom_pkt *const pkt)
+{
+	struct kcom_task *tsk = __find_task_for_packet(pkt, node, NULL);
+	unsigned int *data;
+
+	if (!tsk)
+		return -ESRCH;
+
+	data = (unsigned int *) pkt->data;
+
+	ptrace_disable(tsk->task);
+
+	read_lock(&tasklist_lock);
+	tsk->task->ptrace = 0;
+	read_unlock(&tasklist_lock);
+
+	if(TASK_TRACED == tsk->task->state)
+		ptrace_unlink(tsk->task);
+
+	if (tsk->task->exit_state != EXIT_ZOMBIE)
+		wake_up_process(tsk->task);
+	return 0;
+}
+
+/*
+ * Ptrace commands part
+ */
+
+int deputy_ptrace_get_set_long(struct task_struct * child, long nb, long address, long * data, int get)
+{
+	struct kcom_task *task;
+	struct sockaddr_in *dest_ptr=(void *)child->pms.whereto;
+	struct pmsp_ptrace_getset_long s;
+	struct kcom_pkt *pkt;
+
+	int ret = -ESRCH;
+
+	task = kcom_home_task_find(child->pid);
+
+	if (!task)
+		return ret;
+
+	s.data = *data;
+	s.get  = get;
+	s.address = address;
+	s.ptrace_nb = nb;
+
+	ret = __kcom_send_command(task, KCOM_L1_PTRACE_GETSET_LONG, sizeof(s), (char *)&s, 0, dest_ptr, &pkt );
+
+	if (!ret)
+		return ret;
+
+	if (get) {
+		struct pmsp_ptrace_getset_long *r;
+
+		r = (struct pmsp_ptrace_getset_long *) pkt->data;
+		*data = r->data;
+	}
+
+	kcom_pkt_delete( pkt );
+
+	return 0;
+}
+
+int remote_ptrace( struct kcom_node *node, const struct kcom_pkt *const pkt )
+{
+	struct pmsp_ptrace_getset_long *s;
+	long ret;
+	unsigned long data;
+	mm_segment_t oldfs = KERNEL_DS;
+
+	struct kcom_task *task;
+
+	task = __find_task_for_packet(pkt, node, NULL);
+	if (!task)
+		return -ESRCH;
+
+	s = (struct pmsp_ptrace_getset_long *) pkt->data;
+	data = s->data;
+
+	if (s->get) {
+		oldfs = get_fs();
+		set_fs(KERNEL_DS);
+	}
+
+	ret = arch_ptrace(task->task, s->ptrace_nb, s->address, (unsigned long) &data);
+
+	if (s->get) {
+		set_fs(oldfs);
+	}
+
+	if (ret) {
+		kcom_send_nack(task->task, pkt);
+	} else {
+		kcom_send_resp(task->task, sizeof(data), (char *)&data, pkt );
+	}
+	return 0;
+}
+
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/remote.c linux-2.6.28.7-pms/hpc/remote.c
--- linux-2.6.28.7/hpc/remote.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/remote.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,407 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/signal.h>
+#include <linux/mm.h>
+#include <linux/mman.h>
+#include <linux/syscalls.h>
+#include <linux/pagemap.h>
+#include <asm/unistd.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/kcom.h>
+
+struct vm_operations_struct remote_inode_mmap =
+{
+	.fault = filemap_fault,
+};
+
+int remote_file_mmap(struct file *file, struct vm_area_struct *vma)
+{
+        PMSDEBUG_SYS(2, "\n");
+
+	if (vma->vm_flags & VM_SHARED) {
+		PMSERR( "remote_file_mmap: VM_SHARED mmaping\n");
+		return -1;
+	}
+	vma->vm_ops = &remote_inode_mmap;
+	return 0;
+}
+
+int remote_readpage(struct file *file, struct page *page)
+{
+	int error;
+	void *kmpage;
+	struct pmsp_page_req m;
+	struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+
+        PMSDEBUG_SYS(2, "\n");
+
+	kmpage = kmap(page);
+
+	m.file = rfiles_inode_get_file(file->f_dentry->d_inode);
+	m.offset = page->index << PAGE_CACHE_SHIFT;
+
+	error = kcom_send_command(KCOM_L2_REQ_GET_PAGE, sizeof(m)
+				 ,(char *)&m, 0, dest_ptr, &pkt);
+
+	if (error < 0)
+		goto error;
+
+	memcpy(kmpage, pkt->data, PAGE_SIZE);
+	kcom_pkt_delete(pkt);
+
+	SetPageUptodate(page);
+	kunmap(page);
+	return 0;
+error:
+	PMSERR("error %d\n", error);
+	ClearPageUptodate(page);
+	SetPageError(page);
+	return error;
+}
+
+long remote_do_mmap(unsigned long addr, unsigned long len,
+		unsigned long prot, unsigned long flags,
+		unsigned long fd, unsigned long pgoff)
+{
+	struct pmsp_mmap_req m;
+	struct pmsp_mmap_ret *r;
+	struct kcom_pkt *pkt;
+	struct file *file;
+	long error;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+
+        PMSDEBUG_SYS(2, "\n");
+
+	m.addr = addr;
+	m.len = len;
+	m.prot = prot;
+	m.flags = flags;
+	m.fd = fd;
+	m.pgoff = pgoff;
+
+	error = kcom_send_command(KCOM_L2_REQ_MMAP, sizeof(m), (char*)&m, 0, dest_ptr, &pkt);
+
+	if (error < 0)
+		goto out;
+
+	r = (struct pmsp_mmap_ret*) pkt->data;
+
+	file = task_rfiles_get(current, r->file, -1, r->isize);
+
+	down_write(&current->mm->mmap_sem);
+	error = do_mmap_pgoff(file, addr, len, prot, flags, pgoff);
+	up_write(&current->mm->mmap_sem);
+
+	kcom_pkt_delete(pkt);
+
+out:
+	return error;
+}
+
+/**
+ * remote_do_signal - Handles signals from deputy to remote
+ **/
+
+int remote_do_signal(struct kcom_node* node, const struct kcom_pkt * const pkt)
+{
+        struct task_struct *p;
+	struct pmsp_signal *s;
+	int error;
+	unsigned long flags;
+        struct kcom_task *tsk;
+
+        PMSDEBUG_SYS(2, "\n");
+
+        s = (struct pmsp_signal*) pkt->data;
+        PMSDEBUG_SYS(2, "Received Signal %d From deputy\n", s->signr);
+
+        tsk = __find_task_for_packet(pkt, node, NULL);
+        if (!tsk)
+                return -ENODEV;
+
+        p = tsk->task;
+
+	spin_lock_irqsave(&p->sighand->siglock, flags);
+	error = __group_send_sig_info(s->signr, &s->siginfo, p);
+	spin_unlock_irqrestore(&p->sighand->siglock, flags);
+
+	return error;
+}
+
+/**
+ * remote_unremotise - turn a remote process into a normal process
+ * @p
+ * A remote process does not exist as a normal process,
+ * clean up remote specific and exit
+ **/
+void remote_unremotise (struct task_struct *p)
+{
+        PMSDEBUG_SYS(2, "\n");
+
+	task_set_dflags(p, DPASSING);	/* not strictly true, but we must lockout proc read/writes */
+	kcom_wait_sent(p->pid);
+	kcom_task_delete(p->pid);
+	task_heldfiles_clear(p);
+	memset(p->pms.whereto, 0, sizeof(struct sockaddr));
+	task_clear_dflags(p, DREMOTE|DPASSING);
+}
+
+/**
+ * remote_do_syscall - process a remote syscall
+ * @n:		the syscall number
+ * @regs:	userspace registers
+ **/
+long remote_do_syscall(int n, struct pt_regs *regs)
+{
+	struct task_struct *p = current;
+	struct pmsp_syscall_req s;
+	struct pmsp_syscall_ret r;
+	int i;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)p->pms.whereto;
+        struct kcom_pkt* pkt;
+        int ret;
+
+	PMSDEBUG_SYS(2, "sending request for syscall %d\n", n);
+
+	/* g_remlin: this flag does not appear to be used elsewhere as DSYSCALL,
+	 * but it's bit value is!
+	 */
+	task_set_dflags(current, DSYSCALL); 
+
+	s.n = n;
+	for (i = 0; i < NR_MAX_SYSCALL_ARG; i++)
+		s.arg[i] = arch_get_sys_arg(i, regs);
+
+        ret = kcom_send_command(KCOM_L2_MIG_SYSCALL, sizeof(s), (char *)&s, 0, dest_ptr, &pkt);
+        if (ret < 0)
+                goto error;
+
+        memcpy(&r, pkt->data, sizeof(struct pmsp_syscall_ret));
+        kcom_pkt_delete(pkt);
+
+        PMSDEBUG_SYS(2, "received syscall %d reply %ld\n", n, r.ret);
+
+	task_clear_dflags(current, DSYSCALL);
+
+        /* __NR_exit_group and __NR_exit are special cases */
+	if ((n == __NR_exit_group) || (n ==  __NR_exit)) {
+		/* flag the deputy and remote are splitting apart */
+		task_set_dflags(current, DSPLIT);
+		/* change from a remote to a normal process */
+		remote_unremotise(p);
+		/* we were the remote process, and have thus
+		been successful, regardless of the result */
+		current->exit_code = 0;
+		return(0);
+	}
+
+	set_current_state(TASK_RUNNING);
+	return r.ret;
+
+error:
+	task_clear_dflags(current, DSYSCALL);
+        PMSERR( "Error %d while executing remote syscall %d\n", ret, n);
+	return ret;
+}
+
+/**
+ * remote_do_fork - Fork a process on remote
+ **/
+long remote_do_fork(unsigned long clone_flags, unsigned long stack_start,
+	      struct pt_regs *regs, unsigned long stack_size,
+	      int __user *parent_tidptr, int __user *child_tidptr)
+{
+	struct task_struct *child;
+	struct pmsp_fork_req m;
+	struct pmsp_fork_ret *r;
+	int error, ret;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+        struct kcom_pkt *pkt;
+
+	PMSDEBUG_SYS(2,"[REMOTE] do_fork\n");
+
+	m.clone_flags = clone_flags;
+	m.stack_start = stack_start;
+	m.stack_size = stack_size;
+	memcpy(&m.regs, regs, sizeof(struct pt_regs));
+
+        error = kcom_send_command(KCOM_L2_REQ_DO_FORK, sizeof(m), (char*)&m, 0, dest_ptr, &pkt);
+
+	if (error < 0)
+		goto fail;
+
+        r = (struct pmsp_fork_ret*) pkt->data;
+
+	ret = do_fork(clone_flags, stack_start, regs, stack_size, parent_tidptr
+		     ,child_tidptr);
+
+        read_lock(&tasklist_lock);
+	child = find_task_by_vpid(ret);
+        read_unlock(&tasklist_lock);
+
+	if (!child) {
+		PMSERR( "error: child %d not found\n", r->pid);
+		return -1;
+	}
+
+	// FIXME: "Should setup the hpid/rpid for this task here"
+	return ret;
+fail:
+	PMSERR("failed\n");
+	return error;
+}
+
+/*
+ * this is a copy of count in fs/exec.c
+ */
+static int count_len(char __user * __user * argv, int max, int *len)
+{
+	int i = 0;
+
+	*len = 0;
+	if (!argv)
+		return 0;
+
+	for (;;) {
+		char __user * p;
+
+		if (get_user(p, argv))
+			return -EFAULT;
+		if (!p)
+			break;
+		*len += strlen_user(*argv);
+		argv++;
+		if (++i > max)
+			return -E2BIG;
+	}
+	return i;
+}
+
+/**
+ * remote_do_execve - do an execve syscall
+ **/
+long remote_do_execve(char __user * filename, char __user *__user *argv,
+		char __user *__user *envp, struct pt_regs * regs)
+{
+
+        struct pmsp_execve_req m;
+	// struct pmsp_execve_ret r;
+	unsigned long p;
+	char *data, *ptr;
+	int error;
+	int sz;
+        struct kcom_pkt *pkt;
+	struct sockaddr_in *dest_ptr=(struct sockaddr_in *)current->pms.whereto;
+
+        PMSERR("Not Implemented!");
+
+#ifndef MAX_ARG_PAGES
+#define MAX_ARG_PAGES 32
+#endif
+	p = PAGE_SIZE * MAX_ARG_PAGES - sizeof(void *);
+	//m.filename = filename;
+
+	m.filelen = strlen_user(filename);
+
+	error = m.argc = count_len(argv, p / sizeof(void *), &m.argvlen);
+	if (error < 0)
+		goto error;
+
+	error = m.envc = count_len(envp, p / sizeof(void *), &m.envplen);
+	if (error < 0)
+		goto error;
+
+	memcpy(&m.regs, regs, sizeof(struct pt_regs));
+
+        // FIXME: "Filename should be included in the structure itself ..."
+	/* pack all data (filename, argv, envp) */
+	sz = m.filelen + m.argvlen + m.envplen + 3;
+	data = kmalloc(sz, GFP_KERNEL);
+	if (!data)
+		return -ENOMEM;
+
+	error = -EFAULT;
+
+	ptr = data;
+	if (copy_from_user(ptr, filename, m.filelen))
+		goto error;
+	ptr += m.filelen;
+	*ptr++ = '\0';
+
+	if (copy_from_user(ptr, argv, m.argvlen))
+		goto error;
+	ptr += m.argvlen;
+	*ptr++ = '\0';
+
+	if (copy_from_user(ptr, envp, m.envplen))
+		goto error;
+	ptr += m.envplen;
+	*ptr++ = '\0';
+
+	/* send request */
+        error = kcom_send_command(KCOM_L2_REQ_DO_EXECVE, sizeof(m)
+        			 ,(char*)&m, 0, dest_ptr, &pkt);
+
+error:
+	return error;
+}
+
+
+int remote_main_loop(void)
+{
+        struct kcom_task *mytsk;
+        struct kcom_pkt *pkt;
+        int err = 0;
+
+        PMSDEBUG_SYS(2, "\n");
+
+        mytsk=kcom_task_find(current->pid);
+        if (!mytsk)
+                return -ENODEV;
+
+new_packet:
+
+        read_lock(&mytsk->in_packs_lock);
+        if (!list_empty(&mytsk->in_packs)) {
+                err = __kcom_wait_for_next_msg(mytsk, 0, &pkt);
+                if (err < 0)
+                        goto error_unlock;
+
+        }
+        read_unlock(&mytsk->in_packs_lock);
+
+        if (pkt) {
+                err = kcomd_do_l2_state_machine(mytsk, pkt);
+                kcom_pkt_delete(pkt);
+        }
+        if(!list_empty(&mytsk->in_packs))
+                goto new_packet;
+
+        return 0;
+
+error_unlock:
+        read_unlock(&mytsk->in_packs_lock);
+        return err;
+}
+
diff --exclude=.git -Nru linux-2.6.28.7/hpc/syscalls.c linux-2.6.28.7-pms/hpc/syscalls.c
--- linux-2.6.28.7/hpc/syscalls.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/syscalls.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,56 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/syscalls.h>
+#include <linux/types.h>
+#include <asm/ptrace.h>
+#include <asm/unistd.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/remote.h>
+#include <hpc/syscalls.h>
+#include <hpc/arch.h>
+
+asmlinkage long pms_sys_remote(struct pt_regs regs)
+{
+	return remote_do_syscall(SYSNB(), &regs);
+}
+
+/* specific remote syscalls */
+/* g_remlin: make #define in header file ? */
+asmlinkage int pms_sys_gettid(struct pt_regs regs)
+{
+	return current->pms.pid;
+}
+
+/* g_remlin: make #define in header file ? */
+asmlinkage int pms_sys_getpid(struct pt_regs regs)
+{
+	return current->pms.tgid;
+}
+
+asmlinkage int pms_sys_execve(struct pt_regs regs)
+{
+	return remote_do_execve((char __user *) SYSARG(0),
+	                        (char __user *__user *) SYSARG(1),
+	                        (char __user *__user *) SYSARG(2),
+	                        &regs);
+}
diff --exclude=.git -Nru linux-2.6.28.7/hpc/task.c linux-2.6.28.7-pms/hpc/task.c
--- linux-2.6.28.7/hpc/task.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/hpc/task.c	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,184 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#include <linux/sched.h>
+#include <linux/socket.h>
+#include <net/sock.h>
+
+#include <hpc/prototype.h>
+#include <hpc/debug.h>
+#include <hpc/mig.h>
+
+/**
+ * task_file_check_stay - check if task should stay because of file mapping
+ **/
+inline static int task_file_check_stay(struct vm_area_struct *vma)
+{
+	struct inode *inode;
+	mode_t mode;
+	int stay = 0;
+
+	PMSDEBUG_MIG(3, "Checking task stay reason\n");
+	inode = vma->vm_file->f_dentry->d_inode;
+	if (!inode)
+		return 0;
+
+	mode = inode->i_mode;
+
+	/* FIXME Tab: maybe wrong */
+	if (!(vma->vm_flags & VM_NONLINEAR)) {
+		if (!prio_tree_empty(&inode->i_mapping->i_mmap))
+			stay |= DSTAY_MONKEY;
+	} else {
+		if (!list_empty(&vma->shared.vm_set.list))
+			stay |= DSTAY_MONKEY;
+	}
+	if (S_ISCHR(mode) || S_ISFIFO(mode) || S_ISSOCK(mode))
+		stay |= DSTAY_DEV;
+
+	return stay;
+}
+
+/**
+ * task_request_checkstay - adjust stay reason of a task (considering mm)
+ **/
+inline static void task_request_checkstay(struct task_struct *p)
+{
+	struct mm_struct *mm;
+	int stay;
+	struct vm_area_struct *vma;
+
+	task_clear_dreqs(p, DREQ_CHECKSTAY);
+
+	printk(KERN_ERR "PMS: [%d] do_request: DREQ_CHECKSTAY\n", p->pid);
+
+	/* check if there's a stay reason we can clean, else pass */
+	if (!task_test_stay(p, DSTAY_PER_MM | DSTAY_CLONE))
+		return;
+
+	task_lock(p);
+	mm = p->mm;
+	stay = p->pms.stay & ~(DSTAY_PER_MM | DSTAY_CLONE);
+	if (!mm)
+		stay |= DSTAY_CLONE;
+	else {
+		/* FIXME: need verifying KIOBUF */
+		if (atomic_read(&mm->mm_realusers) > 1)
+			stay |= DSTAY_CLONE;
+		if (mm->def_flags & VM_LOCKED)
+			stay |= DSTAY_MLOCK;
+
+		for (vma = mm->mmap; vma; vma = vma->vm_next)
+		{
+			if (vma->vm_file)
+				stay |= task_file_check_stay(vma);
+			if (vma->vm_flags & VM_LOCKED)
+				stay |= DSTAY_MLOCK;
+		}
+	}
+	if (p->pms.stay != stay)
+		p->pms.stay = stay;
+	task_unlock(p);
+	return;
+}
+
+/**
+ * pms_task_init - Init all PMS structure of a task @p
+ **/
+int pms_task_init(struct task_struct *p)
+{
+	struct task_struct *parent = current;
+
+	memset(&p->pms, 0, sizeof(struct pms_task));
+	INIT_LIST_HEAD(&p->pms.rfiles);
+
+	p->pms.whereto = kmalloc(sizeof(struct sockaddr), GFP_KERNEL);
+	if (!p->pms.whereto) {
+		PMSERR("Can't allocate the whereto sockaddr structure for pid %d\n", p->pid);
+		return -EFAULT;
+	}
+	memset(p->pms.whereto, 0, sizeof(struct sockaddr));
+
+	if (p->pid == 1) /* init stays put */
+		task_set_stay(p, DSTAY_SYSTEM);
+
+	/* if father of task is a DREMOTEDAEMON, then the task is DREMOTE */
+	if (task_test_dflags(parent, DREMOTEDAEMON))
+		task_set_dflags(p, DREMOTE);
+	/* child of a DDEPUTY is a DDEPUTY */
+	else if (task_test_dflags(parent, DDEPUTY))
+		task_set_dflags(p, DDEPUTY);
+
+	return 0;
+}
+
+/**
+ * pms_task_exit - Exit current task
+ **/
+int pms_task_exit(long code)
+{
+	if (task_test_dflags(current, DDEPUTY | DREMOTE)) {
+		if(!task_test_dflags(current, DSPLIT)) {
+			kcom_send_command(KCOM_L2_END_OF_PROCESS, 
+				  sizeof(long), (char *)&code, 0, (struct sockaddr_in *)current->pms.whereto, NULL);
+			kcom_wait_sent(current->pid);
+		}
+		kcom_task_delete(current->pid);
+		task_heldfiles_clear(current);
+		/* task_clear_dflags(current, DDEPUTY|DREMOTE); */
+	}
+
+	if(current->pms.whereto) {
+		kfree(current->pms.whereto);
+		current->pms.whereto = NULL;
+	}
+	return 0;
+}
+
+
+/**
+ * task_register_migration - register a migration for this process
+ * @p:		task to migrate
+ **/
+int task_register_migration(struct task_struct *p)
+{
+	struct thread_info *ti = task_thread_info(p);
+
+	PMSDEBUG_MIG(3, "pid %d registering process migration ?\n", p->pid);
+	PMS_VERBOSE_MIG("pid[%d] task_register_migration\n", p->pid);
+
+	task_set_dreqs(p, DREQ_MOVE);
+	set_ti_thread_flag(ti, TIF_PMS_PENDING);
+	if (task_test_dflags(p,DDEPUTY))
+		wake_up_process(p);
+	return 0;
+}
+EXPORT_SYMBOL_GPL(task_register_migration);
+
+/**
+ * task_do_request - current task processes requests coming from other tasks
+ **/
+void task_do_request(void)
+{
+	if (task_test_dreqs(current, DREQ_MOVE))
+		mig_task_request(current);
+	if (task_test_dreqs(current, DREQ_CHECKSTAY))
+		task_request_checkstay(current);
+}
diff --exclude=.git -Nru linux-2.6.28.7/include/asm-generic/errno.h linux-2.6.28.7-pms/include/asm-generic/errno.h
--- linux-2.6.28.7/include/asm-generic/errno.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/asm-generic/errno.h	2009-03-06 19:59:09.000000000 +0000
@@ -106,4 +106,7 @@
 #define	EOWNERDEAD	130	/* Owner died */
 #define	ENOTRECOVERABLE	131	/* State not recoverable */
 
+/* PMS codes */
+#define ENACKED		270	/* PMS protocol specific NACK received */
+
 #endif
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/arch.h linux-2.6.28.7-pms/include/hpc/arch.h
--- linux-2.6.28.7/include/hpc/arch.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/arch.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,41 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_ARCH_H
+#define _HPC_ARCH_H
+
+#include <hpc/protocol.h>
+
+NORET_TYPE void arch_kickstart(struct task_struct *);
+int arch_mig_receive_proc_context(struct task_struct *, struct pmsp_mig_task *);
+void arch_mig_receive_fp(struct task_struct *, struct pmsp_mig_fp *);
+void arch_do_signal(struct task_struct *p);
+
+void arch_mig_send_pre(struct task_struct *);
+void arch_mig_send_post(struct task_struct *);
+int arch_mig_send_fp(struct task_struct *p, struct pmsp_mig_fp *);
+int arch_mig_send_proc_context(struct task_struct *, struct pmsp_mig_task *);
+int arch_mig_send_specific(struct task_struct *);
+
+#include <asm/pms.h>
+#include <hpc/syscalls.h>
+
+long arch_exec_syscall(int, struct syscall_parameter *);
+
+#endif /* _HPC_ARCH_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/debug.h linux-2.6.28.7-pms/include/hpc/debug.h
--- linux-2.6.28.7/include/hpc/debug.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/debug.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,112 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ * 
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_DEBUG_H
+#define _HPC_DEBUG_H
+
+#include <hpc/kcom.h>
+
+struct pms_options
+{
+#ifdef CONFIG_PMS_DEBUG
+        int debug_mig;
+        int debug_sys;
+        int debug_rino;
+        int debug_copyuser;
+        int debug_kcomd;
+        int debug_protocol;
+#else
+        int dummy;
+#endif
+};
+
+#if 0
+#define DEBUG_MIG 0
+#define DEBUG_SYS 1
+#define DEBUG_RINO 2
+#define DEBUG_COPYUSER 3
+#define DEBUG_KCOMD 4
+#define DEBUG_PROTOCOL 5
+#endif
+
+extern struct pms_options pms_opts; 
+
+/*******************************************************************************
+ * General debug informations 					 	       *
+ ******************************************************************************/
+
+extern void pms_dump_dflags(struct task_struct *);
+extern void pms_debug_regs(struct pt_regs *);
+extern void debug_mlink(struct socket *);
+
+extern void debug_page(unsigned long);
+/* extern void debug_regs(void); */
+extern void debug_vmas(struct mm_struct *);
+
+#ifdef CONFIG_PMS_DEBUG
+/*******************************************************************************
+ * Packet dump (only compiled when debug)			 	       *
+ ******************************************************************************/
+
+extern void pms_dump_packet(const struct kcom_pkt* const pkt);
+
+extern int pms_debug_do_switch;
+
+/*******************************************************************************
+ * Debug macros, to be used as much as possible			 	       *
+ ******************************************************************************/
+#define PMSDEBUG(var, lim, fmt...)	do { \
+					    if (var >= lim) {\
+ 						printk(KERN_ERR \
+ 						      "[PMSDBG] %s:%d " \
+ 						      , __FUNCTION__ \
+ 						      ,  __LINE__); \
+						printk(fmt); \
+					    } \
+					} while (0) \
+
+#define PMSDEBUG_DO(var, lim, action)	do { \
+					    if (var >= lim) { \
+						pms_debug_do_switch = var;  \
+						action; \
+					    } \
+					} while (0)
+#else
+#define PMSDEBUG(var, lim, fmt...)
+#define PMSDEBUG_DO(var, lim, action)
+#endif
+
+/*******************************************************************************
+ * Log Debug macros, to be used as much as possible for logging                *
+ ******************************************************************************/
+
+#define PMSDEBUG_MIG(lim, fmt...)	PMSDEBUG(pms_opts.debug_mig, lim, fmt)
+#define PMSDEBUG_SYS(lim, fmt...)	PMSDEBUG(pms_opts.debug_sys, lim, fmt)
+#define PMSDEBUG_RINO(lim, fmt...)	PMSDEBUG(pms_opts.debug_rino, lim, fmt)
+#define PMSDEBUG_CPYUSER(lim, fmt...)	PMSDEBUG(pms_opts.debug_copyuser, lim,fmt)
+#define PMSDEBUG_KCOMD(lim, fmt...)	PMSDEBUG(pms_opts.debug_kcomd, lim, fmt)
+#define PMSDEBUG_PROTOCOL(lim, fmt...)	PMSDEBUG(pms_opts.debug_protocol,lim,fmt)
+
+#define PMSDEBUG_PROTOCOL_DO(lim, action) PMSDEBUG_DO(pms_opts.debug_protocol, \
+                                         lim, action)
+#define PMSDEBUG_KCOMD_DO(lim, action)   PMSDEBUG_DO(pms_opts.debug_kcomd, \
+                                        lim, action)
+
+#endif /* _HPC_DEBUG_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/deputy.h linux-2.6.28.7-pms/include/hpc/deputy.h
--- linux-2.6.28.7/include/hpc/deputy.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/deputy.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,44 @@
+/*
+ *      Copyright (C) 2006 g_remlin <g_remlin@users.sourceforge.net>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ */
+
+#ifndef _HPC_DEPUTY_H
+#define _HPC_DEPUTY_H
+
+unsigned long   deputy_do_mmap_pgoff(struct file * file, unsigned long addr,
+                                unsigned long len, unsigned long prot,
+                                unsigned long flags, unsigned long pgoff);
+
+/* --------------------------------------------------------------------------*/
+
+extern int deputy_do_syscall(struct kcom_task *, const struct kcom_pkt *const);
+extern int deputy_do_fork(struct kcom_task *, const struct kcom_pkt *const);
+extern int deputy_do_readpage(struct kcom_task *, const struct kcom_pkt * const);
+extern int deputy_do_mmap(struct kcom_task *, const struct kcom_pkt *const);
+extern int deputy_do_execve(struct kcom_task*, const struct kcom_pkt *const);
+extern int deputy_do_notify_parent_cldstop(struct kcom_task*, const struct kcom_pkt *const);
+
+extern void deputy_ptrace_attach(struct task_struct*);
+extern void deputy_ptrace_detach(struct task_struct *, unsigned int);
+extern int deputy_get_remote_task_state(struct task_struct *, struct pmsp_get_task_state *);
+extern void deputy_set_remote_traced(struct task_struct *);
+
+extern int deputy_main_loop(void);
+extern void deputy_startup(struct task_struct *p);
+extern void deputy_undeputise(struct task_struct *p);
+
+extern int deputy_ptrace_get_set_long(struct task_struct *, long, long, long *, int);
+
+#endif /* _HPC_DEPUTY_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/hpc.h linux-2.6.28.7-pms/include/hpc/hpc.h
--- linux-2.6.28.7/include/hpc/hpc.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/hpc.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,70 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_HPC_H
+#define _HPC_HPC_H
+
+/* prototypes for function calls embedded into (what was :>) the vanilla kernel */
+
+
+#include <hpc/proc.h>
+#include <hpc/kernel.h>
+
+
+
+/* all below to be done */
+
+#include <hpc/kcom.h>
+
+
+#include <hpc/remote.h>
+/*
+long remote_do_mmap(unsigned long addr, unsigned long len,
+               unsigned long prot, unsigned long flags,
+               unsigned long fd, unsigned long pgoff);
+*/
+
+#include <hpc/deputy.h>
+/*
+unsigned long   deputy_do_mmap_pgoff(struct file * file, unsigned long addr,
+                                unsigned long len, unsigned long prot,
+                                unsigned long flags, unsigned long pgoff);
+*/
+
+/* task.c */
+int pms_task_init(struct task_struct *);
+int pms_task_exit(long code);
+
+/* deputy.c */
+#include <hpc/deputy.h>
+/*
+‘deputy_get_remote_task_state’
+‘deputy_set_remote_traced’
+‘deputy_ptrace_attach’
+‘deputy_ptrace_detach’
+*/
+
+/* remote.c */
+#include <hpc/remote.h>
+/*
+‘remote_do_notify_parent_cldstop’
+*/
+
+#endif /* _HPC_HPC_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/kcom.h linux-2.6.28.7-pms/include/hpc/kcom.h
--- linux-2.6.28.7/include/hpc/kcom.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/kcom.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,400 @@
+/*
+ *	Copyright (C) 2006 Matt Dew <matt@osource.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ */
+
+#ifndef _HPC_KCOM_H
+#define _HPC_KCOM_H
+
+#include <linux/sched.h>
+#include <linux/in.h>
+#include <linux/poll.h>
+#include <net/sock.h>
+
+#include <hpc/protocol.h>
+
+#define DAEMON_IP4_PORT	0xB55 /* 2901 g_remlin - make these a command line option */
+#define DAEMON_IP6_PORT	0xB56 /* 2902 */
+
+/* node-disconnection timeout: */
+#define PMS_CONNECTION_KEEPALIVE_INTERVAL 30
+#define PMS_CONNECTION_KEEPALIVE_MAXTRIES 6
+#define PMS_CONNECTION_KEEPALIVE_TOTAL    150 /* changed from 180 */
+
+
+/* PROTOTYPES */
+#ifdef _HPC_KCOMC_H
+	DEFINE_RWLOCK(kcom_nodes_lock);
+	EXPORT_SYMBOL(kcom_nodes_lock);
+
+	struct list_head kcom_nodes = LIST_HEAD_INIT(kcom_nodes);
+	EXPORT_SYMBOL(kcom_nodes);
+
+	fd_set_bits sockets_fds;
+	EXPORT_SYMBOL(sockets_fds);
+
+	char *sockets_fds_bitmap = NULL;
+	EXPORT_SYMBOL(sockets_fds_bitmap);
+
+	int maxfds = -1;
+	EXPORT_SYMBOL(maxfds);
+
+	struct socket *lsock4=NULL, *lsock6=NULL;
+	EXPORT_SYMBOL(lsock4);
+	EXPORT_SYMBOL(lsock6);
+
+	int fd4, fd6;
+	EXPORT_SYMBOL(fd4);
+	EXPORT_SYMBOL(fd6);
+
+	struct task_struct *kcomd_task=NULL;
+	EXPORT_SYMBOL(kcomd_task);
+
+
+	struct kmem_cache *kcom_data_cachep;
+	EXPORT_SYMBOL(kcom_data_cachep);
+
+	struct kmem_cache *kcom_pkt_cachep;
+	EXPORT_SYMBOL(kcom_pkt_cachep);
+
+	struct kmem_cache *kcom_task_cachep;
+	EXPORT_SYMBOL(kcom_task_cachep);
+
+	struct kmem_cache *kcom_node_cachep;
+	EXPORT_SYMBOL(kcom_node_cachep);
+
+	struct kmem_cache *kcom_saddr_cachep;
+	EXPORT_SYMBOL(kcom_saddr_cachep);
+
+
+#else /* _HPC_KCOMC_H */
+	extern int maxfds;
+	extern rwlock_t kcom_nodes_lock;
+	extern struct list_head kcom_nodes;
+
+	extern fd_set_bits sockets_fds;
+	extern char *sockets_fds_bitmap;
+	extern struct socket *lsock4;
+	extern struct socket *lsock6;
+	extern int fd4;
+	extern int fd6;
+
+	//extern pid_t kcom_pid;
+	extern struct task_struct *kcomd_task;
+	extern struct kmem_cache *kcom_data_cachep;
+	extern struct kmem_cache *kcom_pkt_cachep;
+	extern struct kmem_cache *kcom_task_cachep;
+	extern struct kmem_cache *kcom_node_cachep;
+	extern struct kmem_cache *kcom_saddr_cachep;
+#endif /* _HPC_KCOMC_H */
+
+/*******************************************************************************
+ * Packet exchanged between nodes :                                            *
+ ******************************************************************************/
+
+struct kcom_pkt
+{
+	/* Packet sanity fields                                               */
+
+	unsigned int magic;		/* Used to recognize PMS traffic       */
+	int hdr_len;			/* size of packet header              */
+
+	/* Dispatch fields and protocol fields                                */
+
+	int type;  			/* type of command                    */
+	unsigned int flags;		/* communication type and flags       */
+	pid_t hpid;     		/* home pid of this process           */
+	pid_t rpid;     		/* remote pid of this process         */
+
+	/* Communication identification                                       */
+
+	unsigned int msgid;		/* msgid is shared between msg with   */
+					/* its answer/ack/...                 */
+
+	/* Data related fields                                                */
+
+	int data_len;  			/* len of data without header         */
+	unsigned long addr; 		/* used by mm pages                   */
+
+	/* Fields after this point are not sent neither received              */
+
+	struct list_head list;		/* This field both marks the end of   */
+					/* sendable data and is used for      */
+					/* linking packets together           */
+	char *data;   			/* data if new msg, response if not   */
+
+} __attribute__((packed)); /* structure sent as is, thus needs to be packed   */
+
+#define KCOM_PKT_NET_SIZE	((size_t)(&((struct kcom_pkt*)0)->list))
+#define KCOM_PKT_HDR_MAGIC_STOP	((size_t)(&((struct kcom_pkt*)0)->hdr_len))
+#define KCOM_PKT_HDR_LEN_STOP	((size_t)(&((struct kcom_pkt*)0)->type))
+
+struct kcom_task;
+/*
+extern int kcom_pkt_create(struct kcom_pkt** destpkt, int len, int type
+			  ,int flags,const char*const data, int hpid, int rpid
+			  ,struct kcom_task* task);
+*/
+extern void kcom_pkt_delete(struct kcom_pkt *);
+
+/*******************************************************************************
+ * Node data                                                                   *
+ ******************************************************************************/
+
+struct kcom_node
+{
+	/* Network connectivity                                               */
+
+	int fd;                 	/* fd to send packet                  */
+	struct socket *sock;    	/* socket                             */
+	struct sockaddr addr;  		/* addr of this node                  */
+
+	/* task handling                                                      */
+
+	rwlock_t tasks_lock;  	        /* lock for the list                  */
+	struct list_head tasks; 	/* list of task                       */
+	struct list_head process_list;  /* list used internally by kcomd      */
+	int pkt_ready;			/* Is any packet ready on this node   */
+
+	/*  node linking                                                      */
+
+	struct list_head list; 		/* list of nodes                      */
+
+	/* Socket read/write error counts                                     */
+
+	int error_count;		/* Consecutive error count            */
+	int error_total;		/* Total error count (stats only)     */
+};
+
+struct kcom_node *kcom_node_add(struct socket*);
+extern struct kcom_node *kcom_node_find(const struct sockaddr* const saddr);
+
+extern int kcom_node_del(struct sockaddr *);
+extern void kcom_node_sock_release(struct kcom_node *);
+
+extern int kcom_node_increment_error(struct kcom_node *);
+extern void kcom_node_clear_error(struct kcom_node *);
+
+#if 0
+struct kcom_oob_waitqueue
+{
+	unsigned int msgid;		/* msgid expected                     */
+	pid_t pid;			/* pid of the task waiting 	      */
+	struct list_head list;		/* list of kcom_oob_waitqueue         */
+};
+#endif
+
+/*******************************************************************************
+ * Task data                                                                   *
+ ******************************************************************************/
+
+struct kcom_task
+{
+	/* Task identity                                                      */
+
+	struct task_struct *task; 	/* pointer to the process             */
+        pid_t hpid;          		/* pid on the home node		      */
+        pid_t rpid;          		/* pid of remote node process         */
+
+	/* Node relationship                                                  */
+
+        struct kcom_node *node; 	/* node of the process to send/recv   */
+        struct list_head list;  	/* list of task on the node           */
+
+	/* Task input from the peer node                                      */
+
+        struct list_head in_packs;	/* input packets added by kcomd_thread*/
+	rwlock_t in_packs_lock;		/* input list lock                    */
+
+#if 0
+        struct list_head oob_packs;	/* input packets added by kcomd_thread*/
+	rwlock_t oob_packs_lock;	/* input list lock                    */
+
+	struct list_head oob_waitqueue; /* Waiting tasks kcom_oob_waitqueue   */
+	spinlock_t oob_waitqueue_lock;  /* lock for the waitqueue             */
+#endif
+
+	/* Task output to the peer node                                       */
+
+        struct list_head out_packs;	/* packets ready to be sent           */
+	rwlock_t out_packs_lock;	/* output list lock                   */
+
+	/* kcomd_thread_handle_streams internal handling                      */
+
+	struct list_head process_list;	/* list used internally by kcomd      */
+	struct list_head egress_list;   /* list used internally by kcomd      */
+
+	/* msg id generation is based on the task itself                      */
+
+	unsigned int msgid;		/* Biggest id sent in this task comm  */
+	spinlock_t msgid_lock;		/* smp safe lock                      */
+};
+
+
+extern struct kcom_task *kcom_task_create(struct kcom_node *, int);
+extern int kcom_wait_sent(int);
+extern int kcom_task_delete(int);
+
+extern struct kcom_task *kcom_task_find(int);
+extern struct kcom_task *kcom_remote_task_find(int);
+extern struct kcom_task *kcom_home_task_find(int);
+extern struct kcom_task *__kcom_task_find(pid_t pid, int where);
+
+extern int __kcom_find_or_create_task(const struct sockaddr_in *const saddr
+				     ,struct kcom_task **tsk, pid_t pid);
+
+/*******************************************************************************
+ * Packet Handling related to layer communication                              *
+ ******************************************************************************/
+
+#define KCOM_NO_SIZE_CHECK	-1
+
+/* PMS L1 layer */
+
+struct kcom_pkt_l1_handler {
+	const char *name; 	/* command name, for logging */
+
+	/* receiving part */
+	int (*handle_pkt)(struct kcom_node*, const struct kcom_pkt* const);
+        int recv_size;		/* Size exected to be received */
+
+	/* sending part */
+	int answer_size;	/* Size of the expected answer (if any) */
+	int cmd_flags; 		/*Used for sending this kind of pkt */
+};
+extern struct kcom_pkt_l1_handler kcomd_l1_handlers[KCOM_L1_CMD_MAX-KCOM_L1_CMD_START];
+
+static inline int __is_kcom_l1_pkt_type(int type)
+{
+	return type > KCOM_L1_CMD_START && type < KCOM_L1_CMD_MAX;
+}
+
+static inline int __is_kcom_l1_pkt(struct kcom_pkt *pkt)
+{
+	return __is_kcom_l1_pkt_type(pkt->type);
+}
+
+/* PMS L2 layer */
+struct kcom_pkt_l2_handler {
+	const char *name;
+
+	/* receiving part */
+	int (*handle_pkt)(struct kcom_task*, const struct kcom_pkt* const);
+	int recv_size;
+	int perms;
+
+	/* sending part */
+	int cmd_flags;
+	int answer_size;
+};
+extern struct kcom_pkt_l2_handler kcomd_l2_handlers[KCOM_L2_CMD_MAX-KCOM_L2_CMD_START];
+extern int kcomd_do_l2_state_machine(struct kcom_task*, const struct kcom_pkt* const);
+
+static inline int __is_kcom_l2_pkt_type(int type)
+{
+	return type > KCOM_L2_CMD_START && type < KCOM_L2_CMD_MAX;
+}
+
+static inline int __is_kcom_l2_pkt(struct kcom_pkt *pkt)
+{
+	return __is_kcom_l2_pkt_type(pkt->type);
+}
+
+/**
+ * __get_default_flags - Get default communication flags for the given type
+ **/
+static inline unsigned int __get_default_flags(int type)
+{
+	if (__is_kcom_l1_pkt_type(type))
+		return kcomd_l1_handlers[KCOM_L1_CMD_INDEX(type)].cmd_flags;
+
+	if (__is_kcom_l2_pkt_type(type))
+		return kcomd_l2_handlers[KCOM_L2_CMD_INDEX(type)].cmd_flags;
+
+	return 0;
+}
+
+/**
+ * __get_default_flags - Get default communication flags for the given type
+ **/
+static inline const char* __get_packet_name(int type)
+{
+	if (__is_kcom_l1_pkt_type(type))
+		return kcomd_l1_handlers[KCOM_L1_CMD_INDEX(type)].name;
+
+	if (__is_kcom_l2_pkt_type(type))
+		return kcomd_l2_handlers[KCOM_L2_CMD_INDEX(type)].name;
+
+	return "Invalid Type";
+}
+static inline int __get_answer_size(int type)
+{
+	if (__is_kcom_l1_pkt_type(type))
+		return kcomd_l1_handlers[KCOM_L1_CMD_INDEX(type)].answer_size;
+
+	if (__is_kcom_l2_pkt_type(type))
+		return kcomd_l2_handlers[KCOM_L2_CMD_INDEX(type)].answer_size;
+
+	return -ENODEV;
+}
+static inline int __get_receive_size(int type)
+{
+	if (__is_kcom_l1_pkt_type(type))
+		return kcomd_l1_handlers[KCOM_L1_CMD_INDEX(type)].recv_size;
+
+	if (__is_kcom_l2_pkt_type(type))
+		return kcomd_l2_handlers[KCOM_L2_CMD_INDEX(type)].recv_size;
+
+	return -ENODEV;
+}
+
+/*******************************************************************************
+ * Communication primitives                                                    *
+ ******************************************************************************/
+
+extern int kcom_add_packet(struct kcom_task *tsk, struct kcom_pkt *pkt);
+
+extern int kcom_send(int type, int datasize, char *data, unsigned long addr
+	            ,const struct sockaddr_in * const saddr);
+extern int kcom_task_send(struct kcom_task *, int, int, const char* const,unsigned long);
+
+extern int kcom_send_ack(struct task_struct *, const struct kcom_pkt *const);
+extern int kcom_send_ack_progress(struct task_struct *p, const struct kcom_pkt *const);
+extern int kcom_send_nack(struct task_struct *, const struct kcom_pkt * const);
+extern int kcom_send_resp(struct task_struct *, int , char *, const struct kcom_pkt * const);
+
+/*extern int __kcom_wait_for_any_msg(struct kcom_task* tsk, struct kcom_pkt **answerpkt); */
+extern int __kcom_wait_for_next_msg(struct kcom_task* tsk, int msgid, struct kcom_pkt **answerpkt);
+extern int __kcom_wait_msg(struct kcom_task* tsk, struct kcom_pkt **answerpkt);
+extern struct kcom_node *__create_connection(struct sockaddr*
+					    ,struct kcom_node*);
+
+int __pkt_read(struct kcom_node *node, struct kcom_pkt **recv_kcom_pkt);
+extern int append_in_packs(struct kcom_pkt *, struct kcom_node*);
+
+
+/* Main interface to use for command sending outside of kcomd */
+int kcom_send_command(int type, int datasize, const char * const data
+		     ,unsigned long addr, const struct sockaddr_in * const saddr
+		     ,struct kcom_pkt ** answer);
+
+int __kcom_send_command(struct kcom_task* tsk, int type, int datasize
+			, const char * const data, unsigned long addr
+		        ,const struct sockaddr_in * const saddr
+		        , struct kcom_pkt ** answer);
+
+struct kcom_task * __find_task_for_packet(const struct kcom_pkt* const pkt
+					 ,struct kcom_node* node
+				         ,pid_t *pid);
+
+#endif /* _HPC_KCOM_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/kernel.h linux-2.6.28.7-pms/include/hpc/kernel.h
--- linux-2.6.28.7/include/hpc/kernel.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/kernel.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,26 @@
+/*
+ *      Copyright (C) 2006 g_remlin <g_remlin@users.sourceforge.net>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ */
+
+#ifndef _HPC_KERNEL_H
+#define _HPC_KERNEL_H
+
+int pms_pre_clone(int);
+void pms_post_clone(int);
+void pms_no_longer_monkey(struct inode *);
+int pms_stay_me_and_my_clones(int);
+void pms_unstay_mm(struct mm_struct *);
+
+#endif
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/mig.h linux-2.6.28.7-pms/include/hpc/mig.h
--- linux-2.6.28.7/include/hpc/mig.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/mig.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,50 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_MIG_H
+#define _HPC_MIG_H
+
+#include <linux/sched.h>
+#include <net/sock.h>
+
+#include <hpc/kcom.h>
+
+int mig_task_request(struct task_struct *p);
+int mig_do_receive(struct task_struct *);
+int mig_do_send(struct task_struct *);
+
+/* L1 packet handlers : */
+extern int mig_do_receive_init(struct kcom_node*, const struct kcom_pkt* const);
+extern int mig_do_come_home(struct kcom_node*, const struct kcom_pkt* const);
+extern int mig_do_l1_error(struct kcom_node*, const struct kcom_pkt* const);
+
+/* L2 packet handlers */
+
+extern int mig_do_receive_home(struct kcom_task*, const struct kcom_pkt* const);
+extern int mig_do_end_of_process(struct kcom_task *tsk, const struct kcom_pkt * const pkt);
+extern int mig_do_receive_mm(struct kcom_task *, const struct kcom_pkt *const);
+extern int mig_do_receive_proc_context(struct kcom_task *, const struct kcom_pkt * const);
+extern int mig_do_receive_fp(struct kcom_task *, const struct kcom_pkt *const);
+extern int mig_do_receive_page(struct kcom_task *, const struct kcom_pkt *const);
+extern int mig_do_receive_vma(struct kcom_task *, const struct kcom_pkt * const);
+
+KCOMD_NSTATIC int mig_handle_migration(void *param);
+
+
+#endif /* _HPC_MIG_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/pmstask.h linux-2.6.28.7-pms/include/hpc/pmstask.h
--- linux-2.6.28.7/include/hpc/pmstask.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/pmstask.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,60 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_OMTASK_H
+#define _HPC_OMTASK_H
+#include <linux/capability.h>
+#include <linux/list.h>
+#include <asm/atomic.h>
+
+/* temporary fix for ppc */
+#ifndef NCAPINTS
+# define NCAPINTS 1
+#endif
+
+
+struct pms_task {
+	volatile u32 dflags;		/* distributed flags */
+	volatile u32 stay;		/* reasons why process must stay */
+	atomic_t dreqs;			/* bits that others may request */
+	struct socket *contact;		/* DEPUTY <==> REMOTE connection */
+	struct sockaddr *whereto;	/* sockaddr to send to if DREQ_MOVE */
+
+	/* ptrace specific fields */
+
+	unsigned old_dumpable;		/* old mm->dumpable */
+	int sig_status;			/* Used for do_notify_parent_cldstop */
+	int sig_status_ready;		/* set to one when ready, 0 if not */
+	long remote_state;		/* The remote last reported state (ptrace) */
+	unsigned long remote_ptrace;	/* The remote ptrace var */
+	long remote_exit_state;
+
+
+	struct list_head rfiles;	/* deputy held files */
+
+	/* the following variables are only use on remote */
+	kernel_cap_t remote_caps;	/* effective capabilities on REMOTE */
+	pid_t pid;			/* original PID */
+	pid_t tgid;			/* original TGID */
+
+	/* arch dependant */
+	u32 features[NCAPINTS];		/* CPU features on original node */
+};
+
+#endif /* _HPC_OMTASK_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/proc.h linux-2.6.28.7-pms/include/hpc/proc.h
--- linux-2.6.28.7/include/hpc/proc.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/proc.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,27 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_PROC_H
+#define _HPC_PROC_H
+
+void proc_pms_init(void);
+int proc_pms_pid_getattr(struct task_struct *, char *, void *, size_t);
+int proc_pms_pid_setattr(struct task_struct *, char *, void *, size_t);
+
+#endif /* _HPC_PROC_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/protocol.h linux-2.6.28.7-pms/include/hpc/protocol.h
--- linux-2.6.28.7/include/hpc/protocol.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/protocol.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,356 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006- Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+#ifndef _HPC_PROTOCOL_H
+#define _HPC_PROTOCOL_H
+
+#include <linux/sched.h>
+#include <linux/fs.h>
+#include <linux/types.h>
+#include <linux/socket.h>
+#include <asm/pms-protocol.h>
+#include <asm/pms.h>
+
+/* packet magic number */
+#define PMS_PKT_MAGIC		0xB1adeFad
+
+
+
+/* g_remlin: this is a mess, some defines resolve to zero, making them
+ * indistguinguishable, others marked flags are used as absolute values.
+ * The absolute values are or'ed with bit flags confusing the issue further.
+ * As migration "sort of" works after hacking kcom, I will leave rewriting
+ * this (and kcomd, kcom, & the table) until my brain can hadle the
+ * fustration. For now, Beasting rules!.
+ */
+
+/* pkt communication flags pkt->flags */
+
+#define __kcom_pkt_flags(pkt)	(pkt->flags)
+
+/* bits 3:0 - ACK related flags */
+#define CASE_PKT_NEW_MSG	0x0
+#define CASE_PKT_ACK		0x1
+#define CASE_PKT_NACK		0x2
+#define CASE_PKT_ACK_PROGRESS	0x3
+#define CASE_PKT_RESP		0x4
+#define KCOM_PKT_MSG_MASK 	0xF
+
+#define __kcom_msg_flags(data)		((data)&KCOM_PKT_MSG_MASK)
+#define __kcom_pkt_msg_flags(pkt)	__kcom_msg_flags(__kcom_pkt_flags(pkt))
+
+/* bits 7:4 - Command Protocol type */
+#define KCOM_PKT_SYNC		0x10
+#define KCOM_PKT_CPLX		0x20
+#define KCOM_PKT_TSK_ACKED	0x40
+#define KCOM_PKT_ANSWERED	0x80
+#define KCOM_PKT_CMD_MASK	0xF0
+
+#define KCOM_PKT_ASYNC		0x00	/* Async messages don't care of any answer */
+//#define KCOM_PKT_SIMPLE	0x00
+//#define KCOM_PKT_NOTACKED	0x00
+//#define KCOM_PKT_KCOMD_ACKED	0x00
+//#define KCOM_PKT_NOANSWER	0x00
+
+#define __kcom_cmd_flags(data)		((data)&KCOM_PKT_CMD_MASK)
+#define __kcom_pkt_cmd_flags(pkt)	__kcom_cmd_flags((__kcom_pkt_flags(pkt)))
+
+/* Composed protocol messages flags : */
+
+#define KCOM_COMPLEX_MSG	(KCOM_PKT_SYNC|KCOM_PKT_CPLX)		//(KCOM_PKT_SYNC|KCOM_PKT_CPLX|KCOM_PKT_KCOMD_ACKED)
+#define KCOM_SYNC	        (KCOM_PKT_SYNC)				//(KCOM_PKT_SYNC|KCOM_PKT_SIMPLE|KCOM_PKT_KCOMD_ACKED)
+#define KCOM_TSK_SYNC		(KCOM_PKT_SYNC|KCOM_PKT_TSK_ACKED)	//(KCOM_PKT_SYNC|KCOM_PKT_SIMPLE|KCOM_PKT_TSK_ACKED)
+
+#define KCOM_ASYNC_SIMPLE	(KCOM_PKT_ASYNC)			//(KCOM_PKT_ASYNC|KCOM_PKT_SIMPLE|KCOM_PKT_NOTACKED|KCOM_PKT_NOANSWER)
+
+
+#define KCOM_TSK_ANSWERED	(KCOM_PKT_SYNC|KCOM_PKT_TSK_ACKED|KCOM_PKT_ANSWERED)	//(KCOM_TSK_SYNC|KCOM_PKT_ANSWERED)
+
+/* Composed messages types */
+
+#define KCOM_ACK_FLAGS		(CASE_PKT_ACK)			//(CASE_PKT_ACK | KCOM_ASYNC_SIMPLE)
+#define KCOM_NACK_FLAGS		(KCOM_PKT_ASYNC)		//(CASE_PKT_NACK| KCOM_ASYNC_SIMPLE)
+#define KCOM_ACK_PROG_FLAGS	(CASE_PKT_ACK_PROGRESS)		//(CASE_PKT_ACK_PROGRESS | KCOM_ASYNC_SIMPLE)
+#define KCOM_RESPONSE_FLAGS	(CASE_PKT_RESP)			//(CASE_PKT_RESP | KCOM_ASYNC_SIMPLE)
+
+/* bits 11:8 - node status */
+
+#define KCOM_PKT_DEP_FLG	0x100
+#define KCOM_PKT_MIG_FLG	0x200
+#define KCOM_PKT_REM_FLG	0x400
+#define KCOM_PKT_NODE_MASK	0xF00
+
+/* bit 12 : Out Of Band stream marker */
+
+#define KCOM_PKT_OOB		0x1000
+
+#define __kcom_node_flags(data)		((data)&KCOM_PKT_NODE_MASK)
+#define __kcom_pkt_node_flags(pkt)	__kcom_node_flags(__kcom_pkt_flags(pkt))
+
+/* Packet command types pkt->type */
+
+#define KCOM_CMD_NONE	0		/* Should never happen */
+enum {
+
+	/* Commands executed directly on packet read,                    */
+	/* hence in kcomd_thread context                                 */
+
+	KCOM_L1_CMD_START	= 0,
+	KCOM_L1_MIG_INIT,	       /* Send to initiate the migration */
+	KCOM_L1_MIG_COME_HOME,	       /* Ask the task to go home        */
+	KCOM_L1_DEP_SIGNAL,            /* Deputy send a signal to remote */
+
+	/* ptrace support                                                */
+
+	KCOM_L1_PTRACE_ATTACH,	       /* Notify the remote its attached */
+	KCOM_L1_PTRACE_CALL,	       /* execute ptrace on deputy       */
+	KCOM_L1_GET_TASK_STATE,	       /*  get the remote task state     */
+	KCOM_L1_SET_TRACED,	       /* called to set to TASK_TRACED   */
+	KCOM_L1_PTRACE_DETACH,	       /* called to set the task free(tm)*/
+	KCOM_L1_PTRACE_GETSET_LONG,    /* called by several ptrace calls */
+
+	KCOM_L1_CMD_MAX,
+
+	/* Commands executed in the process context                      */
+	KCOM_L2_CMD_START 	= 1000,
+
+	/* Migration commands protocol                                   */
+
+	KCOM_L2_MIG_MM,		       /* mm struct send                 */
+	KCOM_L2_MIG_VMA,	       /* vma struct packet              */
+	KCOM_L2_MIG_PAGE,	       /* page struct packet             */
+	KCOM_L2_MIG_FP,	               /* Floating point struct packet   */
+	KCOM_L2_MIG_ARCH,	       /* arch specific packet           */
+	KCOM_L2_MIG_TASK,	       /* task struct packet             */
+
+	/* Commands occurring while task is running                      */
+
+	KCOM_L2_MIG_GO_HOME,	       /* remote task coming back home   */
+	KCOM_L2_MIG_SYSCALL,	       /* Syscall command                */
+	KCOM_L2_END_OF_PROCESS,	       /* Sent by remote to notify exit  */
+
+	/* Request during syscalls                                       */
+
+	KCOM_L2_REQ_COPY_FROM_USER,    /* Remote copy_from_user          */
+	KCOM_L2_REQ_COPY_TO_USER,      /* Remote copy_to_user            */
+	KCOM_L2_REQ_STRNCPY_FROM_USER, /* Remote strncpy_from_user       */
+	KCOM_L2_REQ_STRNLEN_USER,      /* Remote strnlen_user            */
+	KCOM_L2_REQ_GET_USER,          /* Remote get_user                */
+	KCOM_L2_REQ_PUT_USER,          /* Remote put_user                */
+
+	KCOM_L2_REQ_GET_PAGE,
+	KCOM_L2_REQ_DO_FORK,
+	KCOM_L2_REQ_MMAP,
+	KCOM_L2_REQ_DO_EXECVE,
+
+
+	KCOM_L2_NOTIFY_CLDSTOP,	       /* Notify deputy of the break     */
+
+	KCOM_L2_CMD_MAX,
+
+        /* FIXME not handled yet : */
+
+	KCOM_L2_REQ_DO_SYSCALL,
+	KCOM_L2_REQ_COMING_HOME,
+	KCOM_L2_REQ_BRING_HOME,
+};
+
+/* Last known command type*/
+//#define	KCOM_CMD_MAX	KCOM_CMD_ASY_MAX
+
+//#define MIG_HOME	MIG_GO_HOME
+
+#define KCOM_L1_CMD_INDEX(type)		(type-KCOM_L1_CMD_START)
+#define KCOM_L2_CMD_INDEX(type)		(type-KCOM_L2_CMD_START)
+
+
+/* Permissions for packet command execution in L2 */
+
+#define KCOM_PERM_MIGRATION		0x00000080
+#define KCOM_PERM_SYSCALL		0x00000010
+#define KCOM_PERM_NEVER			0x0
+#define KCOM_PERM_ANYTIME		0xFFFFFFFF
+
+
+/* task_struct values that need to be passed */
+struct pmsp_mig_task
+{
+	unsigned long ptrace;
+	long nice;
+
+	kernel_cap_t caps;
+	struct rlimit rlim_cpu, rlim_data, rlim_stack, rlim_rss, rlim_as;
+
+	pid_t pid, tgid;
+	unsigned long personality;
+
+	/* process credentials */
+	uid_t uid, euid, suid, fsuid;
+	gid_t gid, egid, sgid, fsgid;
+
+	/* signals */
+	sigset_t blocked, real_blocked;
+	struct k_sigaction sighand[_NSIG];
+	unsigned long sas_ss_sp;
+	size_t sas_ss_size;
+
+	/* saved user space regs */
+	struct pt_regs regs;
+
+	struct pmsp_mig_arch_task arch;
+	char comm[TASK_COMM_LEN];
+};
+
+/* mm_struct values */
+struct pmsp_mig_mm
+{
+	unsigned long start_code, end_code, start_data, end_data;
+	unsigned long start_brk, brk, start_stack;
+	unsigned long arg_start, arg_end, env_start, env_end;
+};
+
+struct pmsp_mig_vma
+{
+	unsigned long vm_start;
+	unsigned long vm_size;
+	unsigned long vm_flags;
+	unsigned long vm_pgoff;
+	struct file *vm_file;
+	struct dentry *vm_dentry;
+	loff_t i_size;
+};
+
+struct pmsp_syscall_req
+{
+	int n;			/* syscall number */
+	unsigned long arg[NR_MAX_SYSCALL_ARG];	/* array of arguments */
+};
+
+struct pmsp_syscall_ret
+{
+	long ret;		/* syscall return value */
+};
+
+struct pmsp_fork_req
+{
+	unsigned long clone_flags;
+	struct pt_regs regs;
+	struct sockaddr sockaddr;
+	unsigned long stack_start;
+	unsigned long stack_size;
+};
+
+struct pmsp_fork_ret
+{
+	pid_t pid, tgid;	/* child pid and tgid */
+};
+
+struct pmsp_usercopy_req
+{
+	unsigned long addr;
+	unsigned long len;
+};
+
+struct pmsp_usercopy_emb
+{
+	unsigned long addr;
+	unsigned long len;
+	s64 val;
+};
+
+struct pmsp_page_req
+{
+	struct file * file;
+	unsigned long offset;
+};
+
+struct pmsp_mmap_req
+{
+	unsigned long addr;
+	unsigned long len;
+	unsigned long flags;
+	unsigned long prot;
+	unsigned long fd;
+	unsigned long pgoff;
+};
+
+struct pmsp_execve_req
+{
+	int argc, envc;
+	int argvlen, envplen;
+	struct pt_regs regs;
+	int filelen;
+	char filename[PATH_MAX+1];
+};
+
+struct pmsp_execve_ret
+{
+	int ret;
+};
+
+struct pmsp_mmap_ret
+{
+	long ret;
+	struct file * file;
+	unsigned long isize;
+};
+
+struct pmsp_signal
+{
+	int signr;
+	siginfo_t siginfo;
+};
+
+struct pmsp_ptrace_call
+{
+	unsigned long request;
+	void * addr;
+	void * data;
+};
+
+struct pmsp_do_notify_parent_cldstop
+{
+	int why;
+	cputime_t utime;
+	cputime_t stime;
+	long state;
+	unsigned long ptrace;
+	long exit_code;
+	long exit_state;
+	int sig_status;
+};
+
+
+struct pmsp_ptrace_getset_long
+{
+	long ptrace_nb;
+	long address;
+	long data;
+	int get;
+	int set;
+};
+
+/* types stolen from include/linux/sched.h */
+struct pmsp_get_task_state
+{
+  volatile long state;
+  unsigned long ptrace;
+};
+
+#endif /*  _HPC_PROTOCOL_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/prototype.h linux-2.6.28.7-pms/include/hpc/prototype.h
--- linux-2.6.28.7/include/hpc/prototype.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/prototype.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,95 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *	Copyright (C) 2006 Florian Delizy <fdy@e8dev.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_PROTOTYPE_H
+#define _HPC_PROTOTYPE_H
+
+asmlinkage long sys_madvise(unsigned long, size_t, int);
+
+PMS_NSTATIC void reparent_to_kthreadd(void);
+
+int obtain_mm(struct task_struct *p);
+
+int alloc_fd_bitmap(int);
+
+int user_thread(int (*fn)(void *), volatile void * arg, unsigned long flags);
+
+#include <linux/kernel.h>
+
+#ifdef CONFIG_PMS_MIGRATION_VERBOSE
+#define PMS_VERBOSE_MIG(fmt...)	printk(KERN_ERR fmt)
+#else
+#define PMS_VERBOSE_MIG(fmt...)	do { } while (0)
+#endif
+
+#define PMSBUG(f, a...)	do { \
+			    printk(KERN_ERR "[PMSBUG] %s: " f, __FUNCTION__, ## a); \
+			    dump_stack(); \
+			} while (0)
+
+#define PMSERR(f, a...)	do { \
+			    printk(KERN_ERR "[PMS ERROR] %s: " f, __FUNCTION__, ## a); \
+			} while (0)
+
+#include <linux/in.h>
+#include <hpc/kcom.h>
+
+/*****************************************************************************/
+
+struct pms_held_file
+{
+	struct list_head list;
+	struct file *file;
+	unsigned long nb;
+	int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf);
+};
+
+struct rfile_inode_data
+{
+	struct file *file;
+	unsigned long node;
+	loff_t isize;
+};
+
+struct vm_operations_struct; /* forward declaration */
+
+int			task_heldfiles_add(struct task_struct *p, struct file *file,
+					struct vm_operations_struct *vm_ops);
+void			task_heldfiles_clear(struct task_struct *p);
+struct pms_held_file *	task_heldfiles_find(struct task_struct *p, struct file *file);
+
+struct file *		task_rfiles_get(struct task_struct *p, struct file *file,
+					unsigned long node, loff_t isize);
+
+struct file *		rfiles_inode_get_file(struct inode *inode);
+
+/*****************************************************************************/
+
+/*
+extern int task_request_move(struct task_struct *p);
+
+*/
+
+void do_notify_parent_cldstop(struct task_struct *tsk, int why);
+
+extern PMS_NSTATIC unsigned short twd_i387_to_fxsr( unsigned short twd );
+extern PMS_NSTATIC unsigned long twd_fxsr_to_i387( struct i387_fxsave_struct *fxsave );
+
+#endif /* _HPC_PROTOTYPE_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/remote.h linux-2.6.28.7-pms/include/hpc/remote.h
--- linux-2.6.28.7/include/hpc/remote.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/remote.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,58 @@
+/*
+ *      Copyright (C) 2006 g_remlin <g_remlin@users.sourceforge.net>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ */
+
+#ifndef _HPC_REMOTE_H
+#define _HPC_REMOTE_H
+
+long            remote_do_mmap(unsigned long addr, unsigned long len,
+                                unsigned long prot, unsigned long flags,
+                                unsigned long fd, unsigned long pgoff);
+
+long            remote_do_execve(char __user * filename,
+                                char __user *__user *argv,
+                                char __user *__user *envp,
+                                struct pt_regs * regs);
+
+/*---------------------------------------------------------------------------*/
+
+#include <hpc/protocol.h>
+
+extern int remote_main_loop(void);
+extern int remote_file_mmap(struct file *file, struct vm_area_struct *vma);
+extern int remote_readpage(struct file *file, struct page *page);
+extern long remote_do_syscall(int, struct pt_regs *);
+extern void remote_unremotise (struct task_struct *p);
+
+extern long remote_do_fork(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr);
+
+/* L1 packet handlers : */
+extern int remote_do_signal(struct kcom_node*, const struct kcom_pkt * const);
+extern int remote_put_user(struct kcom_task*, const struct kcom_pkt *const);
+extern int remote_copy_to_user(struct kcom_task *, const struct kcom_pkt * const);
+extern int remote_get_user(struct kcom_task *, const struct kcom_pkt *const);
+extern int remote_strncpy_from_user(struct kcom_task *, const struct kcom_pkt * const);
+extern int remote_copy_from_user(struct kcom_task *,const struct kcom_pkt *const);
+extern int remote_strnlen_user(struct kcom_task*, const struct kcom_pkt *const);
+extern void remote_do_notify_parent_cldstop(struct task_struct *tsk, int why);
+
+extern int remote_get_task_state(struct kcom_node*, const struct kcom_pkt *const);
+extern int remote_ptrace_attach(struct kcom_node *, const struct kcom_pkt *const);
+extern int remote_set_traced(struct kcom_node *, const struct kcom_pkt *const);
+extern int remote_ptrace_detach(struct kcom_node *, const struct kcom_pkt *const);
+extern int remote_ptrace( struct kcom_node *, const struct kcom_pkt *const);
+
+#endif /* _HPC_REMOTE_H */
+
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/syscalls.h linux-2.6.28.7-pms/include/hpc/syscalls.h
--- linux-2.6.28.7/include/hpc/syscalls.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/syscalls.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,30 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_SYSCALL_H
+#define _HPC_SYSCALL_H
+
+#define SYSARG(n)	arch_get_sys_arg(n, &regs)
+#define SYSNB()		arch_get_sys_nb(&regs)
+
+struct syscall_parameter { long arg[NR_MAX_SYSCALL_ARG]; };
+
+typedef long (*syscall_func_t)(struct syscall_parameter);
+
+#endif /* _HPC_SYSCALL_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/task.h linux-2.6.28.7-pms/include/hpc/task.h
--- linux-2.6.28.7/include/hpc/task.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/task.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,142 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_TASK_H
+#define _HPC_TASK_H
+
+#ifdef CONFIG_PMS
+
+#include <linux/types.h>
+#include <linux/sched.h>
+#include <asm/atomic.h>
+
+/*
+ * distributed flags (dflags):
+ * that are *ONLY* set by the process itself, but may be read by others:
+ * Those flags are used in L2 of kcomd to check if a packet can be executed
+ */
+#define	DDEPUTY		0x00000001	/* process is a DEPUTY stub */
+#define	DREMOTE		0x00000002	/* process is running remotely */
+
+#define DSYSCALL	0x00000010	/* task is executing remote syscall */
+#define	DINCOMING	0x00000040	/* process coming here */
+#define	DPASSING	0x00000080	/* process is in migration */
+
+#define	DSPLIT		0x00000100	/* other (task) partner has died */
+#define	DFINISHED	0x00000200	/* wants to become zombie */
+#define	DREMOTEDAEMON	0x00000400	/* set DREMOTE on "fork" */
+
+#define	DMIGRATED	(DDEPUTY | DREMOTE) /* if task has been migrated */
+
+/*
+ * distributed request (dreqs):
+ * Thoses flags are set by any process to interact with the process.
+ */
+#define DREQ_MOVE	(1 << 0)	/* the process has to move */
+#define	DREQ_CHECKSTAY	(1 << 1)	/* check whether still stay */
+#define	DREQ_URGENT	(1 << 2)	/* something urgent (R=>D) */
+
+/*
+ * stay reason (dstay):
+ */
+#define	DSTAY_MONKEY	(1 << 0)	/* using monkey vnode */
+#define	DSTAY_DEV	(1 << 1)	/* mapping a device */
+#define	DSTAY_86	(1 << 2)	/* running in 86 mode */
+//#define	DSTAY_PRIV	(1 << 4)	/* privilleged inst. access (in/out) */
+#define	DSTAY_MLOCK	(1 << 5)	/* has locked memory */
+#define	DSTAY_CLONE	(1 << 6)	/* shared VM, eliminate this once DSM*/
+//#define	DSTAY_RT	(1 << 7)	/* Real-Time scheduling */
+//#define	DSTAY_IOPL	(1 << 8)	/* direct I/O permission */
+#define	DSTAY_SYSTEM	(1 << 9)	/* init process */
+//#define	DSTAY_OTHER1	(1 << 24)	/* external reason for stay (1) */
+//#define	DSTAY_OTHER2	(1 << 25)	/* external reason for stay (2) */
+//#define	DSTAY_OTHER3	(1 << 26)	/* external reason for stay (3) */
+//#define	DSTAY_OTHER4	(1 << 27)	/* external reason for stay (4) */
+#define	DNOMIGRATE	(1 << 31)	/* user requested no auto-migrations */
+
+#define	DSTAY		(~DNOMIGRATE)
+#define	DSTAY_PER_MM	(DSTAY_MONKEY|DSTAY_DEV|DSTAY_MLOCK)
+
+int task_set_where(struct task_struct *p, int value);
+int task_get_where(struct task_struct *p);
+
+/* dreqs */
+static inline void task_set_dreqs(struct task_struct *p, unsigned int val)
+{
+	atomic_set_mask(val, &p->pms.dreqs);
+}
+
+static inline void task_clear_dreqs(struct task_struct *p, unsigned int val)
+{
+	atomic_clear_mask(val, &p->pms.dreqs);
+}
+
+static inline int task_test_dreqs(struct task_struct *p, unsigned int val)
+{
+	return (atomic_read(&p->pms.dreqs) & val);
+}
+
+/* dflags */
+
+static inline void task_set_dflags(struct task_struct *p, unsigned int val)
+{
+	p->pms.dflags |= val;
+}
+
+static inline void task_clear_dflags(struct task_struct *p, unsigned int val)
+{
+	p->pms.dflags &= ~val;
+}
+
+static inline int task_test_dflags(struct task_struct *p, unsigned int val)
+{
+	return (p->pms.dflags & val);
+}
+
+/* stay */
+
+static inline void task_set_stay(struct task_struct *p, unsigned int val)
+{
+	p->pms.stay |= val;
+}
+
+static inline void task_clear_stay(struct task_struct *p, unsigned int val)
+{
+	p->pms.stay &= ~val;
+}
+
+static inline int task_test_stay(struct task_struct *p, unsigned int val)
+{
+	return (p->pms.stay & val);
+}
+
+#define task_dreqs_pending(p)	task_test_dreqs(p, ~0)
+
+int task_go_home(struct task_struct *p);
+int task_go_home_for_reason(struct task_struct *p, int reason);
+
+void task_do_request(void);
+
+struct sockaddr;
+int task_register_migration(struct task_struct *p);
+
+struct inode;
+
+#endif /* CONFIG_PMS */
+#endif /* _HPC_HPCTASK_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/uaccess.h linux-2.6.28.7-pms/include/hpc/uaccess.h
--- linux-2.6.28.7/include/hpc/uaccess.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/uaccess.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,65 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_UACCESS_H
+#define _HPC_UACCESS_H
+
+//#ifdef CONFIG_PMS
+#include <hpc/task.h>
+
+unsigned long	deputy_copy_from_user(void *to,
+					const void __user *from,
+					unsigned long n);
+unsigned long	deputy_copy_to_user(void __user *to,
+					const void *from,
+					unsigned long n);
+unsigned long	deputy_strncpy_from_user(char *dst, const char __user *src,
+							long count);
+unsigned long	deputy_strnlen_user(const char *s, long n);
+
+long		deputy_get_user(long *value, const void *addr, size_t size);
+long		deputy_put_user(long value, const void *addr, size_t size);
+
+#if BITS_PER_LONG < 64
+long		deputy_get_user64(s64 *value, const void *addr);
+long		deputy_put_user64(s64 value, const void *addr);
+#endif
+
+/**
+ * pms_memory_away - Test is memory is here
+ **/
+static inline int pms_memory_away(void)
+{
+	if (segment_eq(get_fs(), KERNEL_DS))
+		return 0;
+	if (task_test_dflags(current, DDEPUTY)) {
+		return 1;
+        }
+	return 0;
+}
+
+//#else
+
+//#define pms_memory_away() 0
+//#define deputy_put_user(a, b, c) 0
+//#define deputy_get_user(a, b, c) 0
+
+//#endif
+
+#endif /* _HPC_UACCESS_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/hpc/version.h linux-2.6.28.7-pms/include/hpc/version.h
--- linux-2.6.28.7/include/hpc/version.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/hpc/version.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,45 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *	Copyright (C) 2005-2006 Vincent Hanquez <vincent@snarc.org>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ *
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez and Alexander Nyberg
+ *
+ */
+
+#ifndef _HPC_VERSION_H
+#define _HPC_VERSION_H
+
+#define PMS_VERSION_MAJOR		0
+#define PMS_VERSION_MINOR		0
+#define PMS_VERSION_MICRO		0
+
+#define PMS_VERSION_TUPPLE \
+				PMS_VERSION_MAJOR, \
+				PMS_VERSION_MINOR, \
+				PMS_VERSION_MICRO
+
+// PMSVERSION=$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
+
+/*
+#define PMS_VERSION	(PMS_VERSION_MAJOR * 10000) + \
+				(PMS_VERSION_MINOR * 100) + \
+				(PMS_VERSION_MICRO)
+*/
+
+/* FIXME : need to create a scheme about version handling
+#define PMS_VERSION_BALANCE	0x1L
+#define PMS_VERSION_MIGRATION	0x1L
+*/
+
+#endif /* _HPC_VERSION_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/compiler.h linux-2.6.28.7-pms/include/linux/compiler.h
--- linux-2.6.28.7/include/linux/compiler.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/compiler.h	2009-03-06 19:59:09.000000000 +0000
@@ -53,6 +53,18 @@
 # include <linux/compiler-intel.h>
 #endif
 
+#ifdef CONFIG_PMS
+#define PMS_NSTATIC
+#else
+#define PMS_NSTATIC static
+#endif
+
+#if defined(CONFIG_KCOMD) || defined(CONFIG_KCOMD_MODULE)
+#define KCOMD_NSTATIC
+#else
+#define KCOMD_NSTATIC static
+#endif
+
 /*
  * Generic compiler-dependent macros required for kernel
  * build go below this comment. Actual compiler/compiler version
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/hpc.h linux-2.6.28.7-pms/include/linux/hpc.h
--- linux-2.6.28.7/include/linux/hpc.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/include/linux/hpc.h	2009-03-06 19:59:09.000000000 +0000
@@ -0,0 +1,26 @@
+/*
+ *	Copyright (C) 2002-2004 Moshe Bar <moshe@moshebar.com>
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License as published
+ * by the Free Software Foundation; version 2 only.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ * 
+ * Original Mosix code Copyright (C) Amnon Barak, Amnon Shiloh
+ *
+ * Changes for 2.6 by Vincent Hanquez
+ *
+ */
+
+#ifndef _LINUX_HPC_H
+#define _LINUX_HPC_H
+
+#ifdef CONFIG_PMS
+#include <hpc/hpc.h>
+#endif
+
+#endif /* _LINUX_HPC_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/init_task.h linux-2.6.28.7-pms/include/linux/init_task.h
--- linux-2.6.28.7/include/linux/init_task.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/init_task.h	2009-03-06 19:59:09.000000000 +0000
@@ -11,6 +11,8 @@
 #include <linux/securebits.h>
 #include <net/net_namespace.h>
 
+#include <hpc/task.h>
+
 extern struct files_struct init_files;
 
 #define INIT_KIOCTX(name, which_mm) \
@@ -26,6 +28,13 @@
 	.max_reqs	= ~0U,				\
 }
 
+#ifdef CONFIG_PMS
+#define PMS_INIT_MM()			\
+	.mm_realusers = ATOMIC_INIT(1),
+#else
+#define PMS_INIT_MM()
+#endif
+
 #define INIT_MM(name) \
 {			 					\
 	.mm_rb		= RB_ROOT,				\
@@ -36,6 +45,7 @@
 	.page_table_lock =  __SPIN_LOCK_UNLOCKED(name.page_table_lock),	\
 	.mmlist		= LIST_HEAD_INIT(name.mmlist),		\
 	.cpu_vm_mask	= CPU_MASK_ALL,				\
+	PMS_INIT_MM()					\
 }
 
 #define INIT_SIGNALS(sig) {						\
@@ -113,6 +123,16 @@
 # define CAP_INIT_BSET  CAP_INIT_EFF_SET
 #endif
 
+#ifdef CONFIG_PMS
+#define PMS_INIT_TASK(tsk) \
+	.pms = {	\
+	.dflags = 0,				\
+	.dreqs = ATOMIC_INIT(0),                \
+	.rfiles = LIST_HEAD_INIT(tsk.pms.rfiles),\
+	}
+#else
+#define PMS_INIT_TASK(tsk)
+#endif
 /*
  *  INIT_TASK is used to set up the first task table, touch at
  * your own risk!. Base=0, limit=0x1fffff (=2MB)
@@ -180,6 +200,7 @@
 	INIT_IDS							\
 	INIT_TRACE_IRQFLAGS						\
 	INIT_LOCKDEP							\
+	PMS_INIT_TASK(tsk)					\
 }
 
 
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/mm_types.h linux-2.6.28.7-pms/include/linux/mm_types.h
--- linux-2.6.28.7/include/linux/mm_types.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/mm_types.h	2009-03-06 19:59:09.000000000 +0000
@@ -256,6 +256,9 @@
 #ifdef CONFIG_MMU_NOTIFIER
 	struct mmu_notifier_mm *mmu_notifier_mm;
 #endif
+#ifdef CONFIG_PMS
+        atomic_t mm_realusers;          /* nb of processes that uses this mm */
+#endif /* CONFIG_PMS */
 };
 
 #endif /* _LINUX_MM_TYPES_H */
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/net.h linux-2.6.28.7-pms/include/linux/net.h
--- linux-2.6.28.7/include/linux/net.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/net.h	2009-03-06 19:59:09.000000000 +0000
@@ -208,6 +208,10 @@
 extern int	     sock_wake_async(struct socket *sk, int how, int band);
 extern int	     sock_register(const struct net_proto_family *fam);
 extern void	     sock_unregister(int family);
+#ifdef CONFIG_KCOMD
+extern struct	     socket *sock_alloc(void);
+#endif
+
 extern int	     sock_create(int family, int type, int proto,
 				 struct socket **res);
 extern int	     sock_create_kern(int family, int type, int proto,
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/ptrace.h linux-2.6.28.7-pms/include/linux/ptrace.h
--- linux-2.6.28.7/include/linux/ptrace.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/ptrace.h	2009-03-06 19:59:09.000000000 +0000
@@ -67,6 +67,9 @@
 #define PT_TRACE_EXEC	0x00000080
 #define PT_TRACE_VFORK_DONE	0x00000100
 #define PT_TRACE_EXIT	0x00000200
+#ifdef CONFIG_PMS
+#define PT_ATTACHED      0x00000400      /* parent != real_parent    g_remlin: PT_TRACE_MASK */
+#endif
 
 #define PT_TRACE_MASK	0x000003f4
 
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/sched.h linux-2.6.28.7-pms/include/linux/sched.h
--- linux-2.6.28.7/include/linux/sched.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/sched.h	2009-03-06 19:59:09.000000000 +0000
@@ -1,6 +1,10 @@
 #ifndef _LINUX_SCHED_H
 #define _LINUX_SCHED_H
 
+#ifdef CONFIG_PMS
+#include <hpc/pmstask.h>
+#endif /* CONFIG_PMS */
+
 /*
  * cloning flags:
  */
@@ -239,6 +243,9 @@
 extern spinlock_t mmlist_lock;
 
 struct task_struct;
+//#ifdef CONFIG_PMS
+//typedef struct task_struct task_t;
+//#endif
 
 extern void sched_init(void);
 extern void sched_init_smp(void);
@@ -1325,6 +1332,9 @@
 	struct list_head pi_state_list;
 	struct futex_pi_state *pi_state_cache;
 #endif
+#ifdef CONFIG_PMS
+	struct pms_task pms;
+#endif /* CONFIG_PMS */
 #ifdef CONFIG_NUMA
 	struct mempolicy *mempolicy;
 	short il_next;
diff --exclude=.git -Nru linux-2.6.28.7/include/linux/signal.h linux-2.6.28.7-pms/include/linux/signal.h
--- linux-2.6.28.7/include/linux/signal.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/linux/signal.h	2009-03-06 19:59:09.000000000 +0000
@@ -234,7 +234,7 @@
 
 extern int next_signal(struct sigpending *pending, sigset_t *mask);
 extern int group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p);
-extern int __group_send_sig_info(int, struct siginfo *, struct task_struct *);
+extern int __group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p);
 extern long do_sigpending(void __user *, unsigned long);
 extern int sigprocmask(int, sigset_t *, sigset_t *);
 extern int show_unhandled_signals;
diff --exclude=.git -Nru linux-2.6.28.7/include/net/sock.h linux-2.6.28.7-pms/include/net/sock.h
--- linux-2.6.28.7/include/net/sock.h	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/include/net/sock.h	2009-03-06 19:59:09.000000000 +0000
@@ -869,6 +869,10 @@
 						     unsigned long size,
 						     int noblock,
 						     int *errcode);
+#ifdef CONFIG_PMS
+extern struct socket 		*sock_alloc(void);
+#endif
+
 extern void *sock_kmalloc(struct sock *sk, int size,
 			  gfp_t priority);
 extern void sock_kfree_s(struct sock *sk, void *mem, int size);
diff --exclude=.git -Nru linux-2.6.28.7/kernel/exit.c linux-2.6.28.7-pms/kernel/exit.c
--- linux-2.6.28.7/kernel/exit.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/kernel/exit.c	2009-03-06 19:59:09.000000000 +0000
@@ -48,12 +48,14 @@
 #include <linux/tracehook.h>
 #include <trace/sched.h>
 
+#include <linux/hpc.h>
+
 #include <asm/uaccess.h>
 #include <asm/unistd.h>
 #include <asm/pgtable.h>
 #include <asm/mmu_context.h>
 
-static void exit_mm(struct task_struct * tsk);
+PMS_NSTATIC void exit_mm(struct task_struct * tsk);
 
 static inline int task_detached(struct task_struct *p)
 {
@@ -322,7 +324,7 @@
  *
  * NOTE that reparent_to_kthreadd() gives the caller full capabilities.
  */
-static void reparent_to_kthreadd(void)
+PMS_NSTATIC void reparent_to_kthreadd(void)
 {
 	write_lock_irq(&tasklist_lock);
 
@@ -670,11 +672,15 @@
  * Turn us into a lazy TLB process if we
  * aren't already..
  */
-static void exit_mm(struct task_struct * tsk)
+PMS_NSTATIC void exit_mm(struct task_struct * tsk)
 {
 	struct mm_struct *mm = tsk->mm;
 	struct core_state *core_state;
 
+#ifdef CONFIG_PMS
+        // if (!task_test_dflags(tsk, DDEPUTY|DSPLIT))
+        if (!task_test_dflags(tsk, DSPLIT))
+#endif
 	mm_release(tsk, mm);
 	if (!mm)
 		return;
@@ -1052,6 +1058,9 @@
 		update_hiwater_rss(tsk->mm);
 		update_hiwater_vm(tsk->mm);
 	}
+#ifdef CONFIG_PMS
+	pms_task_exit(code);
+#endif
 	group_dead = atomic_dec_and_test(&tsk->signal->live);
 	if (group_dead) {
 		hrtimer_cancel(&tsk->signal->real_timer);
diff --exclude=.git -Nru linux-2.6.28.7/kernel/fork.c linux-2.6.28.7-pms/kernel/fork.c
--- linux-2.6.28.7/kernel/fork.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/kernel/fork.c	2009-03-06 19:59:09.000000000 +0000
@@ -68,6 +68,8 @@
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 
+#include <linux/hpc.h>
+
 /*
  * Protected counters by write_lock_irq(&tasklist_lock)
  */
@@ -403,6 +405,9 @@
 {
 	atomic_set(&mm->mm_users, 1);
 	atomic_set(&mm->mm_count, 1);
+#ifdef CONFIG_PMS
+	atomic_set(&mm->mm_realusers, 1);
+#endif /* CONFIG_PMS */
 	init_rwsem(&mm->mmap_sem);
 	INIT_LIST_HEAD(&mm->mmlist);
 	mm->flags = (current->mm) ? current->mm->flags
@@ -596,6 +601,9 @@
 	err = dup_mmap(mm, oldmm);
 	if (err)
 		goto free_pt;
+#ifdef CONFIG_PMS
+	task_clear_stay(tsk, DSTAY_CLONE);
+#endif /* CONFIG_PMS */
 
 	mm->hiwater_rss = get_mm_rss(mm);
 	mm->hiwater_vm = mm->total_vm;
@@ -640,6 +648,9 @@
 
 	if (clone_flags & CLONE_VM) {
 		atomic_inc(&oldmm->mm_users);
+#ifdef CONFIG_PMS
+		atomic_inc(&oldmm->mm_realusers);
+#endif /* CONFIG_PMS */
 		mm = oldmm;
 		goto good_mm;
 	}
@@ -1100,6 +1111,10 @@
 		goto bad_fork_cleanup_policy;
 	if ((retval = audit_alloc(p)))
 		goto bad_fork_cleanup_security;
+#ifdef CONFIG_PMS
+	if ((retval = pms_task_init(p)))
+		goto bad_fork_cleanup_audit;
+#endif /* CONFIG_PMS */
 	/* copy all the process information */
 	if ((retval = copy_semundo(clone_flags, p)))
 		goto bad_fork_cleanup_audit;
@@ -1266,6 +1281,9 @@
 		attach_pid(p, PIDTYPE_PID, pid);
 		nr_threads++;
 	}
+#ifdef CONFIG_PMS
+	pms_pre_clone(clone_flags);
+#endif
 
 	total_forks++;
 	spin_unlock(&current->sighand->siglock);
@@ -1435,6 +1453,9 @@
 	} else {
 		nr = PTR_ERR(p);
 	}
+#ifdef CONFIG_PMS
+	pms_post_clone(clone_flags);
+#endif
 	return nr;
 }
 
diff --exclude=.git -Nru linux-2.6.28.7/kernel/ptrace.c linux-2.6.28.7-pms/kernel/ptrace.c
--- linux-2.6.28.7/kernel/ptrace.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/kernel/ptrace.c	2009-03-06 19:59:09.000000000 +0000
@@ -21,6 +21,7 @@
 #include <linux/audit.h>
 #include <linux/pid_namespace.h>
 #include <linux/syscalls.h>
+#include <linux/hpc.h>
 
 #include <asm/pgtable.h>
 #include <asm/uaccess.h>
@@ -66,7 +67,11 @@
  */
 void __ptrace_unlink(struct task_struct *child)
 {
+#ifdef CONFIG_PMS
+	BUG_ON(!child->ptrace && !task_test_dflags(child, DDEPUTY));
+#else
 	BUG_ON(!child->ptrace);
+#endif
 
 	child->ptrace = 0;
 	child->parent = child->real_parent;
@@ -82,6 +87,26 @@
 int ptrace_check_attach(struct task_struct *child, int kill)
 {
 	int ret = -ESRCH;
+#ifdef CONFIG_PMS
+	//long state;
+	//int ptrace;
+
+	//state = child->state;
+	//ptrace = child->ptrace;
+
+	if (task_test_dflags(child, DDEPUTY)) {
+		struct pmsp_get_task_state s;
+		int ret;
+
+		ret = deputy_get_remote_task_state(child, &s);
+		if (ret)
+			goto notask;
+
+		child->state = s.state;
+		child->ptrace = s.ptrace;
+	}
+notask:
+#endif
 
 	/*
 	 * We take the read lock around doing both checks to close a
@@ -135,6 +160,11 @@
 	     (current->gid != task->gid)) && !capable(CAP_SYS_PTRACE))
 		return -EPERM;
 	smp_rmb();
+#ifdef CONFIG_PMS
+	if (task_test_dflags(task, DDEPUTY))
+		dumpable = task->pms.old_dumpable;
+	else
+#endif
 	if (task->mm)
 		dumpable = get_dumpable(task->mm);
 	if (!dumpable && !capable(CAP_SYS_PTRACE))
@@ -227,10 +257,18 @@
 
 	write_lock_irq(&tasklist_lock);
 	/* protect against de_thread()->release_task() */
+#ifdef CONFIG_PMS
+	if (child->ptrace || task_test_dflags(child, DDEPUTY))
+#else
 	if (child->ptrace)
+#endif
 		__ptrace_detach(child, data);
 	write_unlock_irq(&tasklist_lock);
 
+#ifdef CONFIG_PMS
+	if(task_test_dflags(child, DDEPUTY))
+		deputy_ptrace_detach(child, data);
+#endif
 	return 0;
 }
 
diff --exclude=.git -Nru linux-2.6.28.7/kernel/sched.c linux-2.6.28.7-pms/kernel/sched.c
--- linux-2.6.28.7/kernel/sched.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/kernel/sched.c	2009-03-06 19:59:09.000000000 +0000
@@ -954,7 +954,7 @@
  * interrupts. Note the ordering: we can safely lookup the task_rq without
  * explicitly disabling preemption.
  */
-static struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
+PMS_NSTATIC struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
 	__acquires(rq->lock)
 {
 	struct rq *rq;
@@ -983,7 +983,7 @@
 	spin_unlock(&rq->lock);
 }
 
-static inline void task_rq_unlock(struct rq *rq, unsigned long *flags)
+PMS_NSTATIC inline void task_rq_unlock(struct rq *rq, unsigned long *flags)
 	__releases(rq->lock)
 {
 	spin_unlock_irqrestore(&rq->lock, *flags);
diff --exclude=.git -Nru linux-2.6.28.7/kernel/signal.c linux-2.6.28.7-pms/kernel/signal.c
--- linux-2.6.28.7/kernel/signal.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/kernel/signal.c	2009-03-06 19:59:09.000000000 +0000
@@ -27,6 +27,7 @@
 #include <linux/freezer.h>
 #include <linux/pid_namespace.h>
 #include <linux/nsproxy.h>
+#include <linux/hpc.h>
 #include <trace/sched.h>
 
 #include <asm/param.h>
@@ -35,6 +36,7 @@
 #include <asm/siginfo.h>
 #include "audit.h"	/* audit_signal_info() */
 
+
 /*
  * SLAB caches for signal bits.
  */
@@ -1419,14 +1421,23 @@
 	return ret;
 }
 
-static void do_notify_parent_cldstop(struct task_struct *tsk, int why)
+PMS_NSTATIC void do_notify_parent_cldstop(struct task_struct *tsk, int why)
 {
 	struct siginfo info;
 	unsigned long flags;
 	struct task_struct *parent;
 	struct sighand_struct *sighand;
 
+#ifdef CONFIG_PMS
+	if (task_test_dflags(tsk, DREMOTE)) {
+		remote_do_notify_parent_cldstop(tsk, why);
+		return;
+	}
+
+	if (tsk->ptrace & PT_PTRACED || task_test_dflags(tsk, DDEPUTY))
+#else
 	if (tsk->ptrace & PT_PTRACED)
+#endif
 		parent = tsk->parent;
 	else {
 		tsk = tsk->group_leader;
@@ -1448,6 +1459,14 @@
 	info.si_stime = cputime_to_clock_t(tsk->stime);
 
  	info.si_code = why;
+#ifdef CONFIG_PMS
+	if (unlikely(task_test_dflags(tsk, DDEPUTY) && tsk->pms.sig_status_ready))
+	{
+		tsk->pms.sig_status_ready = 0;
+		info.si_status = tsk->pms.sig_status;
+		goto sendsig;
+	}
+#endif
  	switch (why) {
  	case CLD_CONTINUED:
  		info.si_status = SIGCONT;
@@ -1462,6 +1481,9 @@
  		BUG();
  	}
 
+#ifdef CONFIG_PMS
+sendsig:
+#endif
 	sighand = parent->sighand;
 	spin_lock_irqsave(&sighand->siglock, flags);
 	if (sighand->action[SIGCHLD-1].sa.sa_handler != SIG_IGN &&
@@ -1476,6 +1498,20 @@
 
 static inline int may_ptrace_stop(void)
 {
+#ifdef CONFIG_PMS
+       /*
+        * On remote ptrace, the parent is the same as real_parent,
+        * but the process is marked as PT_ATTACHED, finally there
+        * are no real interest in checking current->parent->signal
+        * since the real parent is not on this computer
+        */
+	if (unlikely(task_test_dflags(current, DREMOTE))) {
+		if (unlikely(current->parent != current->real_parent))
+			return 0;
+		if(!unlikely(current->ptrace & PT_ATTACHED))
+			return 0;
+	}
+#endif
 	if (!likely(current->ptrace & PT_PTRACED))
 		return 0;
 	/*
diff --exclude=.git -Nru linux-2.6.28.7/MAINTAINERS linux-2.6.28.7-pms/MAINTAINERS
--- linux-2.6.28.7/MAINTAINERS	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/MAINTAINERS	2009-03-06 19:59:09.000000000 +0000
@@ -2709,6 +2709,11 @@
 M:	eric.piel@tremplin-utc.net
 S:	Maintained
 
+LINUXPMI
+M:	g_remlin@users.sourceforge.net
+W:      http://pmsuscd.sourceforge.net
+S:	Maintained
+
 LM83 HARDWARE MONITOR DRIVER
 P:	Jean Delvare
 M:	khali@linux-fr.org
diff --exclude=.git -Nru linux-2.6.28.7/Makefile linux-2.6.28.7-pms/Makefile
--- linux-2.6.28.7/Makefile	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/Makefile	2009-03-06 19:59:09.000000000 +0000
@@ -509,6 +509,9 @@
 # Defaults vmlinux but it is usually overridden in the arch makefile
 all: vmlinux
 
+unsparse:
+	scripts/unsparse
+
 ifdef CONFIG_CC_OPTIMIZE_FOR_SIZE
 KBUILD_CFLAGS	+= -Os
 else
@@ -619,7 +622,7 @@
 
 
 ifeq ($(KBUILD_EXTMOD),)
-core-y		+= kernel/ mm/ fs/ ipc/ security/ crypto/ block/
+core-y		+= kernel/ mm/ fs/ ipc/ security/ crypto/ block/ hpc/
 
 vmlinux-dirs	:= $(patsubst %/,%,$(filter %/, $(init-y) $(init-m) \
 		     $(core-y) $(core-m) $(drivers-y) $(drivers-m) \
diff --exclude=.git -Nru linux-2.6.28.7/mm/mlock.c linux-2.6.28.7-pms/mm/mlock.c
--- linux-2.6.28.7/mm/mlock.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/mm/mlock.c	2009-03-06 19:59:09.000000000 +0000
@@ -18,6 +18,7 @@
 #include <linux/rmap.h>
 #include <linux/mmzone.h>
 #include <linux/hugetlb.h>
+#include <linux/hpc.h>
 
 #include "internal.h"
 
@@ -513,6 +514,10 @@
 	/* check against resource limits */
 	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
 		error = do_mlock(start, len, 1);
+#ifdef CONFIG_PMS
+	if (!error) /* FIXME len == 0 shouldn't DSTAY MLOCK current & clones */
+		pms_stay_me_and_my_clones(DSTAY_MLOCK);
+#endif /* CONFIG_PMS */
 	up_write(&current->mm->mmap_sem);
 	return error;
 }
@@ -526,6 +531,10 @@
 	start &= PAGE_MASK;
 	ret = do_mlock(start, len, 0);
 	up_write(&current->mm->mmap_sem);
+#ifdef CONFIG_PMS
+	if (ret)
+		pms_unstay_mm(current->mm);
+#endif /* CONFIG_PMS */
 	return ret;
 }
 
@@ -577,6 +586,10 @@
 	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
 	    capable(CAP_IPC_LOCK))
 		ret = do_mlockall(flags);
+#ifdef CONFIG_PMS
+	if (!ret)
+		pms_stay_me_and_my_clones(DSTAY_MLOCK);
+#endif /* CONFIG_PMS */
 	up_write(&current->mm->mmap_sem);
 out:
 	return ret;
@@ -589,6 +602,10 @@
 	down_write(&current->mm->mmap_sem);
 	ret = do_mlockall(0);
 	up_write(&current->mm->mmap_sem);
+#ifdef CONFIG_PMS
+	if (ret)
+		pms_unstay_mm(current->mm);
+#endif /* CONFIG_PMS */
 	return ret;
 }
 
diff --exclude=.git -Nru linux-2.6.28.7/mm/mlock.c.orig linux-2.6.28.7-pms/mm/mlock.c.orig
--- linux-2.6.28.7/mm/mlock.c.orig	1970-01-01 01:00:00.000000000 +0100
+++ linux-2.6.28.7-pms/mm/mlock.c.orig	2009-02-20 22:41:27.000000000 +0000
@@ -0,0 +1,629 @@
+/*
+ *	linux/mm/mlock.c
+ *
+ *  (C) Copyright 1995 Linus Torvalds
+ *  (C) Copyright 2002 Christoph Hellwig
+ */
+
+#include <linux/capability.h>
+#include <linux/mman.h>
+#include <linux/mm.h>
+#include <linux/swap.h>
+#include <linux/swapops.h>
+#include <linux/pagemap.h>
+#include <linux/mempolicy.h>
+#include <linux/syscalls.h>
+#include <linux/sched.h>
+#include <linux/module.h>
+#include <linux/rmap.h>
+#include <linux/mmzone.h>
+#include <linux/hugetlb.h>
+
+#include "internal.h"
+
+int can_do_mlock(void)
+{
+	if (capable(CAP_IPC_LOCK))
+		return 1;
+	if (current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur != 0)
+		return 1;
+	return 0;
+}
+EXPORT_SYMBOL(can_do_mlock);
+
+#ifdef CONFIG_UNEVICTABLE_LRU
+/*
+ * Mlocked pages are marked with PageMlocked() flag for efficient testing
+ * in vmscan and, possibly, the fault path; and to support semi-accurate
+ * statistics.
+ *
+ * An mlocked page [PageMlocked(page)] is unevictable.  As such, it will
+ * be placed on the LRU "unevictable" list, rather than the [in]active lists.
+ * The unevictable list is an LRU sibling list to the [in]active lists.
+ * PageUnevictable is set to indicate the unevictable state.
+ *
+ * When lazy mlocking via vmscan, it is important to ensure that the
+ * vma's VM_LOCKED status is not concurrently being modified, otherwise we
+ * may have mlocked a page that is being munlocked. So lazy mlock must take
+ * the mmap_sem for read, and verify that the vma really is locked
+ * (see mm/rmap.c).
+ */
+
+/*
+ *  LRU accounting for clear_page_mlock()
+ */
+void __clear_page_mlock(struct page *page)
+{
+	VM_BUG_ON(!PageLocked(page));
+
+	if (!page->mapping) {	/* truncated ? */
+		return;
+	}
+
+	dec_zone_page_state(page, NR_MLOCK);
+	count_vm_event(UNEVICTABLE_PGCLEARED);
+	if (!isolate_lru_page(page)) {
+		putback_lru_page(page);
+	} else {
+		/*
+		 * We lost the race. the page already moved to evictable list.
+		 */
+		if (PageUnevictable(page))
+			count_vm_event(UNEVICTABLE_PGSTRANDED);
+	}
+}
+
+/*
+ * Mark page as mlocked if not already.
+ * If page on LRU, isolate and putback to move to unevictable list.
+ */
+void mlock_vma_page(struct page *page)
+{
+	BUG_ON(!PageLocked(page));
+
+	if (!TestSetPageMlocked(page)) {
+		inc_zone_page_state(page, NR_MLOCK);
+		count_vm_event(UNEVICTABLE_PGMLOCKED);
+		if (!isolate_lru_page(page))
+			putback_lru_page(page);
+	}
+}
+
+/*
+ * called from munlock()/munmap() path with page supposedly on the LRU.
+ *
+ * Note:  unlike mlock_vma_page(), we can't just clear the PageMlocked
+ * [in try_to_munlock()] and then attempt to isolate the page.  We must
+ * isolate the page to keep others from messing with its unevictable
+ * and mlocked state while trying to munlock.  However, we pre-clear the
+ * mlocked state anyway as we might lose the isolation race and we might
+ * not get another chance to clear PageMlocked.  If we successfully
+ * isolate the page and try_to_munlock() detects other VM_LOCKED vmas
+ * mapping the page, it will restore the PageMlocked state, unless the page
+ * is mapped in a non-linear vma.  So, we go ahead and SetPageMlocked(),
+ * perhaps redundantly.
+ * If we lose the isolation race, and the page is mapped by other VM_LOCKED
+ * vmas, we'll detect this in vmscan--via try_to_munlock() or try_to_unmap()
+ * either of which will restore the PageMlocked state by calling
+ * mlock_vma_page() above, if it can grab the vma's mmap sem.
+ */
+static void munlock_vma_page(struct page *page)
+{
+	BUG_ON(!PageLocked(page));
+
+	if (TestClearPageMlocked(page)) {
+		dec_zone_page_state(page, NR_MLOCK);
+		if (!isolate_lru_page(page)) {
+			int ret = try_to_munlock(page);
+			/*
+			 * did try_to_unlock() succeed or punt?
+			 */
+			if (ret == SWAP_SUCCESS || ret == SWAP_AGAIN)
+				count_vm_event(UNEVICTABLE_PGMUNLOCKED);
+
+			putback_lru_page(page);
+		} else {
+			/*
+			 * We lost the race.  let try_to_unmap() deal
+			 * with it.  At least we get the page state and
+			 * mlock stats right.  However, page is still on
+			 * the noreclaim list.  We'll fix that up when
+			 * the page is eventually freed or we scan the
+			 * noreclaim list.
+			 */
+			if (PageUnevictable(page))
+				count_vm_event(UNEVICTABLE_PGSTRANDED);
+			else
+				count_vm_event(UNEVICTABLE_PGMUNLOCKED);
+		}
+	}
+}
+
+/**
+ * __mlock_vma_pages_range() -  mlock/munlock a range of pages in the vma.
+ * @vma:   target vma
+ * @start: start address
+ * @end:   end address
+ * @mlock: 0 indicate munlock, otherwise mlock.
+ *
+ * If @mlock == 0, unlock an mlocked range;
+ * else mlock the range of pages.  This takes care of making the pages present ,
+ * too.
+ *
+ * return 0 on success, negative error code on error.
+ *
+ * vma->vm_mm->mmap_sem must be held for at least read.
+ */
+static long __mlock_vma_pages_range(struct vm_area_struct *vma,
+				   unsigned long start, unsigned long end,
+				   int mlock)
+{
+	struct mm_struct *mm = vma->vm_mm;
+	unsigned long addr = start;
+	struct page *pages[16]; /* 16 gives a reasonable batch */
+	int nr_pages = (end - start) / PAGE_SIZE;
+	int ret = 0;
+	int gup_flags = 0;
+
+	VM_BUG_ON(start & ~PAGE_MASK);
+	VM_BUG_ON(end   & ~PAGE_MASK);
+	VM_BUG_ON(start < vma->vm_start);
+	VM_BUG_ON(end   > vma->vm_end);
+	VM_BUG_ON((!rwsem_is_locked(&mm->mmap_sem)) &&
+		  (atomic_read(&mm->mm_users) != 0));
+
+	/*
+	 * mlock:   don't page populate if page has PROT_NONE permission.
+	 * munlock: the pages always do munlock althrough
+	 *          its has PROT_NONE permission.
+	 */
+	if (!mlock)
+		gup_flags |= GUP_FLAGS_IGNORE_VMA_PERMISSIONS;
+
+	if (vma->vm_flags & VM_WRITE)
+		gup_flags |= GUP_FLAGS_WRITE;
+
+	while (nr_pages > 0) {
+		int i;
+
+		cond_resched();
+
+		/*
+		 * get_user_pages makes pages present if we are
+		 * setting mlock. and this extra reference count will
+		 * disable migration of this page.  However, page may
+		 * still be truncated out from under us.
+		 */
+		ret = __get_user_pages(current, mm, addr,
+				min_t(int, nr_pages, ARRAY_SIZE(pages)),
+				gup_flags, pages, NULL);
+		/*
+		 * This can happen for, e.g., VM_NONLINEAR regions before
+		 * a page has been allocated and mapped at a given offset,
+		 * or for addresses that map beyond end of a file.
+		 * We'll mlock the the pages if/when they get faulted in.
+		 */
+		if (ret < 0)
+			break;
+		if (ret == 0) {
+			/*
+			 * We know the vma is there, so the only time
+			 * we cannot get a single page should be an
+			 * error (ret < 0) case.
+			 */
+			WARN_ON(1);
+			break;
+		}
+
+		lru_add_drain();	/* push cached pages to LRU */
+
+		for (i = 0; i < ret; i++) {
+			struct page *page = pages[i];
+
+			lock_page(page);
+			/*
+			 * Because we lock page here and migration is blocked
+			 * by the elevated reference, we need only check for
+			 * page truncation (file-cache only).
+			 */
+			if (page->mapping) {
+				if (mlock)
+					mlock_vma_page(page);
+				else
+					munlock_vma_page(page);
+			}
+			unlock_page(page);
+			put_page(page);		/* ref from get_user_pages() */
+
+			/*
+			 * here we assume that get_user_pages() has given us
+			 * a list of virtually contiguous pages.
+			 */
+			addr += PAGE_SIZE;	/* for next get_user_pages() */
+			nr_pages--;
+		}
+		ret = 0;
+	}
+
+	return ret;	/* count entire vma as locked_vm */
+}
+
+/*
+ * convert get_user_pages() return value to posix mlock() error
+ */
+static int __mlock_posix_error_return(long retval)
+{
+	if (retval == -EFAULT)
+		retval = -ENOMEM;
+	else if (retval == -ENOMEM)
+		retval = -EAGAIN;
+	return retval;
+}
+
+#else /* CONFIG_UNEVICTABLE_LRU */
+
+/*
+ * Just make pages present if VM_LOCKED.  No-op if unlocking.
+ */
+static long __mlock_vma_pages_range(struct vm_area_struct *vma,
+				   unsigned long start, unsigned long end,
+				   int mlock)
+{
+	if (mlock && (vma->vm_flags & VM_LOCKED))
+		return make_pages_present(start, end);
+	return 0;
+}
+
+static inline int __mlock_posix_error_return(long retval)
+{
+	return 0;
+}
+
+#endif /* CONFIG_UNEVICTABLE_LRU */
+
+/**
+ * mlock_vma_pages_range() - mlock pages in specified vma range.
+ * @vma - the vma containing the specfied address range
+ * @start - starting address in @vma to mlock
+ * @end   - end address [+1] in @vma to mlock
+ *
+ * For mmap()/mremap()/expansion of mlocked vma.
+ *
+ * return 0 on success for "normal" vmas.
+ *
+ * return number of pages [> 0] to be removed from locked_vm on success
+ * of "special" vmas.
+ */
+long mlock_vma_pages_range(struct vm_area_struct *vma,
+			unsigned long start, unsigned long end)
+{
+	int nr_pages = (end - start) / PAGE_SIZE;
+	BUG_ON(!(vma->vm_flags & VM_LOCKED));
+
+	/*
+	 * filter unlockable vmas
+	 */
+	if (vma->vm_flags & (VM_IO | VM_PFNMAP))
+		goto no_mlock;
+
+	if (!((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
+			is_vm_hugetlb_page(vma) ||
+			vma == get_gate_vma(current))) {
+
+		__mlock_vma_pages_range(vma, start, end, 1);
+
+		/* Hide errors from mmap() and other callers */
+		return 0;
+	}
+
+	/*
+	 * User mapped kernel pages or huge pages:
+	 * make these pages present to populate the ptes, but
+	 * fall thru' to reset VM_LOCKED--no need to unlock, and
+	 * return nr_pages so these don't get counted against task's
+	 * locked limit.  huge pages are already counted against
+	 * locked vm limit.
+	 */
+	make_pages_present(start, end);
+
+no_mlock:
+	vma->vm_flags &= ~VM_LOCKED;	/* and don't come back! */
+	return nr_pages;		/* error or pages NOT mlocked */
+}
+
+
+/*
+ * munlock_vma_pages_range() - munlock all pages in the vma range.'
+ * @vma - vma containing range to be munlock()ed.
+ * @start - start address in @vma of the range
+ * @end - end of range in @vma.
+ *
+ *  For mremap(), munmap() and exit().
+ *
+ * Called with @vma VM_LOCKED.
+ *
+ * Returns with VM_LOCKED cleared.  Callers must be prepared to
+ * deal with this.
+ *
+ * We don't save and restore VM_LOCKED here because pages are
+ * still on lru.  In unmap path, pages might be scanned by reclaim
+ * and re-mlocked by try_to_{munlock|unmap} before we unmap and
+ * free them.  This will result in freeing mlocked pages.
+ */
+void munlock_vma_pages_range(struct vm_area_struct *vma,
+			   unsigned long start, unsigned long end)
+{
+	vma->vm_flags &= ~VM_LOCKED;
+	__mlock_vma_pages_range(vma, start, end, 0);
+}
+
+/*
+ * mlock_fixup  - handle mlock[all]/munlock[all] requests.
+ *
+ * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
+ * munlock is a no-op.  However, for some special vmas, we go ahead and
+ * populate the ptes via make_pages_present().
+ *
+ * For vmas that pass the filters, merge/split as appropriate.
+ */
+static int mlock_fixup(struct vm_area_struct *vma, struct vm_area_struct **prev,
+	unsigned long start, unsigned long end, unsigned int newflags)
+{
+	struct mm_struct *mm = vma->vm_mm;
+	pgoff_t pgoff;
+	int nr_pages;
+	int ret = 0;
+	int lock = newflags & VM_LOCKED;
+
+	if (newflags == vma->vm_flags ||
+			(vma->vm_flags & (VM_IO | VM_PFNMAP)))
+		goto out;	/* don't set VM_LOCKED,  don't count */
+
+	if ((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
+			is_vm_hugetlb_page(vma) ||
+			vma == get_gate_vma(current)) {
+		if (lock)
+			make_pages_present(start, end);
+		goto out;	/* don't set VM_LOCKED,  don't count */
+	}
+
+	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
+	*prev = vma_merge(mm, *prev, start, end, newflags, vma->anon_vma,
+			  vma->vm_file, pgoff, vma_policy(vma));
+	if (*prev) {
+		vma = *prev;
+		goto success;
+	}
+
+	if (start != vma->vm_start) {
+		ret = split_vma(mm, vma, start, 1);
+		if (ret)
+			goto out;
+	}
+
+	if (end != vma->vm_end) {
+		ret = split_vma(mm, vma, end, 0);
+		if (ret)
+			goto out;
+	}
+
+success:
+	/*
+	 * Keep track of amount of locked VM.
+	 */
+	nr_pages = (end - start) >> PAGE_SHIFT;
+	if (!lock)
+		nr_pages = -nr_pages;
+	mm->locked_vm += nr_pages;
+
+	/*
+	 * vm_flags is protected by the mmap_sem held in write mode.
+	 * It's okay if try_to_unmap_one unmaps a page just after we
+	 * set VM_LOCKED, __mlock_vma_pages_range will bring it back.
+	 */
+	vma->vm_flags = newflags;
+
+	if (lock) {
+		ret = __mlock_vma_pages_range(vma, start, end, 1);
+
+		if (ret > 0) {
+			mm->locked_vm -= ret;
+			ret = 0;
+		} else
+			ret = __mlock_posix_error_return(ret); /* translate if needed */
+	} else {
+		__mlock_vma_pages_range(vma, start, end, 0);
+	}
+
+out:
+	*prev = vma;
+	return ret;
+}
+
+static int do_mlock(unsigned long start, size_t len, int on)
+{
+	unsigned long nstart, end, tmp;
+	struct vm_area_struct * vma, * prev;
+	int error;
+
+	len = PAGE_ALIGN(len);
+	end = start + len;
+	if (end < start)
+		return -EINVAL;
+	if (end == start)
+		return 0;
+	vma = find_vma_prev(current->mm, start, &prev);
+	if (!vma || vma->vm_start > start)
+		return -ENOMEM;
+
+	if (start > vma->vm_start)
+		prev = vma;
+
+	for (nstart = start ; ; ) {
+		unsigned int newflags;
+
+		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */
+
+		newflags = vma->vm_flags | VM_LOCKED;
+		if (!on)
+			newflags &= ~VM_LOCKED;
+
+		tmp = vma->vm_end;
+		if (tmp > end)
+			tmp = end;
+		error = mlock_fixup(vma, &prev, nstart, tmp, newflags);
+		if (error)
+			break;
+		nstart = tmp;
+		if (nstart < prev->vm_end)
+			nstart = prev->vm_end;
+		if (nstart >= end)
+			break;
+
+		vma = prev->vm_next;
+		if (!vma || vma->vm_start != nstart) {
+			error = -ENOMEM;
+			break;
+		}
+	}
+	return error;
+}
+
+SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
+{
+	unsigned long locked;
+	unsigned long lock_limit;
+	int error = -ENOMEM;
+
+	if (!can_do_mlock())
+		return -EPERM;
+
+	lru_add_drain_all();	/* flush pagevec */
+
+	down_write(&current->mm->mmap_sem);
+	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
+	start &= PAGE_MASK;
+
+	locked = len >> PAGE_SHIFT;
+	locked += current->mm->locked_vm;
+
+	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
+	lock_limit >>= PAGE_SHIFT;
+
+	/* check against resource limits */
+	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
+		error = do_mlock(start, len, 1);
+	up_write(&current->mm->mmap_sem);
+	return error;
+}
+
+SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
+{
+	int ret;
+
+	down_write(&current->mm->mmap_sem);
+	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
+	start &= PAGE_MASK;
+	ret = do_mlock(start, len, 0);
+	up_write(&current->mm->mmap_sem);
+	return ret;
+}
+
+static int do_mlockall(int flags)
+{
+	struct vm_area_struct * vma, * prev = NULL;
+	unsigned int def_flags = 0;
+
+	if (flags & MCL_FUTURE)
+		def_flags = VM_LOCKED;
+	current->mm->def_flags = def_flags;
+	if (flags == MCL_FUTURE)
+		goto out;
+
+	for (vma = current->mm->mmap; vma ; vma = prev->vm_next) {
+		unsigned int newflags;
+
+		newflags = vma->vm_flags | VM_LOCKED;
+		if (!(flags & MCL_CURRENT))
+			newflags &= ~VM_LOCKED;
+
+		/* Ignore errors */
+		mlock_fixup(vma, &prev, vma->vm_start, vma->vm_end, newflags);
+	}
+out:
+	return 0;
+}
+
+SYSCALL_DEFINE1(mlockall, int, flags)
+{
+	unsigned long lock_limit;
+	int ret = -EINVAL;
+
+	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE)))
+		goto out;
+
+	ret = -EPERM;
+	if (!can_do_mlock())
+		goto out;
+
+	lru_add_drain_all();	/* flush pagevec */
+
+	down_write(&current->mm->mmap_sem);
+
+	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
+	lock_limit >>= PAGE_SHIFT;
+
+	ret = -ENOMEM;
+	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
+	    capable(CAP_IPC_LOCK))
+		ret = do_mlockall(flags);
+	up_write(&current->mm->mmap_sem);
+out:
+	return ret;
+}
+
+SYSCALL_DEFINE0(munlockall)
+{
+	int ret;
+
+	down_write(&current->mm->mmap_sem);
+	ret = do_mlockall(0);
+	up_write(&current->mm->mmap_sem);
+	return ret;
+}
+
+/*
+ * Objects with different lifetime than processes (SHM_LOCK and SHM_HUGETLB
+ * shm segments) get accounted against the user_struct instead.
+ */
+static DEFINE_SPINLOCK(shmlock_user_lock);
+
+int user_shm_lock(size_t size, struct user_struct *user)
+{
+	unsigned long lock_limit, locked;
+	int allowed = 0;
+
+	locked = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
+	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
+	if (lock_limit == RLIM_INFINITY)
+		allowed = 1;
+	lock_limit >>= PAGE_SHIFT;
+	spin_lock(&shmlock_user_lock);
+	if (!allowed &&
+	    locked + user->locked_shm > lock_limit && !capable(CAP_IPC_LOCK))
+		goto out;
+	get_uid(user);
+	user->locked_shm += locked;
+	allowed = 1;
+out:
+	spin_unlock(&shmlock_user_lock);
+	return allowed;
+}
+
+void user_shm_unlock(size_t size, struct user_struct *user)
+{
+	spin_lock(&shmlock_user_lock);
+	user->locked_shm -= (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
+	spin_unlock(&shmlock_user_lock);
+	free_uid(user);
+}
diff --exclude=.git -Nru linux-2.6.28.7/mm/mmap.c linux-2.6.28.7-pms/mm/mmap.c
--- linux-2.6.28.7/mm/mmap.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/mm/mmap.c	2009-03-06 19:59:09.000000000 +0000
@@ -28,6 +28,8 @@
 #include <linux/rmap.h>
 #include <linux/mmu_notifier.h>
 
+#include <linux/hpc.h>
+
 #include <asm/uaccess.h>
 #include <asm/cacheflush.h>
 #include <asm/tlb.h>
@@ -203,9 +205,22 @@
 
 	flush_dcache_mmap_lock(mapping);
 	if (unlikely(vma->vm_flags & VM_NONLINEAR))
+	{
 		list_del_init(&vma->shared.vm_set.list);
+#ifdef CONFIG_PMS
+		if (list_empty(&vma->shared.vm_set.list))
+			pms_no_longer_monkey(file->f_dentry->d_inode);
+#endif /* CONFIG_PMS */
+	}
 	else
+	{
 		vma_prio_tree_remove(vma, &mapping->i_mmap);
+#ifdef CONFIG_PMS
+		/* FIXME tab: maybe wrong ! */
+		if (vma->shared.vm_set.parent && vma->shared.vm_set.head)
+			pms_no_longer_monkey(file->f_dentry->d_inode);
+#endif /* CONFIG_PMS */
+	}
 	flush_dcache_mmap_unlock(mapping);
 }
 
@@ -918,6 +933,9 @@
 	int error;
 	int accountable = 1;
 	unsigned long reqprot = prot;
+#ifdef CONFIG_PMS
+        int stay_reason = 0;
+#endif /* CONFIG_PMS */
 
 	/*
 	 * Does the application expect PROT_READ to imply PROT_EXEC?
@@ -949,8 +967,13 @@
                return -EOVERFLOW;
 
 	/* Too many mappings? */
+#ifdef CONFIG_PMS
+	if (mm && mm->map_count > sysctl_max_map_count)
+		return -ENOMEM;
+#else
 	if (mm->map_count > sysctl_max_map_count)
 		return -ENOMEM;
+#endif
 
 	/* Obtain the address to map to. we verify (or select) it and ensure
 	 * that it represents a valid section of the address space.
@@ -964,7 +987,11 @@
 	 * of the memory object, so we don't do any here.
 	 */
 	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
-			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
+#ifdef CONFIG_PMS
+			(mm ? mm->def_flags : 0) | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
+#else
+	       		mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
+#endif
 
 	if (flags & MAP_LOCKED) {
 		if (!can_do_mlock())
@@ -973,7 +1000,11 @@
 	}
 
 	/* mlock MCL_FUTURE? */
+#ifdef CONFIG_PMS
+	if (mm && vm_flags & VM_LOCKED) {
+#else
 	if (vm_flags & VM_LOCKED) {
+#endif
 		unsigned long locked, lock_limit;
 		locked = len >> PAGE_SHIFT;
 		locked += mm->locked_vm;
@@ -1007,9 +1038,19 @@
 			vm_flags |= VM_SHARED | VM_MAYSHARE;
 			if (!(file->f_mode & FMODE_WRITE))
 				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);
+#ifdef CONFIG_PMS
+			if (file->f_mode & FMODE_WRITE)
+				stay_reason |= DSTAY_MONKEY;
+#endif /* CONFIG_PMS */
 
 			/* fall through */
 		case MAP_PRIVATE:
+#ifdef CONFIG_PMS
+			if (inode && inode->i_mapping->i_mmap_writable != 0)
+				stay_reason |= DSTAY_MONKEY;
+			if (S_ISCHR(file->f_dentry->d_inode->i_mode))
+				stay_reason |= DSTAY_DEV;
+#endif /* CONFIG_PMS */
 			if (!(file->f_mode & FMODE_READ))
 				return -EACCES;
 			if (file->f_path.mnt->mnt_flags & MNT_NOEXEC) {
@@ -1050,6 +1091,10 @@
 	error = security_file_mmap(file, reqprot, prot, flags, addr, 0);
 	if (error)
 		return error;
+#ifdef CONFIG_PMS
+        if (file && task_test_dflags(current, DDEPUTY))
+                return deputy_do_mmap_pgoff(file, addr, len, prot, vm_flags, pgoff);
+#endif
 
 	return mmap_region(file, addr, len, flags, vm_flags, pgoff,
 			   accountable);
@@ -1101,6 +1146,9 @@
 	struct rb_node **rb_link, *rb_parent;
 	unsigned long charged = 0;
 	struct inode *inode =  file ? file->f_path.dentry->d_inode : NULL;
+#ifdef CONFIG_PMS
+        int stay_reason = 0;
+#endif /* CONFIG_PMS */
 
 	/* Clear old maps */
 	error = -ENOMEM;
@@ -1228,6 +1276,10 @@
 	if (correct_wcount)
 		atomic_inc(&inode->i_writecount);
 out:
+#ifdef CONFIG_PMS
+	if (stay_reason)
+		pms_stay_me_and_my_clones(stay_reason);
+#endif /* CONFIG_PMS */
 	mm->total_vm += len >> PAGE_SHIFT;
 	vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);
 	if (vm_flags & VM_LOCKED) {
@@ -1451,9 +1503,20 @@
 	unsigned long (*get_area)(struct file *, unsigned long,
 				  unsigned long, unsigned long, unsigned long);
 
+#ifdef CONFIG_PMS
+	if (task_test_dflags(current, DDEPUTY))
+		return PAGE_ALIGN(addr);
+#endif
 	get_area = current->mm->get_unmapped_area;
 	if (file && file->f_op && file->f_op->get_unmapped_area)
 		get_area = file->f_op->get_unmapped_area;
+#ifdef CONFIG_PMS
+	/* g_remlin FIXME */
+	if(!get_area) {
+		addr = PAGE_ALIGN(addr);
+	}
+	else
+#endif
 	addr = get_area(file, addr, len, pgoff, flags);
 	if (IS_ERR_VALUE(addr))
 		return addr;
diff --exclude=.git -Nru linux-2.6.28.7/net/socket.c linux-2.6.28.7-pms/net/socket.c
--- linux-2.6.28.7/net/socket.c	2009-02-20 22:41:27.000000000 +0000
+++ linux-2.6.28.7-pms/net/socket.c	2009-03-06 19:59:09.000000000 +0000
@@ -479,7 +479,7 @@
  *	NULL is returned.
  */
 
-static struct socket *sock_alloc(void)
+PMS_NSTATIC struct socket *sock_alloc(void)
 {
 	struct inode *inode;
 	struct socket *sock;
@@ -498,6 +498,9 @@
 	put_cpu_var(sockets_in_use);
 	return sock;
 }
+#if defined(CONFIG_KCOMD) || defined (CONFIG_KCOMD_MODULE)
+EXPORT_SYMBOL_GPL(sock_alloc);
+#endif
 
 /*
  *	In theory you can't get an open on this inode, but /proc provides

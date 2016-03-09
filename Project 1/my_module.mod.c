#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x5efc761b, "module_layout" },
	{ 0x70b5c985, "kmalloc_caches" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x25ec1b28, "strlen" },
	{ 0x4aabc7c4, "__tracepoint_kmalloc" },
	{ 0xdce1ce59, "remove_proc_entry" },
	{ 0x85df9b6c, "strsep" },
	{ 0x999e8297, "vfree" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x6f70124a, "kmem_cache_alloc_notrace" },
	{ 0x74322b69, "current_task" },
	{ 0xea147363, "printk" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x61651be, "strcat" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x19f306a2, "pv_cpu_ops" },
	{ 0x9dd08427, "create_proc_entry" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x37a0cba, "kfree" },
	{ 0x9edbecae, "snprintf" },
	{ 0x4f6b400b, "_copy_from_user" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "C1C563F4C5C196C31EB8ADB");

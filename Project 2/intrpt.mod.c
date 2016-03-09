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
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x25ec1b28, "strlen" },
	{ 0x78bb7c81, "queue_work" },
	{ 0x999e8297, "vfree" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xea147363, "printk" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb4390f9a, "mcount" },
	{ 0xfda85a7d, "request_threaded_irq" },
	{ 0x27212e9, "__create_workqueue_key" },
	{ 0x61651be, "strcat" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x9dd08427, "create_proc_entry" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x4f6b400b, "_copy_from_user" },
	{ 0xf20dabd8, "free_irq" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "66ADC37247B31EA71552EE4");

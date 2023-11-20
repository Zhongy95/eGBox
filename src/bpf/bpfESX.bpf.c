// SPDX-License-Identifier: GPL-2
//
// Copyright (C) 2021  William Findlay
//
// Jan. 19, 2021  William Findlay  Created this.

// This must be first
#include <vmlinux.h>

// These must be below vmlinux.h
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */

#include <helpers.h>
//#include <string.h>
#include <structs.h>
#include <linux/mman.h>
//#include <malloc.h>

#include <kernel_defs.h>
#define VM_SHARED	0x00000008
#include <audit.h>
#include <errno.h>

/* ========================================================================= *
 * BPF CO-RE Globals                                                         *
 * ========================================================================= */

static const struct path_t empty_path = {"\0"};
static const char split[2] ="/";

int mprotect_count = 0;
u8 audit_mode = 0;
u64 config_id = 0 ;
u32 esx_pid = 0;

struct fs_audit_event_t _fs_audit_event={0} ;
/* ========================================================================= *
 * BPF Maps                                                                  *
 * ========================================================================= */

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct fs_policy_key));
    __uint(value_size, sizeof(struct policy_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} fs_policies SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct fs_policy_key));
    __uint(value_size, sizeof(struct policy_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} fs_dir_policies SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct net_policy_key));
    __uint(value_size, sizeof(struct policy_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} net_policies SEC(".maps");



struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(map_flags, 0);
    __uint(pinning,0);
    __uint(max_entries, MAX_POLICY_SIZE);
} profile_config SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct procfs_policy_key_t));
    __uint(value_size, sizeof(struct policy_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} procfs_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AUDIT_RINGBUF_PAGES);
} fs_audit_events SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, AUDIT_RINGBUF_PAGES);
} audit_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(struct profile_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} profiles SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct process_t));
    __uint(max_entries, MAX_POLICY_SIZE);
} processes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size,sizeof(u64));
    __uint(value_size,sizeof(struct path_t));
    __uint(max_entries,MAX_POLICY_SIZE);
}paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} eventsss SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} comline_audit_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct comline_audit_event);
} execs SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(key_size,sizeof(u32));
    __uint(value_size,4096);
    __uint(max_entries,10240);
}fullpath SEC(".maps");


// ssh session data
struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct session_context_t));
    __uint(max_entries, 5000);
} session_context SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, USERNAME_MAX_LENGTH);
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 5000);
} user_profile_cookie SEC(".maps");

struct binary_context_t {
    u32 session_cookie;
    u32 binary_cookie;
};

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct binary_context_t));
    __uint(max_entries, 32000);
} pid_binary_context SEC(".maps");


/* ========================================================================= *
 * Kernel-Dependent Helpers                                                  *
 * ========================================================================= */

// TODO: Your version-dependent helpers here

/* ========================================================================= *
 * Helpers Functions                                                         *
 * ========================================================================= */

// TODO: Your helpers here
static __always_inline enum audit_level_t action_to_audit_level(enum action_t action)
{
    enum audit_level_t level = AUDIT__NONE;

    if (action & ACTION_DENY)
        level = AUDIT_DENY;
    if (action & ACTION_AUDIT)
        level = AUDIT_INFO;
    if (action & ACTION_COMPLAIN)
        level = AUDIT_WARN;

    if((action & (ACTION_ALLOW | ACTION_AUDIT)))
        level = AUDIT_ALLOW;


    return level;
}

static __always_inline int strcmp(const char *cs, const char *ct)
{
	unsigned char c1, c2;
	int res = 0;

	do {
		c1 = *cs++;
		c2 = *ct++;
		res = c1 - c2;
		if (res)
			break;
	} while (c1);
	return res;
}

//static __always_inline int strlen(const char *s)
//{
//	const char *sc = s;
//
//	while (*sc != '\0')
//		sc++;
//	return sc - s;
//}

static __always_inline int strlen(char *s)
{

    int i =0;
    for(i=0;i<32;i++)
    {
        if(s[i]=='\0')
            break;

        }
    return i;
}

static __always_inline void strcat(char *s1,char *s2,char *dst)
{
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    for(int i=0;i<len1+len2;i++)
    {
        if(i<len1)
            dst[i]=s1[i];
        else
            dst[i]=s2[i-len1];
    }


}

/* ========================================================================= *
 * BPF Programs                                                              *
 * ========================================================================= */
static __always_inline struct process_t *get_current_process()
{
    u32 pid = bpf_get_current_pid_tgid();
    return bpf_map_lookup_elem(&processes, &pid);
}


static __always_inline enum action_t policy_decision(struct policy_t *policy,
    u32 access)
{
    return ACTION_ALLOW;
    // Set deny action based on whether or not we are enforcing
// #ifndef BPFBOX_ENFORCING
    enum action_t deny_action = ACTION_DENY;
// #else
//     enum action_t deny_action = ACTION_DENY;
// #endif

    enum action_t allow_action = ACTION_ALLOW;

//    bool tainted = process->tainted;
//
//    // If we have no policy for this object, either deny or allow,
//    // depending on if the process is tainted or not
//    if (!policy)
//    {
//        if (tainted)
//        {
//            return deny_action;
//        }
//        else
//        {
//            return allow_action;
//        }
//    }

    // Set allow action based on whether or not we want to audit
    if ((access & policy->audit))
    {
        allow_action |= ACTION_AUDIT;
    }

    // Taint process if we hit a taint rule
    //if (!tainted && (access & policy->taint) )
    //{
        //process->tainted = 1;
    //    return allow_action | ACTION_TAINT;
    //}

    // If we are not tainted

    //if (!tainted)
    //{
    //    return allow_action;
    //}

    // If we are tainted, but the operation is allowed
    if (access & policy->allow)
    {
        return deny_action;
    }

    // Default deny
    return deny_action;
}

static __always_inline struct process_t *get_process(u32 pid)
{
    struct process_t *ptr = bpf_map_lookup_elem(&processes, &pid);
    return ptr;
}

/* Linux prot mask to bpfbox access */
static __always_inline enum fs_access_t prot_mask_to_access(int mask,
                                                                   bool shared)
{
    enum fs_access_t access = 0;

    if (mask & PROT_READ) {
        access |= FS_READ;
    }

    if (shared && (mask & PROT_WRITE)) {
        access |= FS_WRITE;
    }

    if (mask & PROT_EXEC) {
        access |= FS_EXEC;
    }

    return access;
}


static __always_inline struct process_t *create_process(
    u32 pid, u32 tgid,u32 uid,u64 config_id, bool tainted)
{
    struct process_t new_process = {};
    new_process.pid = pid;
    new_process.tgid = tgid;
    //new_process.profile_key = profile_key;
//    new_process.config_id = config_id;
    new_process.tainted = tainted;
    new_process.uid = uid;

    bpf_map_update_elem(&processes, &pid, &new_process, BPF_NOEXIST);
    return bpf_map_lookup_elem(&processes, &pid);
}

static __always_inline struct profile_t *create_profile(u64 profile_key,u8 taint_on_exec)
{
    struct profile_t new_profile = {};
    new_profile.taint_on_exec = taint_on_exec;

    bpf_map_update_elem(&profiles,&profile_key,&new_profile,BPF_NOEXIST);
    return bpf_map_lookup_elem(&profiles,&profile_key);
}


/* =========================================================================
 * 追踪进程创建
 * ========================================================================= */

//SEC("lsm/bprm_committing_creds")
//int BPF_PROG(bprm_committing_creds, struct linux_binprm *bprm)
//{
//    struct process_t *process;
//    struct profile_t *profile;
//
//    /* Calculate profile_key by taking inode number and filesystem device
//     * number together */
//    u64 st_ino = (u64)bprm->file->f_path.dentry->d_inode->i_ino;
//    u64 st_dev =         ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
//                          << 16);
//    u64 profile_key =
//        (u64)bprm->file->f_path.dentry->d_inode->i_ino |
//        ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
//         << 16);
//
//    u32 pid = bpf_get_current_pid_tgid();
//    u32 tgid = bpf_get_current_pid_tgid() >> 32;
//    bpf_printk("bprm pid:%d(%d) ", pid,tgid);
//    profile = bpf_map_lookup_elem(&profiles, &profile_key);
//
////    u64 *config_idt;
////    u64 profile_keyt = 138346498;
////    config_idt = bpf_map_lookup_elem(&profile_config,&profile_keyt);
////    if (!config_idt)
////    {
////        bpf_printk("no config_idt ");
////        return 0;
////    }
////
////    bpf_printk("profile key %u config_idt %u exist,config_id = %u",profile_keyt,*config_idt,config_id);
//
//    if (!profile)
//    {
//        bpf_printk("no profile %d,st_dev %d,st_ino %d",profile_key,st_dev,st_ino);
//        return 0;
//    }
//    //u64 config_id;
//    //config_id = bpf_map_lookup_elem(&profile_config, &profile_key);
//
//
//
//    u32 uid = bpf_get_current_uid_gid();
//    bpf_printk("bprm profile:%d ,config:%d", profile_key,config_id);
//    process = create_process(pid, tgid,uid,config_id, profile->taint_on_exec);
//    if (!process)
//    {
//        bpf_printk("Failed to create process by bprm");
//    }
//    else{
//        bpf_printk("successfully  create process %d by bprm",pid);
//    }
//
//    return 0;
//}

SEC("tp_btf/sched_process_fork")
int sched_process_fork(struct bpf_raw_tracepoint_args *args){
    struct task_struct *parent = (struct task_struct *)args->args[0];
    struct task_struct *child  = (struct task_struct *)args->args[1];

    u32 ppid = parent->pid;
    u32 cpid = child->pid;
    u32 ctgid = bpf_get_current_pid_tgid() >> 32;

    //if confining parent
    struct process_t *parent_process = bpf_map_lookup_elem(&processes,&ppid);

    if(!parent_process){
        return 0;
    }

    //Create child process
    struct process_t *process;
    bpf_printk("fork, parent:%d,child:%d",ppid,cpid);
    u32 uid = bpf_get_current_uid_gid();

    process = create_process(cpid,ctgid,uid,parent_process->config_id,parent_process->tainted);

//    if (!process) {
//            // TODO log error
//        } else{
//    }


    return 0;
}
/* Propagate a process' policy_id to its children */
/* Gabage collector */
SEC("tp_btf/sched_process_exit")
int sched_process_exit(struct bpf_raw_tracepoint_args *args)
{
    struct task_struct *task = (struct task_struct *)args->args[0];

    u32 pid = task->pid;

    struct process_t *parent_process = bpf_map_lookup_elem(&processes,&pid);

    if(!parent_process)
        return 0;

    bpf_map_delete_elem(&processes,&pid);


//    remove_process_from_container(container, task->pid);

    return 0;
}


// =======
// 文件系统
// =======


static __always_inline void audit_fs(u32 pid, enum action_t action, struct inode *inode, access_t access)
{
    FILTER_AUDIT(action);
    struct fs_audit_event_t *event = bpf_ringbuf_reserve(&fs_audit_events, sizeof(struct fs_audit_event_t), BPF_ANY);
    DO_AUDIT_COMMON(event, pid, action,config_id);

    event->st_ino = inode->i_ino;
    event->st_dev = (u32)inode->i_sb->s_dev;
    bpf_probe_read_str(event->s_id, sizeof(event->s_id), inode->i_sb->s_id);
    bpf_ringbuf_submit(event, BPF_ANY);
    bpf_printk("audit_fs active,pid %d",pid);
}



//static __always_inline char *get_path_from_dent(struct dentry *dent,char* buffer)
//{
//    if(dent == NULL)
//        return NULL;
//    struct list_head* plist = NULL;
//    struct dentry* tmp = NULL;
//
//	struct dentry* parent = NULL;
//	char* name = NULL;
//	char* pbuf = buffer + PATH_MAX - 1;
//	bpf_probe_read_kernel(pinode,sizeof(struct inode),inod);
//	int length = 0;
//
//    buffer[PATH_MAX - 1] ='\0';
//    if(pinode == NULL)
//        return NULL;
//    struct hlist_node* first = NULL;
//    bpf_probe_read(first,sizeof(struct hlist_node),&(pinode->i_dentry.first));
//    list_for_each(plist,first)
//    {
//        tmp = list_entry(plist,struct dentry,d_u.d_alias);
//        if(tmp->d_inode == pinode)
//        {
//            dent = tmp;
//            break;
//        }
//    }
//    if(dent == NULL)
//    {
//        return NULL;
//    }
//    bpf_probe_read_str(&name,PATH_MAX, dent->d_name.name);
//    name = name + strlen(name) - 4;
//    if(!strcmp(name,".img"))
//    {
//        while(pinode && pinode->i_ino !=2 && pinode->i_ino !=1)
//        {
//            if(dent == NULL)
//                break;
//            bpf_probe_read_str(&name,PATH_MAX, dent->d_name.name);
//            pbuf = pbuf - strlen(name) -1;
//            *pbuf = '/';
//            memcpy1(pbuf+1,name,strlen(name));
//            length += strlen(name) + 1;
//            if(parent != dent->d_parent)
//            {
//                dent = parent;
//                pinode = dent->d_inode;
//            }
//        }
//
//    bpf_trace_printk("get full path:%s",*pbuf);
//    }
//    return pbuf;
//}




static __always_inline u64 calculate_profile_key(u64 st_ino,u64 st_dev)
{
    return (st_ino | (st_dev <<16));
}



static __always_inline struct fs_policy_key create_fs_policy_key(struct inode *inode)
{
    u64 profile_keyt = calculate_profile_key((u64)(inode->i_ino),(u64)(new_encode_dev(inode->i_sb->s_dev)));
    u64 ugid = bpf_get_current_uid_gid();
    u32 uid = ugid & 0xFFFFFFFF;
    struct fs_policy_key key = {
            .config_id= config_id,
            .device_id = (u64)(new_encode_dev(inode->i_sb->s_dev)),
            .profile_key = profile_keyt,
            .uid = uid,
    };
    return key;
}

static __always_inline enum action_t fs_dir_policy_decision(enum fs_access_t access,struct dentry *dent)
{
    struct dentry *dir_dent = dent->d_parent;
    struct inode* dir_inode = dir_dent->d_inode;
    struct fs_policy_key key = create_fs_policy_key(dir_inode);
    struct policy_t *dir_fs_policy = bpf_map_lookup_elem(&fs_dir_policies,&key);
    // if dir is added, then return result
    if (dir_fs_policy){
        return policy_decision(dir_fs_policy,access);
    }

    if (dir_dent == dent){
        // already loop to root
        return 0;
    }

    return 0;
}

static __always_inline enum action_t fs_policy_decision(struct inode *inode, enum fs_access_t access,struct dentry *dent)
{
    u32 pid = bpf_get_current_pid_tgid();
    // guarantee the privilege of esx
    if (pid == esx_pid)
    {
        return 0;
    }

    // check directory privileged
    int dir_len = 64;
    enum action_t dir_action = ACTION_NONE;
    do{
        dir_action = fs_dir_policy_decision(access,dent);
        if(dir_action != ACTION_NONE){
            return dir_action;
        }
        dent = dent->d_parent;
        dir_len --;
    }while (dir_len >=0 && dent->d_parent !=dent);

    dir_action = fs_dir_policy_decision(access,dent);
    if(dir_action != ACTION_NONE){
        return dir_action;
    }

    u64 profile_keyt = calculate_profile_key((u64)(inode->i_ino),(u64)(new_encode_dev(inode->i_sb->s_dev)
                                                                                                    ));
    u64 profile_key_all = 0;
    u64 ugid = bpf_get_current_uid_gid();
    u32 gid = ugid >> 32;
    u32 uid = ugid & 0xFFFFFFFF;
    struct fs_policy_key key = create_fs_policy_key(inode);


//    struct fs_policy_key key = {
//        .config_id= config_id,
//        .device_id = (u64)(new_encode_dev(inode->i_sb->s_dev)),
//        .profile_key = profile_keyt,
//        .uid = uid,
//    };
    s32 topuid = -1;
    u32 u_topuid = (u32)topuid;
    struct fs_policy_key keyal = {
            .config_id= config_id,
            .device_id = (u64)(new_encode_dev(inode->i_sb->s_dev)),
            .profile_key = profile_keyt,
            .uid = u_topuid,
    };

    struct fs_policy_key key_all_path = {
        .config_id= config_id,
        .device_id = (u64)profile_key_all,
        .profile_key = profile_key_all,
        .uid = uid,
    };


    struct policy_t *policy = bpf_map_lookup_elem(&fs_policies, &key);
    struct policy_t *top_policy = bpf_map_lookup_elem(&fs_policies,&keyal);
    struct policy_t *policy_all_path = bpf_map_lookup_elem(&fs_policies,&key_all_path);
    if(top_policy)
    {
        bpf_printk("top_fs_policy_key existed , profile_key:%d,dev_id:%d",profile_keyt,(u64)(new_encode_dev(inode->i_sb->s_dev)));
        return policy_decision(top_policy,access);
    }else if (policy_all_path){
        return policy_decision(policy_all_path,access);
    }
    if(!policy)
    {
//        enum action_t deny_action = ACTION_DENY;
        return 0;
    }
    else{
//        bpf_printk("fs_policy_key existed , profile_key:%d,dev_id:%d",profile_keyt,(u64)(new_encode_dev(inode->i_sb->s_dev)));
//        bpf_printk("policy.allow : %x,policy.audit : %x",policy->allow,policy->audit);
    }
    return policy_decision(policy, access);
}
static __always_inline void get_fullpath_dent(struct dentry *dent)
{
    struct dentry *dentmp = dent;

    struct inode *inode = dentmp->d_inode;
    u64 profile_key = calculate_profile_key((u64)(inode->i_ino),(u64)(new_encode_dev(inode->i_sb->s_dev)));
    struct path_t *patht = bpf_map_lookup_elem(&paths,&profile_key);
    if(patht)
        return;
    if(bpf_map_update_elem(&paths,&profile_key,&empty_path, BPF_NOEXIST))
        return;
    struct path_t *path;
    path = bpf_map_lookup_elem(&paths,&profile_key);
    if(!path)
        return;
    path->st_ino = (u64)(inode->i_ino);
    path->st_dev = (u64)(new_encode_dev(inode->i_sb->s_dev));
    path->pathsize = 0;
    path->count = 0;
    long ret = 0;
//    char buffert[DNAME_INLINE_LEN];
    if(dentmp->d_iname!=NULL)
    {
        ret = bpf_probe_read_kernel_str(path->fullpath,DNAME_INLINE_LEN,dentmp->d_iname);

        path->pathsize += (ret-1);
        // the directory maximum here is set as 256, maybe longer in future
        if(path->pathsize>=0 && path->pathsize<256)
        {
            ret = bpf_probe_read_str(&path->fullpath[path->pathsize],DNAME_INLINE_LEN,&split);
//            path->pathsize += ret-1;
            }
//        bpf_printk("first path=%s , ret = %d",path->fullpath,ret);
        path->pathsize++;
        path->count ++;
        int count = 1;


        do {
//            bpf_probe_read_kernel_str(buffert,DNAME_INLINE_LEN,dentmp->d_iname);
//            if(dentmp==NULL){
//                break;
//            }
//            struct dentry* dentparent = dentmp->d_parent;
//            if (dentparent ==NULL){
//                break;
//            }
//
//            if(dentmp == (struct dentry*)dentmp->d_parent){
//                break;
//            }
//            if (dentmp != dentmp->d_parent){
//                dentmp = dentparent;
//            }
            dentmp = (struct dentry *)dentmp->d_parent;

            if(!dentmp->d_iname)
               break;
            if(path->pathsize>256)
               break;
            unsigned int pathsizetmp = path->pathsize;
            if(pathsizetmp>=0 && pathsizetmp<256){

                ret = bpf_probe_read_kernel_str(&path->fullpath[pathsizetmp],DNAME_INLINE_LEN,dentmp->d_iname);

                path->pathsize += (ret-1);
            }
            if((path->pathsize>=0) && (path->pathsize<256))
            {
                ret = bpf_probe_read_str(&path->fullpath[path->pathsize],DNAME_INLINE_LEN,&split);
                path->pathsize += (ret-1);
            }
            path->count++;
            count++;
//            bpf_printk("path name section:%s,ret=%d,count=%d",buffert,ret,count);
        }while(count<60 && dentmp != dentmp->d_parent);
//        bpf_printk("full path namenew:%s,length = %d",&path->fullpath,path->pathsize);
    }
}




static __always_inline void audit_fs1(u32 pid, enum action_t action, struct dentry *dentry,enum fs_access_t access)
{
//    FILTER_AUDIT(action);

    if ((action & (ACTION_COMPLAIN | ACTION_DENY | ACTION_AUDIT)) && (action & ACTION_ALLOW))
    {
        return;
    }
    struct dentry *dentmp = dentry;
    struct inode *inode = dentry->d_inode;
    struct audit_event_t *event = bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event_t), BPF_ANY);
    u64 profile_key = calculate_profile_key ((u64)(inode->i_ino),(u64)(new_encode_dev(inode->i_sb->s_dev)));

    char buffert[DNAME_INLINE_LEN];

    if(event){
        event->file.access = access;
        enum audit_type_t type = AUDIT_TYPE_FILE;
        //    do_audit_common(event,pid,tgid,action,type);
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        event->uid = bpf_get_current_uid_gid();
        event->gid = bpf_get_current_uid_gid() >> 32;
        event->pid = pid;
        event->tgid = pid;
        event->config_id = config_id;
        event->type = type;
        enum audit_level_t level = action_to_audit_level(action);
        event->level = action_to_audit_level(action);
        struct path_t *patht;
        patht = bpf_map_lookup_elem(&paths,&profile_key);
        if(!patht)
        {
            get_fullpath_dent(dentry);
            patht = bpf_map_lookup_elem(&paths,&profile_key);
            }
//        event->file.path = *patht;
        bpf_probe_read(&(event->file.path),sizeof(struct path_t),patht);


        bpf_ringbuf_submit(event, BPF_ANY);
    }

}

static __always_inline enum fs_access_t file_mask_to_access(int mask)
{
    enum fs_access_t access = 0;

    if (mask & MAY_READ)
    {
        access |= FS_READ;
    }

    // Appending and writing are mutually exclusive,
    // but MAY_APPEND is typically seen with MAY_WRITE
    if (mask & MAY_APPEND)
    {
        access |= FS_APPEND;
    }
    else if (mask & MAY_WRITE)
    {
        access |= FS_WRITE;
    }

    if (mask & MAY_EXEC)
    {
        access |= FS_EXEC;
    }

    return access;
}




// 进程相关inode访问，如/proc/{pid}下的资源
SEC("lsm/inode_create")
int BPF_PROG(inode_create, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum action_t action = fs_policy_decision( dir, FS_WRITE,dentry);
    enum fs_access_t access = FS_WRITE;

    audit_fs1(pid,action,dentry,access);
    return action & ACTION_DENY ? -EPERM : 0;
}

// 进程相关inode访问，如/proc/{pid}下的资源
SEC("lsm/inode_symlink")
int BPF_PROG(inode_symlink, struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum action_t action = fs_policy_decision( dir, FS_WRITE,dentry);
//    audit_fs(pid, action, dir, FS_WRITE);
    enum fs_access_t access = FS_WRITE;

    audit_fs1(pid,action,dentry,access);
    return action & ACTION_DENY ? -EPERM : 0;
}


SEC("lsm/inode_mkdir")
int BPF_PROG(inode_mkdir,struct inode *dir,struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum action_t action = fs_policy_decision(dir,FS_WRITE,dentry);

    enum fs_access_t access = FS_WRITE;

    audit_fs1(pid,action,dentry,access);

    return action & ACTION_DENY ? -EPERM: 0;

}

SEC("lsm/inode_rmdir")
int BPF_PROG(inode_rmdir,struct inode *dir,struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }
    enum action_t action = fs_policy_decision(dir,FS_DELETE,dentry);
//    audit_fs(pid,action,dir,FS_DELETE);
    enum fs_access_t access = FS_DELETE;

    audit_fs1(pid,action,dentry,access);

    return action & ACTION_DENY ? -EPERM: 0;
}


/* A task attempts to create a hard link from @old_dentry to @dir/@new_dentry */
SEC("lsm/inode_link")
int BPF_PROG(inode_link,struct dentry *old_dentry,struct inode *dir,struct dentry *new_dentry)
{
     u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

     enum action_t action = fs_policy_decision(dir,FS_WRITE,old_dentry);
     audit_fs(pid,action,dir,FS_WRITE);
     if(action & ACTION_DENY){
        return -EPERM;
     }

     struct inode *old_inode = old_dentry->d_inode;

     action = fs_policy_decision(old_inode,FS_LINK,old_dentry);
     audit_fs(pid,action,old_inode,FS_LINK);
     enum fs_access_t access = FS_LINK;

     audit_fs1(pid,action,old_dentry,access);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(inode_unlink,  struct inode *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();
    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }


    enum action_t action = fs_policy_decision(dir,FS_WRITE,dentry);
    audit_fs(pid,action,dir,FS_WRITE);
    if(action & ACTION_DENY){
        return -EPERM;
    }

    struct inode *inode = dentry->d_inode;
    
    action = fs_policy_decision( inode, FS_DELETE,dentry);

    enum fs_access_t access = FS_DELETE;

    audit_fs1(pid,action,dentry,access);
    return action & ACTION_DENY ? -EPERM : 0;
}


SEC("lsm/inode_setattr")
int BPF_PROG(inode_setattr,struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = dentry->d_inode;

    enum action_t action = fs_policy_decision(inode,FS_CHMOD,dentry);
//    audit_fs(pid,action,inode,FS_CHMOD);
    enum fs_access_t access = FS_CHMOD;

    audit_fs1(pid,action,dentry,access);

    return action & ACTION_DENY ? -EPERM :0;
}

/* A task attempts to change an extended attribute of @dentry */
SEC("lsm/inode_setxattr")
int BPF_PROG(inode_setxattr,struct user_namespace *mnt_userns,struct dentry *dentry,const char *name, const void *value,
             size_t size, int flags)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }


    struct inode *inode = dentry->d_inode;

    enum action_t action = fs_policy_decision(inode,FS_CHMOD,dentry);
//    audit_fs(pid,action,inode,FS_CHMOD);
    enum fs_access_t access = FS_CHMOD;

    audit_fs1(pid,action,dentry,access);
    return action & ACTION_DENY ? -EPERM :0;
}




/* A task attempts to read an attribute of @path */
SEC("lsm/inode_getattr")
int BPF_PROG(inode_getattr,struct path *path)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = path->dentry->d_inode;
    if(!pid){
        return 0;
    }

    if(inode == NULL)
        return 0;
    enum fs_access_t access = FS_GETATTR;
    enum action_t action = fs_policy_decision(inode,FS_GETATTR,path->dentry);
//    audit_fs(pid,action,inode,FS_GETATTR);
    audit_fs1(pid,action,path->dentry,access);



    return action & ACTION_DENY ? -EPERM :0;
}




/* Access to create a file under the path. */
SEC("lsm/path_mknod")
int BPF_PROG(path_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = dir->dentry->d_inode;

    enum fs_access_t access = FS_APPEND;
    enum action_t action = fs_policy_decision(inode,access,dir->dentry);


    audit_fs1(pid,action,dir->dentry,access);


    return action & ACTION_DENY ? -EPERM :0;
}

/* Access to make a dir under the path. */
SEC("lsm/path_mkdir")
int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = dir->dentry->d_inode;

    enum fs_access_t access = FS_APPEND;
    enum action_t action = fs_policy_decision(inode,access,dir->dentry);


    audit_fs1(pid,action,dir->dentry,access);


    return action & ACTION_DENY ? -EPERM :0;
}

/* Access to make a symlink under the path. */
SEC("lsm/path_symlink")
int BPF_PROG(path_symlink, const struct path *dir, struct dentry *dentry,const char *old_name)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = dir->dentry->d_inode;

    enum fs_access_t access = FS_APPEND;
    enum action_t action = fs_policy_decision(inode,access,dir->dentry);


    audit_fs1(pid,action,dir->dentry,access);


    return action & ACTION_DENY ? -EPERM :0;
}

/* Access to make a hard link under the path. */
SEC("lsm/path_link")
int BPF_PROG(path_link, struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    struct inode *inode = old_dentry->d_inode;

    // determine path append
    enum fs_access_t access = FS_APPEND;
    enum action_t action = fs_policy_decision(inode,access,new_dir->dentry);
    audit_fs1(pid,action,new_dir->dentry,access);
    if (action & ACTION_DENY){
        return -EPERM;
    }



    // determine inode link
    access = FS_LINK;
    action = fs_policy_decision(old_dentry->d_inode,access,old_dentry);
    audit_fs1(pid,action,old_dentry,access);



    return action & ACTION_DENY ? -EPERM :0;
}

/* Access to rename a file or path. */
SEC("lsm/path_rename")
int BPF_PROG(path_rename, const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    // determine path delete
    enum fs_access_t access = FS_DELETE;
    enum action_t action = fs_policy_decision(old_dentry->d_inode,access,old_dentry);
    audit_fs1(pid,action,old_dentry,access);
    if (action & ACTION_DENY){
        return -EPERM;
    }



    // determine the path append
    access = FS_APPEND;
    action = fs_policy_decision(new_dir->dentry->d_inode,access,new_dir->dentry);
    audit_fs1(pid,action,new_dir->dentry,access);



    return action & ACTION_DENY ? -EPERM :0;
}


/* Access to truncate a file. */
SEC("lsm/path_truncate")
int BPF_PROG(path_truncate, const struct path *path)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum fs_access_t access = FS_WRITE;
    enum action_t action = fs_policy_decision(path->dentry->d_inode,access,path->dentry);
    audit_fs1(pid,action,path->dentry,access);


    return action & ACTION_DENY? -EPERM :0;
}

/* Access to chmod a file or a directory. */
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path)
{
    u32 pid = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }
    enum fs_access_t access = FS_CHMOD;
    enum action_t action = fs_policy_decision(path->dentry->d_inode,access,path->dentry);
    audit_fs1(pid,action,path->dentry,access);


    return action & ACTION_DENY? -EPERM :0;

}



// 进程相关inode访问，如/proc/{pid}下的资源
//SEC("lsm/task_to_inode")
//int BPF_PROG(task_to_inode, struct task_struct *target, struct inode *inode)
//{
//    u32 pid = bpf_get_current_pid_tgid();
//
//    u32 tgid = bpf_get_current_pid_tgid() >> 32;
//
//    struct process_t *p = get_process(pid);
//    if (!p)
//    {
//        return 0;
//    }
//
//    struct fs_policy_key_t key = {
//
//        .st_dev = (u32)inode->i_sb->s_dev,
//        .config_id = p->config_id,
//    };
//    struct policy_t policy = {};
//
//    bpf_printk("task_to_inode pid:%d ", pid);
//    // 允许进程访问自己的资源
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//    if (task == target)
//    {
//        policy.allow =
//            FS_READ | FS_WRITE | FS_APPEND | FS_EXEC | FS_GETATTR | FS_CHMOD;
//        bpf_map_update_elem(&fs_policy, &key, &policy, BPF_ANY);
//        return 0;
//    }
//
//  //   查询目标子进程
//    u32 target_pid = target->pid;
//    struct process_t *sp = get_process(target_pid);
//    if (!sp)
//    {
//        return 0;
//    }
//    struct procfs_policy_key_t pfs_key = {
//        .subject_profile_key = p->profile_key,
//        .object_profile_key = sp->profile_key,
//    };
//    struct policy_t *pfs_policy = bpf_map_lookup_elem(&procfs_policy, &pfs_key);
//    if (!pfs_policy)
//    {
//        return 0;
//    }
//    policy.allow = pfs_policy->allow;
//    policy.taint = pfs_policy->taint;
//    policy.audit = pfs_policy->audit;
//
//
//    bpf_map_update_elem(&fs_policy, &key, &policy, BPF_ANY);
//    return 0;
//}

//SEC("lsm/file_permission")
//int BPF_PROG(forbid_inode_create, struct file *file, int mask, int ret)
//{
//    __u64 ugid = bpf_get_current_uid_gid();
//    __u32 gid = ugid >> 32;
//    __u32 uid = ugid & 0xFFFFFFFF;
//
//    if (ret != 0 || uid == 0)
//        return ret;
//
//    u64 st_ino = (u64)file->f_path.dentry->d_inode->i_ino;
//    u64 st_dev = (new_encode_dev(file->f_path.dentry->d_inode->i_sb->s_dev)
//                              );
//
//
//    st_dev = st_dev << 16;
//    u64 profile_key = st_ino | st_dev;
//
////    if(uid !=1000)
////        return 0;
//
//
//
//    __u32 pid = bpf_get_current_pid_tgid() >> 32;
//    // struct task_struct *task_ptr = (struct task_struct *)bpf_get_current_task();
//
////    char match_name[] = "ls";
////    char path_name[20] = {};
////    bpf_get_current_comm(path_name, sizeof(path_name));
////    for (int i = 0; i < sizeof(match_name); i++)
////    {
////        if (path_name[i] != match_name[i])
////        {
////            return 0;
////        }
////    }
////    if(profile_key != 138346498)
////            return 0;
//
//    enum action_t action = fs_policy_decision(file->f_path.dentry->d_inode,FS_READ);
//    //bpf_printk("file permission %d,st_ino %d,action = ",profile_key,st_ino,action);
//    audit_fs(pid, action, file->f_path.dentry->d_inode, FS_READ);
////    if(profile_key == 138346498)
////        return -EPERM;
//
//
////    bpf_printk("uid:%d(%d)\t mask:%d", uid, gid, mask);
////    bpf_printk("pid:%d,name:%s", pid, path_name);
////    bpf_printk("filename:%s,fmode:%x", file->f_path.dentry->d_name.name, file->f_mode);
////    bpf_printk("iname:%s", file->f_path.dentry->d_iname);
////    bpf_printk("mntname:%s", file->f_path.mnt->mnt_root->d_name.name);
//
////    if (uid == 1000)
////    {
////        return -EPERM;
////    }
//
//mismatch:
//    // bpf_printk("pid:%d,name:%s", pid, path_name);
//    return 0;
//}


/* =========================================================================
 * mmap Policy
 * ========================================================================= */
//SEC("lsm/mmap_file")
//int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,unsigned long prot, unsigned long flags)
//{
//
//    u32 pid = bpf_get_current_pid_tgid();
//    //only monitor process triggered by SSH session
//    struct process_t *process = get_process(pid);
//    if(!process){
//        return 0;
//    }
//
//    if(!file)
//    {
//        return 0;
//    }
//
//    struct inode *inode = file->f_inode;
//
//    enum fs_access_t access = prot_mask_to_access(prot, (flags & MAP_TYPE) == MAP_SHARED);
//
//    if(!access)
//    {
//        return 0;
//    }
//
//    enum action_t action = fs_policy_decision(inode,access,file->);
//    audit_fs(pid,action,inode,access);
//
//    return action & ACTION_DENY ? -EPERM : 0;
//}
//
//
//SEC("lsm/file_mprotect")
//int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
//                       unsigned long prot)
//{
//    u32 pid = bpf_get_current_pid_tgid();
//    //only monitor process triggered by SSH session
//    struct process_t *process = get_process(pid);
//    if(!process){
//        return 0;
//    }
//
//    if (!vma) {
//            return 0;
//        }
//
//    struct file *file = vma->vm_file;
//
//    struct inode *inode = file->f_inode;
//
//    enum fs_access_t access = prot_mask_to_access(prot, vma->vm_flags & VM_SHARED);
//
//    if(!access)
//    {
//        return 0;
//    }
//
//    enum action_t action = fs_policy_decision(inode,access);
//    audit_fs(pid,action,inode,access);
//
//    return action & ACTION_DENY ? -EPERM : 0;
//}

/* ========================================================================= *
 * Network Policy                                                            *
 * ========================================================================= */

static __always_inline u8 family_to_category(int family)
{

    switch (family) {
    case AF_UNIX:
        return NET_IPC;
        break;
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
        return NET_WWW;
        break;
    default:
        return 0;
    }
}

static __always_inline void do_audit_common(struct audit_event_t *event,u32 pid,u32 tgid,enum action_t action,enum audit_type_t type)
{
    if(!event)
        return ;
    bpf_get_current_comm(&event->comm,sizeof(event->comm));
    event->uid = bpf_get_current_uid_gid();
    event->pid = pid;
    event->tgid = tgid;
    event->config_id = config_id;
    event->type = type;

    event->level = action_to_audit_level(action);

}


static __always_inline void audit_net(u32 pid,u32 tgid, enum action_t action,enum net_operation_t op)
{
//    FILTER_AUDIT(action);

    struct audit_event_t *event = bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event_t), BPF_ANY);
    if(!event)
        return;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
//    DO_AUDIT_COMMON(event, pid, action,config_id);
    if(event){
            event->net.operation = op;
        }
    enum audit_type_t type = AUDIT_TYPE_NET;
//    do_audit_common(event,pid,tgid,action,type);

    event->uid = bpf_get_current_uid_gid();
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->pid = pid;
    event->tgid = tgid;
    event->config_id = config_id;
    event->type = type;
    enum audit_level_t level = action_to_audit_level(action);
    event->level = action_to_audit_level(action);
    bpf_ringbuf_submit(event, BPF_ANY);
//    bpf_ringbuf_output(&audit_events,event,sizeof(*event),0);
//    bpf_printk("audit_net active,action%d,level %d",action,level);
}

static __always_inline enum action_t net_www_perm(u32 pid , enum net_operation_t access)
{
    // Allow runc to access whatever it needs
//    if (container->status == DOCKER_INIT)
//        return BPFCON_ALLOW;
//    bpf_printk("net rule activated created,access opA %d",access);
    enum action_t decision = ACTION_NONE;

    struct net_policy_key key = {};

    key.config_id = config_id;

    enum action_t allow_action = ACTION_ALLOW;

    struct policy_t *policy = bpf_map_lookup_elem(&net_policies, &key);

    if(!policy)
        return 0;
    else
    {

        enum action_t action = policy_decision(policy,access);
//        bpf_printk("net rule activated , policy%d,access opB %d,action %d",policy->audit,access,action);
        return policy_decision(policy,access);
        }


    // Submit an audit event
//    audit_data_t *event = alloc_audit_event(
//        container->policy_id, AUDIT_TYPE_NET,
//        decision_to_audit_level(decision, container->tainted));
//    if (event) {
//        event->net.operation = access;
//        submit_audit_event(event);
//    }
    return 0;
}




/* Take all policy decisions together to reach a verdict on network access.
 *
 * This function should be called and taken as a return value to whatever LSM
 * hooks involve network access.
 *
 * @policy_id: 64-bit id of the current policy
 * @family:       Requested family.
 * @access:       Requested access.
 *
 * return: -EACCES if access is denied or 0 if access is granted.
 */
static __always_inline enum action_t net_perm( u32 pid,
                                               u8 category, enum net_operation_t access,
                                               struct socket *sock)
{
    enum action_t decision = ACTION_NONE ;

    if (category == NET_WWW){

        decision = net_www_perm(pid, access);
        }

//    else if (category == NET_IPC)
//        decision = net_ipc_perm(pid, access, sock);

    return decision;
}

SEC("lsm/socket_create")
int BPF_PROG(socket_create, int family, int type, int protocol, int kern)
{
    u32 pid  = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;


    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_CREATE;

    u8 category = family_to_category(family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen)
{

    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_BIND;

    u8 category = family_to_category(address->sa_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);



    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen)
{
    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_CONNECT;

    u8 category = family_to_category(address->sa_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);



    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(unix_stream_connect, struct socket *sock, struct socket *other,
             struct socket *newsock)
{
    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_CONNECT;

    u8 category = family_to_category(AF_UNIX);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(unix_may_send, struct socket *sock, struct socket *other)
{
    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_SEND;

    u8 category = family_to_category(AF_UNIX);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(socket_listen, struct socket *sock, int backlog)
{
    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_LISTEN;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(socket_accept, struct socket *sock, struct socket *newsock)
{
    u32 pid                = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_ACCEPT;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}


SEC("lsm/socket_sendmsg")
int BPF_PROG(socket_sendmsg,  struct socket *sock, struct msghdr *msg, int size)
{
    u32 pid                 = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_SEND;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(socket_recvmsg, struct socket *sock, struct msghdr *msg, int size,
             int flags)
{

    u32 pid                 = bpf_get_current_pid_tgid();

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }

    enum net_operation_t op = NET_RECV;
    u8 category = family_to_category(sock->sk->__sk_common.skc_family);
    enum action_t action = net_perm(pid,category,op,NULL);

    return action & ACTION_DENY ? -EPERM : 0;
}

SEC("lsm/socket_shutdown")
int BPF_PROG(socket_shutdown, struct socket *sock, int how)
{
    u32 pid                 = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    //only monitor process triggered by SSH session
    struct process_t *process = get_process(pid);
    if(!process){
        return 0;
    }


    enum net_operation_t op = NET_SHUTDOWN;

    u8 category = family_to_category(sock->sk->__sk_common.skc_family);
    enum action_t action = net_perm(pid,category,op,NULL);
    audit_net(pid,tgid,action,op);

    return action & ACTION_DENY ? -EPERM : 0;
}

















/* ========================================================================= *
 * Uprobe Commands                                                           *
 * ========================================================================= */
SEC("uprobe")
int BPF_KPROBE(do_containerize, int *ret_p, u64 config_id)
{
    int ret = 0;
    // Look up common policy information from fs_policy_key_t map

    // Try to add a process to `processes` with `pid`/`tgid`, associated with
    // `config_id`

    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid();
    struct process_t *process = create_process(pid,tgid,uid,config_id,false);

    if(!process){
         ret = -EINVAL;
         goto out;
    }
out:
    if (ret_p)
        bpf_probe_write_user(ret_p, &ret, sizeof(ret));

    return 0;
}


/* ========================================================================= *
 * Commandline collect                                                           *
 * ========================================================================= */
static const struct comline_audit_event empty_event = {};
const volatile int max_args = DEFAULT_MAXARGS;
const volatile bool ignore_failed = true;
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	u32 pid,tgid;
	int ret;
	struct comline_audit_event *event;
	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;
	u32 uid = (u32)bpf_get_current_uid_gid();
	int i;
    id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;
	if(bpf_map_update_elem(&execs,&pid,&empty_event, BPF_NOEXIST))
        return 0;

    event = bpf_map_lookup_elem(&execs,&pid);
    if(!event)
        return 0;
    event->pid = tgid;
    event->uid = uid;
    task = (struct task_struct*)bpf_get_current_task();
    event->ppid = (u32)BPF_CORE_READ(task, real_parent, tgid);
    event->args_count = 0;
    event->args_size = 0;

    ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
    if (ret <= ARGSIZE) {
    		event->args_size += ret;
    	} else {
    		/* write an empty string */
    		event->args[0] = '\0';
    		event->args_size++;
    	}
	#pragma unroll
	for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);

		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;
//	bpf_printk("araall=%s",&event->args);
	return 0;




}
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
	u64 id;
	u32 pid;
	int ret;
	struct comline_audit_event *event;
	u32 uid = (u32)bpf_get_current_uid_gid();

	id = bpf_get_current_pid_tgid();
	pid = (u32)id;
	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;
	ret = ctx->ret;
	if (ignore_failed && ret < 0)
		goto cleanup;

	event->retval = ret;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

    int rete = bpf_ringbuf_output(&comline_audit_events,event,sizeof(*event),0);
//    bpf_printk("com active ,ret=%d",rete);
//	struct comline_audit_event *event_t = bpf_ringbuf_reserve(&comline_audit_events, sizeof(struct comline_audit_event), BPF_ANY);
//	bpf_probe_read_user_str(event_t->pid,sizeof(u32),event->pid);
//	event_t->pid = event->pid;
//	event_t->ppid = event->ppid;
//    event_t->uid = event->uid;
//    event_t->retval = event->retval;
//    event_t->args_count = event->args_count;
//    event_t->args_size = event->args_size;
//	bpf_get_current_comm(&event_t->comm, sizeof(event_t->comm));
//    bpf_probe_read_user_str(event_t->args,event->args_size,event->args);

    //event_t->args = event->args;


//	bpf_ringbuf_submit(event_t, BPF_ANY);
//	size_t len = EVENT_SIZE(event);
//	if (len <= sizeof(*event))
//		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);
cleanup:
	bpf_map_delete_elem(&execs, &pid);
	return 0;



}


/*
 * uprobe_setlogin is used to track new logins in the ssh daemon
 */
SEC("uprobe")
int uprobe_setlogin(struct pt_regs *ctx)
{

    char *username = (void *)PT_REGS_PARM1(ctx);

    struct session_context_t session = {};

    char login[USERNAME_MAX_LENGTH] = {};
    // Select the profile cookie of the provided username
    bpf_probe_read_str(&login, USERNAME_MAX_LENGTH, username);
    u32 *profile_cookie = bpf_map_lookup_elem(&user_profile_cookie, login);
    if (profile_cookie == NULL) {
            session.profile_cookie = UNKNOWN_USER_NAME;
        } else {
            session.profile_cookie = *profile_cookie;
        }

    // Generate a random session cookie for this new ssh session
    u32 session_cookie = bpf_get_prandom_u32();
    session.login_timestamp = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    session.init_pid = pid;
    session.session_cookie = session_cookie;

      // Update the session cookie <-> session context mapping
    bpf_map_update_elem(&session_context, &session_cookie, &session, BPF_ANY);
    // Update the pid <-> session mapping
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        struct binary_context_t new_binary_ctx = {};
        new_binary_ctx.session_cookie = session_cookie;
        bpf_map_update_elem(&pid_binary_context, &pid, &new_binary_ctx, BPF_ANY);
    } else {
        binary_ctx->session_cookie = session_cookie;
    }

//    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct process_t new_process_t = {};
    new_process_t.pid = pid;
    new_process_t.tgid = tgid;
    u32 uid = bpf_get_current_uid_gid();
    create_process(pid,tgid,uid,config_id,true);

    bpf_map_lookup_or_try_init(&processes,&pid,&new_process_t);

    return 0;
};
/*
 * uprobe_closefrom is used to track new logins in the ssh daemon
 */
SEC("uprobe")
int uprobe_closefrom(struct pt_regs *ctx)
{
    u32 uid = bpf_get_current_uid_gid();
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    create_process(pid,tgid,uid,config_id,true);


    return 0;
}


/* ========================================================================= *
 * License String                                                            *
 * ========================================================================= */

char LICENSE[] SEC("license") = "GPL";

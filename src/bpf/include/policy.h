#ifndef __POLICY_H__
#define __POLICY_H__

#include "user_types.h"
#include "stdbool.h"
#include "const.h"
#include "structs.h"
#define access_t u32
#define MAX_CONTAINERS 10240
// TODO: This will no longer be necessary with task_local_storage in 5.11
#define MAX_PROCESSES 10240
#define MAX_POLICY 10240

#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))






#define MAX_POLICY_SIZE 1024
#define AUDIT_RINGBUF_PAGES (1 << 12)
#define __PACKED __attribute__((__packed__))
#define STRUCT_AUDIT_COMMON \
    u32 uid;                \
    u32 pid;                \
    u64 profile_key;        \
    access_t access;        \
    u8 comm[16];            \
    enum action_t action;



typedef enum action_t
{
    ACTION_NONE = 0x00000000,
    ACTION_ALLOW = 0x00000001,
    ACTION_AUDIT = 0x00000002,
    ACTION_TAINT = 0x00000004,
    ACTION_DENY = 0x00000008,
    ACTION_COMPLAIN = 0x00000010,
};




/**
 * fs_policy_key - Key into the filesystem policy map
 * @config_id: The config id of this config
 * @device_id: The device id of the filesystem
 */
 struct fs_policy_key{
    u32 config_id;
    u32 uid;
    u64 device_id;
    u64 profile_key;

};

struct file_policy_key{
    u64 policy_id;
    u64 inode_id;
    u32 device_id;
};

/**
 * file_permission_t - Access permissions for accessing files
 * @MAY_EXEC: Execute the file
 * @MAY_WRITE: Write to the file (implied append)
 * @MAY_READ: Read from the file
 * @MAY_APPEND: Append to the file
 * @MAY_CHMOD: Change file permissions and owners
 * @MAY_DELETE: Unlink the file
 * @MAY_EXEC_MMAP: Map the file into executable memory
 * @MAY_LINK: Create a hard link to the file
 */
typedef enum {
    MAY_EXEC      = (1U << 0),
    MAY_WRITE     = (1U << 1),
    MAY_READ      = (1U << 2),
    MAY_APPEND    = (1U << 3),
    MAY_CHMOD     = (1U << 4),
    MAY_DELETE    = (1U << 5),
    MAY_EXEC_MMAP = (1U << 6),
    MAY_LINK      = (1U << 7),
    MAY_IOCTL     = (1U << 8),
} file_permission_t;


struct file_policy_val_t{
    file_permission_t allow;
    file_permission_t taint;
    file_permission_t deny;
};

struct inode_key_t {
    u64 inode_id;
    u32 device_id;
} ;

struct process_t
{
 //   u64 profile_key;
    u64 config_id;
    u32 pid;
    u32 tgid;
    u32 uid;
    bool tainted;
};

struct profile_t
{
    u8 taint_on_exec;
};



struct policy_t
{
    access_t allow;
    access_t taint;
    access_t audit;
    access_t deny;
};

//=======
//文件系统
//=======
struct fs_policy_key_t
{
    u64 config_id;
    u64 st_dev;
};

struct procfs_policy_key_t
{
    u64 subject_profile_key;
    u64 object_profile_key;
};


struct fs_audit_event_t
{
    STRUCT_AUDIT_COMMON
    u32 st_ino;
    u32 st_dev;
    char s_id[32];
};

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct comline_audit_event
{
	u32 pid;
	u32 ppid;
	u32 uid;
	int retval;
	int args_count;
	unsigned int args_size;
	u8 comm[TASK_COMM_LEN];
	u8 args[FULL_MAX_ARGS_ARR];
};



/**
 * struct audit_string_t - Audit data representing a generic string.
 *
 * @FIXME: Add documentation
 * @TODO: This will become useful when bpf_snprintf() lands
 */
typedef struct {
    u8 inner_str[512];
} audit_string_t;



// from "linux/fs.h"
#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN 0x00000020
#define MAY_CHDIR 0x00000040
/* called from RCU mode, don't block */
#define MAY_NOT_BLOCK 0x00000080

#endif

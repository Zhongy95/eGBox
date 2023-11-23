#ifndef STRUCTS_H
#define STRUCTS_H

#include "user_types.h"

///**
// * process_t - Represents per-task metadata
// * @host_pid: pid of this task in the host's pid namespace
// * @host_tgid: tgid of this task in the host's pid namespace
// * @pid: pid of this task in our own pid namespace
// * @tgid: tgid of this task in our own pid namesapce
// */
//typedef struct {
////    u32 host_pid;
////    u32 host_tgid;
//    u32 pid;
//    u32 tgid;
//} process_t;

/**
 * session_context_t- Represents a ssh-session metadata
 */
struct session_context_t
{
    u64 login_timestamp;
    u32 profile_cookie;
    u32 session_cookie;
    u32 init_pid;

    u8 unknown_binary_default;
    u8 deletions_and_moves;
    u8 socket_creation;
    u8 privilege_elevation;
    u8 os_level_protections;
    u8 process_level_protections;
    u8 performance_monitoring;
    u8 kill;
    u8 unknown_file_default;
};


/* ========================================================================= *
 * File Policy                                                               *
 * ========================================================================= */




typedef enum fs_access_t
{
    FS_NONE = 0x0,
    FS_READ = (1U << 0),
    FS_WRITE = (1U << 1),
    FS_APPEND = (1U << 2),
    FS_EXEC = (1U << 3),
    FS_CHMOD = (1U << 4),
    FS_GETATTR = (1U << 5),
    FS_IOCTL = (1U << 6),
    FS_DELETE = (1U << 7),
    FS_LINK = (1U << 8),
};

#define DNAME_INLINE_LEN 32 /* 192 bytes */
struct path_t{
    u8 fullpath[512];
    unsigned int pathsize;
    u64 st_ino;
    u64 st_dev;
    u32 count;
};
/**
 * struct audit_file_t - Audit data representing a file access.
 *
 *
 */
struct audit_file_t{
    enum fs_access_t access;
    struct path_t path;

} ;




/* ========================================================================= *
 * Network Policy                                                            *
 * ========================================================================= */

/* Network categories */
typedef enum  net_category_t{
    NET_WWW = (1U << 0),
    NET_IPC = (1U << 1),
};

/* Network operations */
typedef enum net_operation_t{
    NET_CONNECT  = (1U << 0),
    NET_BIND     = (1U << 1),
    NET_ACCEPT   = (1U << 2),
    NET_LISTEN   = (1U << 3),
    NET_SEND     = (1U << 4),
    NET_RECV     = (1U << 5),
    NET_CREATE   = (1U << 6),
    NET_SHUTDOWN = (1U << 7),
};

struct net_policy_key{
    u32 config_id;
    u32 uid;
};
struct net_policy_key_group{
    u32 config_id;
    u32 gid;
};

/**
 * enum audit_type_t - Specifies the inner type container in an audit_data_t.
 *
 *
 */
typedef enum audit_type_t{
    AUDIT_TYPE_FILE    = (1U << 0),
    AUDIT_TYPE_CAP     = (1U << 1),
    AUDIT_TYPE_NET     = (1U << 2),
    AUDIT_TYPE_IPC     = (1U << 3),
    AUDIT_TYPE_SIGNAL  = (1U << 4),
    AUDIT_TYPE__UNKOWN = (1U << 5),
} ;



/**
 * struct audit_net_t - Audit data representing net access.
 *
 *
 */
typedef struct audit_net_t{
    enum net_operation_t operation;
} ;


/**
 * enum audit_level_t - Specifies the audit level, used to control verbosity in
 * userspace.
 *
 *
 */
typedef enum audit_level_t{
    AUDIT__NONE    = 0,
    AUDIT_ALLOW    = (1U << 0), // Audit policy allows
    AUDIT_DENY     = (1U << 1), // Audit policy denials
    AUDIT_TAINT    = (1U << 2), // Audit policy taints
    AUDIT_INFO     = (1U << 3), // Audit info
    AUDIT_WARN     = (1U << 4), // Audit warnings
    AUDIT__UNKNOWN = (1U << 5),
};


/**
 * struct audit_data_t - Common audit data.
 *
 *
 */
struct audit_event_t{
    u8 comm[64];
    u32 uid;
    u32 gid;
    u64 config_id;
    u32 pid;
    u32 tgid;
    enum audit_type_t type;
    enum audit_level_t level;
    union {
        struct audit_file_t file;
//        audit_cap_t cap;
        struct audit_net_t net;
//        audit_ipc_t ipc;
//        audit_signal_t signal;
    };
};




#endif
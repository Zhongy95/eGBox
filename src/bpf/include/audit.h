#ifndef AUDIT_H
#define AUDIT_H

//#include "vmlinux.h"
#include "policy.h"

//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_tracing.h>

#define FILTER_AUDIT(action)                                        \
    if (!(action & (ACTION_COMPLAIN | ACTION_DENY | ACTION_AUDIT))) \
    {                                                               \
        return;                                                     \
    }

#define DO_AUDIT_COMMON(event, pid, action,config_id)    \
    do                                             \
    {                                              \
        if (!event)                                \
        {                                          \
            return;                                \
        }                                          \
        bpf_get_current_comm(&event->comm,sizeof(event->comm));\
        event->uid = bpf_get_current_uid_gid();    \
        event->pid = pid;                 \
        event->profile_key = config_id; \
        event->action = action;                    \
        event->access = access;                    \
    } while (0)





#endif

pub mod config;
pub mod rule;

use std::convert::{TryFrom, TryInto};

use anyhow::bail;
use plain::Plain;

use super::bindings::raw;
pub mod keys {
    use super::*;
    use plain::Plain;

    /// Represents a per-filesystem policy key on the BPF side.
    pub type FsPolicyKey = raw::fs_policy_key;
    unsafe impl Plain for FsPolicyKey {}

    pub type ProcfsPolicyKey = raw::procfs_policy_key_t;
    unsafe impl Plain for ProcfsPolicyKey {}

    /// Represents a network policy key on the BPF side.
    pub type NetPolicyKey = raw::net_policy_key;
    unsafe impl Plain for NetPolicyKey {}
}

pub mod values {

    use super::*;

    pub type PolicyT = raw::policy_t;
    unsafe impl Plain for PolicyT {}
}

pub mod bitflags {
    // use anyhow::Ok;
    use ::bitflags::bitflags;

    use super::{*};

    // bitflags! {
    //     /// Represents a audit Tyoe from the BPF side.
    //     #[derive(Default)]
    //     pub struct AuditType :raw::audit_type_t::Type{
    //         const FILE   = raw::audit_type_t::AUDIT_TYPE_FILE;
    //         const NET    = raw::audit_type_t::AUDIT_TYPE_NET;
    //         const CAP    = raw::audit_type_t::AUDIT_TYPE_CAP;
    //         const IPC    = raw::audit_type_t::AUDIT_TYPE_IPC;
    //         const SIGNAL = raw::audit_type_t::AUDIT_TYPE_SIGNAL;
    //         const UNKOWN = raw::audit_type_t::AUDIT_TYPE__UNKOWN;
    //     }
    // }

    bitflags! {
        /// Represents a policy decision from the BPF side.
        #[derive(Default)]
        pub struct PolicyDecision :raw::action_t::Type {
            const NO_DECISION = raw::action_t::ACTION_NONE;
            const AUDIT       = raw::action_t::ACTION_AUDIT;
            const ALLOW       = raw::action_t::ACTION_ALLOW;
            const DENY        = raw::action_t::ACTION_DENY;
            const TAINT       = raw::action_t::ACTION_TAINT;
            const COMPLAIN    = raw::action_t::ACTION_COMPLAIN;
        }
    }
    bitflags! {
        /// Represents the file permissions bitmask on the BPF side.
        #[derive(Default)]
        pub struct FileAccess :raw::fs_access_t::Type {
            const FS_NONE      = raw::fs_access_t::FS_NONE;
            const FS_READ      = raw::fs_access_t::FS_READ;
            const FS_WRITE     = raw::fs_access_t::FS_WRITE;
            const FS_EXEC      = raw::fs_access_t::FS_EXEC;
            const FS_APPEND    = raw::fs_access_t::FS_APPEND;
            const FS_GETATTR   = raw::fs_access_t::FS_GETATTR;
            const FS_DELETE    = raw::fs_access_t::FS_DELETE;
            const FS_CHMOD     = raw::fs_access_t::FS_CHMOD;
            const FS_LINK      = raw::fs_access_t::FS_LINK;
            const FS_IOCTL     = raw::fs_access_t::FS_IOCTL;
        }
    }

    /// Convert &str access flags to FileAccess.
    impl TryFrom<&str> for FileAccess {
        type Error = anyhow::Error;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            // Try convenience aliases first
            match value {
                "readOnly" => return Ok(Self::FS_READ),
                "readWrite" => return Ok(Self::FS_READ | Self::FS_WRITE | Self::FS_APPEND),
                "readAppend" => return Ok(Self::FS_READ | Self::FS_APPEND),
                "library" => return Ok(Self::FS_READ),
                "exec" => return Ok(Self::FS_READ | Self::FS_EXEC),
                "any" => return Ok(Self::all()),
                _ => {}
            };

            let mut access = Self::default();

            // Iterate through the characters in our access flags, creating the
            // bitmask as we go.
            for c in value.chars() {
                // Because of weird Rust-isms, to_lowercase returns a string. We
                // only care about ASCII chars, so we will match on length-1
                // strings.
                let c_lo = &c.to_lowercase().to_string()[..];
                match c_lo {
                    "r" => access |= (Self::FS_READ | Self::FS_GETATTR),
                    "w" => access |= Self::FS_WRITE,
                    "x" => access |= Self::FS_EXEC,
                    "a" => access |= Self::FS_APPEND,
                    "d" => access |= Self::FS_DELETE,
                    "c" => access |= Self::FS_CHMOD,
                    "l" => access |= Self::FS_LINK,
                    "i" => access |= Self::FS_IOCTL,
                    _ => bail!("Unknown access flag {}", c),
                };
            }

            Ok(access)
        }
    }

    /// Convert String access flags to FileAccess.
    /// Uses the implementation for TryFrom<&str>.
    impl TryFrom<String> for FileAccess {
        type Error = anyhow::Error;
        fn try_from(value: String) -> Result<Self, Self::Error> {
            value.try_into()
        }
    }

    bitflags! {
        /// Represents the network operations bitmask on the BPF side.
        /// #[derive(Serialize, Deserialize, Debug)]
        #[derive(Default)]
        pub struct NetOperation :raw::net_operation_t::Type {
            const NET_CONNECT  = raw::net_operation_t::NET_CONNECT;
            const NET_BIND     = raw::net_operation_t::NET_BIND;
            const NET_ACCEPT   = raw::net_operation_t::NET_ACCEPT;
            const NET_LISTEN   = raw::net_operation_t::NET_LISTEN;
            const NET_SEND     = raw::net_operation_t::NET_SEND;
            const NET_RECV     = raw::net_operation_t::NET_RECV;
            const NET_CREATE   = raw::net_operation_t::NET_CREATE;
            const NET_SHUTDOWN = raw::net_operation_t::NET_SHUTDOWN;
            const MASK_SERVER = Self::NET_CREATE.bits | Self::NET_BIND.bits
                | Self::NET_LISTEN.bits | Self::NET_ACCEPT.bits | Self::NET_SHUTDOWN.bits;
            const MASK_CLIENT = Self::NET_CONNECT.bits;
            const MASK_SEND = Self::NET_SEND.bits;
            const MASK_RECV = Self::NET_RECV.bits;
        }
    }



}

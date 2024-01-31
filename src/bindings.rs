// SPDX-License-Identifier: GPL-2

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

/// Raw bindings generated by bindgen
pub(crate) mod raw {
    use std::env;
    use std::include;
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

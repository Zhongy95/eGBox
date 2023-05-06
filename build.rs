// SPDX-License-Identifier: GPL-2
//
// Copyright (C) 2021  William Findlay
//
// Jan. 19, 2021  William Findlay  Created this.

use std::env;
use std::fs::{remove_file, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use uname::uname;
use tempfile::tempdir;

fn main() {
    // Path to BPF program
    let prog_path = Path::new("src/bpf/bpfESX.bpf.c");

    // Re-run build if any C code has changed
    println!("cargo:rerun-if-changed={}", prog_path.display());
    println!("cargo:rerun-if-changed=bindings.h");
    for path in glob("src/bpf/include/*.h")
        .expect("Failed to glob headers")
        .filter_map(Result::ok)
    {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    generate_bindings();
    generate_vmlinux();
    generate_skeleton(prog_path);
}

fn generate_bindings() {
    let out_path = PathBuf::from(format!("{}/bindings.rs", env::var("OUT_DIR").unwrap()));

    // Generate bindings
    let bindings = bindgen::builder()
        .header("bindings.h")
        .derive_default(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .constified_enum_module("action_t")
        .constified_enum_module("fs_access_t")
        .constified_enum_module("net_operation_t")
        .clang_arg("-Isrc/bpf/include")
        .clang_arg("-Wno-unknown-attributes")
        .clang_arg("-target")
        .clang_arg("bpf")
        .generate()
        .expect("Failed to generate bindings");

    // Save bindings
    bindings
        .write_to_file(out_path)
        .expect("Failed to save bindings");
}

fn generate_vmlinux() {
    // Determine pathname for vmlinux header
    let kernel_release = uname().expect("Failed to fetch system information").release;
    let vmlinux_path = PathBuf::from(format!("src/bpf/include/vmlinux_{}.h", kernel_release));
    let vmlinux_link_path = PathBuf::from("src/bpf/include/vmlinux.h");

    // Populate vmlinux_{kernel_release}.h with BTF info
    if !vmlinux_path.exists() {
        let mut vmlinux_writer = BufWriter::new(
            File::create(vmlinux_path.clone())
                .expect("Failed to open vmlinux destination for writing"),
        );

        let output = Command::new("bpftool")
            .arg("btf")
            .arg("dump")
            .arg("file")
            .arg("/sys/kernel/btf/vmlinux")
            .arg("format")
            .arg("c")
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to spawn bpftool. Is it installed?");

        assert!(output.status.success());

        vmlinux_writer
            .write_all(&output.stdout)
            .expect("Failed to write to vmlinux.h");
    }

    // Remove existing link if it exists
    if vmlinux_link_path.exists() {
        remove_file(vmlinux_link_path.clone()).expect("Failed to unlink vmlinux.h");
    }

    // Create a new symlink
    symlink(vmlinux_path.file_name().unwrap(), vmlinux_link_path)
        .expect("Failed to symlink vmlinux.h");
}

fn generate_skeleton<P: AsRef<Path>>(prog_path: P) {
    // match SkeletonBuilder::new(prog_path)
    //     .clang_args("-Isrc/bpf/include")
    //     .generate("src/bpf/mod.rs")
    // {
    //     Ok(_) => {}
    //     Err(e) => panic!("Failed to generate skeleton: {}", e),
    // }
    let dir = tempdir()
        .expect("Failed to create temporary directory")
        .into_path();
    let mut builder = SkeletonBuilder::new();

    builder
        .source(prog_path)
        .clang_args("-O2 -Isrc/bpf/include -Wno-unknown-attributes -emit-llvm")
        .obj(dir.join("bpfESX.bpf.bc")) .build()
        .expect("Failed to build");

    Command::new("llc").args(
        format!(
            "{} -mattr=+alu32 -march=bpf -mcpu=v2 -filetype=obj -o {}",
            dir.join("bpfESX.bpf.bc").display(),
            dir.join("bpfESX.bpf.o").display()
        )
            .split_whitespace(),
    )
        .status()
        .expect("Failed to run llc");

    builder
        .obj(dir.join("bpfESX.bpf.o"))
        .generate("src/bpf/mod.rs")
        .expect("Failed to generate skeleton")
}

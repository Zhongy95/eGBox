use std::fs::read;
use std::path::Path;

use anyhow::{bail, Context as _, Context, Result};
use goblin::elf::{Elf, Sym};
use procfs::process::Process;

/// Resolves symbols from an ELF file
/// Based on https://github.com/ingraind/redbpf/blob/main/redbpf/src/symbols.rs
struct SymbolResolver<'a> {
    elf: Elf<'a>,
}

impl<'a> SymbolResolver<'a> {
    /// Find a symbol offset within a file specified by `pathname`
    pub fn find_in_file(pathname: &Path, symbol: &str) -> Result<Option<usize>> {
        let bytes = read(pathname).context("Failed to read ELF")?;

        let resolver = Self::parse(&bytes).context("Failed to parse ELF")?;
        let offset = resolver.find_offset(symbol);
        Ok(offset)
    }
    pub fn find_in_file_dynamic(pathname: &Path, symbol: &str) -> Result<Option<usize>> {
        let bytes = read(pathname).context("Failed to read ELF")?;

        let resolver = Self::parse(&bytes).context("Failed to parse ELF")?;
        let offset = resolver.find_dynoffset(symbol);
        Ok(offset)
    }

    /// Parse an ELF file and return a [`SymbolResolver`]
    pub fn parse(bytes: &[u8]) -> Result<SymbolResolver> {
        let elf = Elf::parse(bytes)?;
        Ok(SymbolResolver { elf })
    }

    /// Resolve a symbol in the ELF file
    fn resolve_sym(&self, symbol: &str) -> Option<Sym> {
        println!("e_type:{}", self.elf.header.e_type);
        self.elf.syms.iter().find(|sym| {
            self.elf
                .strtab
                .get(sym.st_name)
                .and_then(|sym| sym.ok())
                .map(|sym| sym == symbol)
                .unwrap_or(false)
        })
    }
    /// Resolve a symbol in the ELF file
    fn resolve_dynsym(&self, symbol: &str) -> Option<Sym> {
        self.elf.dynsyms.iter().find(|sym| {
            self.elf
                .dynstrtab
                .get(sym.st_name)
                .and_then(|sym| sym.ok())
                .map(|sym| sym == symbol)
                .unwrap_or(false)
        })
    }

    /// Find the offset of a symbol in the ELF file
    pub fn find_offset(&self, symbol: &str) -> Option<usize> {
        // self.itersym();
        println!("end iter");
        self.resolve_sym(symbol).map(|sym| sym.st_value as usize)
    }
    pub fn find_dynoffset(&self, symbol: &str) -> Option<usize> {
        // self.itersym();
        println!("end iter");
        self.resolve_dynsym(symbol).map(|sym| sym.st_value as usize)
    }
}

pub trait FindSymbolUprobeExt {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link>;

    fn attach_uprobe_dynsymbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link>;

    fn attach_uprobe_addr(
        &mut self,
        retprobe: bool,
        pid: i32,
        addr: usize,
    ) -> Result<libbpf_rs::Link>;
}

impl FindSymbolUprobeExt for libbpf_rs::Program {
    /// Attach a uprobe to a symbol within another binary.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link> {
        // Find symbol in the ELF file

        let offset = SymbolResolver::find_in_file(pathname, symbol)
            .context("Error finding symbol")?
            .context("Failed to find symbol")?;

        // Use the offset we found to attach the probe
        self.attach_uprobe(retprobe, pid, pathname, offset)
            .context("Failed to attach uprobe")
    }
    fn attach_uprobe_dynsymbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link> {
        // Find symbol in the ELF file

        let offset = SymbolResolver::find_in_file_dynamic(pathname, symbol)
            .context("Error finding symbol")?
            .context("Failed to find symbol")?;

        // Use the offset we found to attach the probe
        self.attach_uprobe(retprobe, pid, pathname, offset)
            .context("Failed to attach uprobe")
    }

    /// Attach a uprobe to an address within our own address space.
    fn attach_uprobe_addr(
        &mut self,
        retprobe: bool,
        pid: i32,
        addr: usize,
    ) -> Result<libbpf_rs::Link> {
        // Find the offset
        let base_addr = get_base_addr()?;
        let offset = addr - base_addr;

        let pathname = "/proc/self/exe";

        // Use the offset we found to attach the probe
        self.attach_uprobe(retprobe, pid, pathname, offset)
            .context("Failed to attach uprobe")
    }
}

/// Find our base load address. We use /proc/self/maps for this.
fn get_base_addr() -> Result<usize> {
    let me = Process::myself().context("Failed to find procfs entry")?;
    let maps = me.maps().context("Failed to get maps")?;

    for entry in maps {
        if entry.perms.contains("r-xp") {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }

    bail!("Failed to find executable region")
}

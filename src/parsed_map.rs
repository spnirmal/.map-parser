#[derive(Clone, Default)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Default)]
pub struct ObjFile {
    /// Display name (basename of path, or "lib(member)")
    pub name: String,
    /// Full path as found in the map file
    pub path: String,
    pub sizes: [u64; 5], // indexed by SecFamily as usize
}

impl ObjFile {
    pub fn get(&self, f: SecFamily) -> u64 {
        self.sizes[f as usize]
    }
    pub fn add(&mut self, f: SecFamily, n: u64) {
        self.sizes[f as usize] += n;
    }
    pub fn total(&self) -> u64 {
        self.sizes.iter().sum()
    }
    pub fn module(&self) -> String {
        classify_module(&self.path)
    }
}

#[derive(Clone, Default)]
pub struct FuncEntry {
    pub name: String,
    pub size: u64,
    pub address: u64,
    /// Source object file
    pub src: String,
}

#[derive(Clone, Default)]
pub struct DiscardedEntry {
    pub section: String,
    pub size: u64,
    pub obj: String,
}

#[derive(Clone, Default)]
pub struct ArchiveDep {
    pub member: String,  // "lib.a(file.o)"
    pub needed_by: String,
    pub symbol: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SecFamily {
    Text,
    Rodata,
    Data,
    Bss,
    Other, // .ARM.*, .debug_*, .comment, etc. tracked but not in main totals
}

pub fn sec_family(name: &str) -> SecFamily {
    // "text" 
    match name {
        "text" => return SecFamily::Text,
        _ => {}
    }
    if name.starts_with(".text") {
        return SecFamily::Text;
    }
    if name.starts_with(".rodata") {
        return SecFamily::Rodata;
    }
    if name.starts_with(".data") && !name.starts_with(".data.rel.ro") {
        return SecFamily::Data;
    }
    if name.starts_with(".data.rel.ro") {
        return SecFamily::Rodata; 
    }
    if name.starts_with(".bss") || name.starts_with(".sbss") {
        return SecFamily::Bss;
    }
    SecFamily::Other
}

pub fn family_name(f: SecFamily) -> &'static str {
    match f {
        SecFamily::Text => ".text",
        SecFamily::Rodata => ".rodata",
        SecFamily::Data => ".data",
        SecFamily::Bss => ".bss",
        SecFamily::Other => "other",
    }
}

pub fn classify_module(raw: &str) -> String {
    let path = raw.replace('\\', "/");

    if path.to_lowercase().contains("linker stubs") {
        return "Linker Stubs".into();
    }

    // Archive library: path/to/libname.a(file.o)  or  libname.lib(file.o)
    if let Some(cap) = archive_lib_name(&path) {
        return format!("lib: {}", cap);
    }

    // Bare library path (no parenthesis notation)
    if path.ends_with(".a") || path.ends_with(".lib") {
        let base = path.rsplit('/').next().unwrap_or(&path);
        let name = base
            .trim_start_matches("lib")
            .trim_end_matches(".a")
            .trim_end_matches(".lib");
        return format!("lib: {}", name);
    }

    
    path_to_module(&path)
}


pub fn archive_lib_name(path: &str) -> Option<String> {
    
    let paren = path.find('(')?;
    let lib_path = &path[..paren];
    let base = lib_path.rsplit('/').next().unwrap_or(lib_path);

    let name = base
        .trim_end_matches(".a")
        .trim_end_matches(".lib")
        .trim_start_matches("lib");
    if name.is_empty() {
        Some(base.trim_end_matches(".a").trim_end_matches(".lib").into())
    } else {
        Some(name.into())
    }
}


pub fn path_to_module(path: &str) -> String {
  
    let p = path.trim_start_matches('/');


    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return "Unknown".into();
    }

    const NOISE: &[&str] = &[
        "build", "out", "output", "obj", "objects", "o", "release", "debug",
        "bin", "gcc", "src", "source", "sources", "include", "inc", "arm",
        "arm-none-eabi", "cortex-m", "portable",
    ];

    fn is_noise(s: &str) -> bool {
        NOISE.iter().any(|n| n.eq_ignore_ascii_case(s))
    }

    let dirs: Vec<&str> = parts[..parts.len().saturating_sub(1)]
        .iter()
        .copied()
        .filter(|s| !is_noise(s))
        .collect();

    if dirs.is_empty() {
       
        let fname = parts.last().unwrap_or(&"unknown");
        return fname
            .trim_end_matches(".o")
            .trim_end_matches(".obj")
            .into();
    }

    
    if dirs.len() >= 2 {
        format!("{}/{}", dirs[dirs.len() - 2], dirs[dirs.len() - 1])
    } else {
        dirs[dirs.len() - 1].into()
    }
}

#[derive(Clone, Default)]
pub struct ParsedMap {
    // Totals per section family
    pub totals: [u64; 5],

    // Per top-level section name → size
    pub all_sections: Vec<(String, u64, u64)>, 


    pub rodata_str_size: u64,

    // Symbols per section family
    pub symbols: [Vec<Symbol>; 5],

    // Per object-file contributions
    pub obj_files: Vec<ObjFile>,

    // Functions extracted from -ffunction-sections blocks
    pub functions: Vec<FuncEntry>,

    // Discarded sections
    pub discarded: Vec<DiscardedEntry>,
    pub discarded_total: u64,

    // Alignment padding bytes
    pub fill_bytes: u64,

    // Common symbols 
    pub common_symbols: Vec<Symbol>,

    // Archive dependency 
    pub archive_deps: Vec<ArchiveDep>,
}

impl ParsedMap {
    pub fn total(&self) -> u64 {
        self.totals[SecFamily::Text as usize]
            + self.totals[SecFamily::Rodata as usize]
            + self.totals[SecFamily::Data as usize]
            + self.totals[SecFamily::Bss as usize]
    }
    pub fn flash_total(&self) -> u64 {
        self.totals[SecFamily::Text as usize]
            + self.totals[SecFamily::Rodata as usize]
            + self.totals[SecFamily::Data as usize]
    }
    pub fn ram_total(&self) -> u64 {
        self.totals[SecFamily::Data as usize] + self.totals[SecFamily::Bss as usize]
    }
}
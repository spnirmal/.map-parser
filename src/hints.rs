//optimisation hints

use eframe::egui;
use crate::parsed_map::{ParsedMap, SecFamily, ObjFile, FuncEntry};


#[derive(Clone, PartialEq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    pub fn color(&self) -> egui::Color32 {
        match self {
            Severity::Critical => egui::Color32::from_rgb(230, 60, 60),
            Severity::Warning => egui::Color32::from_rgb(220, 165, 30),
            Severity::Info => egui::Color32::from_rgb(70, 180, 230),
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
        }
    }
    pub fn bg(&self) -> egui::Color32 {
        match self {
            Severity::Critical => egui::Color32::from_rgb(50, 14, 14),
            Severity::Warning => egui::Color32::from_rgb(50, 36, 10),
            Severity::Info => egui::Color32::from_rgb(12, 30, 55),
        }
    }
}

#[derive(Clone)]
pub struct Hint {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub saving: String,
}

pub fn generate_hints(m: &ParsedMap) -> Vec<Hint> {
    let mut hints = Vec::new();
    let total = m.total();
    let bss = m.totals[SecFamily::Bss as usize];
    let text = m.totals[SecFamily::Text as usize];
    let rodata = m.totals[SecFamily::Rodata as usize];

    // ── 1. Single object file dominates BSS ──────────────────────────────────
    let mut bss_dominators: Vec<(&ObjFile, u64, f64)> = m
        .obj_files
        .iter()
        .filter_map(|o| {
            let ob = o.get(SecFamily::Bss);
            if bss > 0 {
                let pct = 100.0 * ob as f64 / bss as f64;
                if pct > 20.0 {
                    Some((o, ob, pct))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    bss_dominators.sort_by(|a, b| b.1.cmp(&a.1));
    for (o, ob, pct) in bss_dominators.iter().take(3) {
        hints.push(Hint {
            severity: if *pct > 40.0 { Severity::Critical } else { Severity::Warning },
            title: format!(
                "'{}' contributes {:.0}% of BSS ({} bytes)",
                o.name,
                pct,
                ob
            ),
            detail: format!(
                "A single object file holds {:.0}% of all zero-initialised RAM. \
                 Review its static arrays and buffers. Consider dynamic allocation \
                 for buffers that are only needed during specific operations, or \
                 reduce maximum buffer sizes if they are over-provisioned.",
                pct
            ),
            saving: format!("Up to {} bytes of RAM", ob),
        });
    }

    // ── 2. Very large functions ───────────────────────────────────────────────
    let huge: Vec<&FuncEntry> = m.functions.iter().filter(|f| f.size >= 1500).collect();
    if !huge.is_empty() {
        let list: Vec<String> = huge
            .iter()
            .take(5)
            .map(|f| format!("{} ({} B)", f.name, f.size))
            .collect();
        let extra = if huge.len() > 5 {
            format!(" … and {} more", huge.len() - 5)
        } else {
            String::new()
        };
        hints.push(Hint {
            severity: Severity::Warning,
            title: format!(
                "{} function(s) exceed 1 500 B — consider refactoring",
                huge.len()
            ),
            detail: format!(
                "Very large functions are harder for the compiler to optimise at -Os and \
                 increase instruction-cache pressure. Splitting each into smaller helpers \
                 (<512 B) is recommended. Identified: {}{}",
                list.join(", "),
                extra
            ),
            saving: "Improved icache utilisation; often 5–15% code-size reduction".into(),
        });
    }

    // ── 3. BSS dominates total footprint ─────────────────────────────────────
    if total > 0 {
        let bss_pct = 100.0 * bss as f64 / total as f64;
        if bss_pct > 40.0 {
            hints.push(Hint {
                severity: Severity::Warning,
                title: format!(
                    "BSS is {:.0}% of total footprint ({} bytes of RAM)",
                    bss_pct, bss
                ),
                detail:
                    "More than 40% of the firmware's total memory footprint is zero-initialised \
                     RAM. This is often caused by large static arrays or structs that are always \
                     resident even when not in use. Audit the largest BSS contributors in the \
                     Object Files tab and consider: dynamic allocation, reducing buffer sizes, \
                     or activating buffers only when the associated feature is running."
                        .into(),
                saving: "Varies; audit Object Files tab for targets".into(),
            });
        }
    }

    // ── 4. String literal bloat ───────────────────────────────────────────────
    if rodata > 0 && m.rodata_str_size > 0 {
        let str_pct = 100.0 * m.rodata_str_size as f64 / rodata as f64;
        if str_pct > 25.0 {
            hints.push(Hint {
                severity: Severity::Warning,
                title: format!(
                    ".rodata.str sections = {} bytes ({:.0}% of .rodata) — debug string bloat",
                    m.rodata_str_size, str_pct
                ),
                detail:
                    ".rodata.str* sections contain pooled string literals, typically produced \
                     by debug/trace logging calls (printf, puts, custom trace macros). \
                     Wrap all debug/trace calls in a compile-time guard such as \
                     #ifndef NDEBUG / #endif or a custom TRACE_ENABLED macro. \
                     Alternatively, replace full-string trace messages with numeric \
                     event codes to eliminate the strings entirely from the binary."
                        .into(),
                saving: format!(
                    "~{} bytes of flash (eliminating debug strings)",
                    m.rodata_str_size * 3 / 4
                ),
            });
        }
    }

    // ── 5. No -ffunction-sections evidence ───────────────────────────────────
    if m.functions.is_empty() {
        hints.push(Hint {
            severity: Severity::Warning,
            title: "No per-function sections found — dead code may not be eliminated".into(),
            detail:
                "No .text.FunctionName sections were found in this map file. \
                 This means the compiler was not invoked with -ffunction-sections \
                 (and -fdata-sections). Without these flags, the linker cannot \
                 discard individual unused functions; entire object files are kept \
                 or discarded as a unit. Add -ffunction-sections -fdata-sections \
                 to CFLAGS and --gc-sections to LDFLAGS."
                    .into(),
            saving: "Potentially significant .text reduction".into(),
        });
    }

    // ── 6. Runtime libraries pull in float / 64-bit helpers ──────────────────
    let lib_text: u64 = m
        .obj_files
        .iter()
        .filter(|o| o.path.contains(".a(") || o.path.ends_with(".a"))
        .map(|o| o.get(SecFamily::Text))
        .sum();
    if text > 0 {
        let lib_pct = 100.0 * lib_text as f64 / text as f64;
        if lib_pct > 8.0 {
            hints.push(Hint {
                severity: Severity::Info,
                title: format!(
                    "Runtime libraries contribute {:.0}% of .text ({} bytes)",
                    lib_pct, lib_text
                ),
                detail:
                    "A significant portion of code size comes from runtime library routines. \
                     Common causes: 64-bit integer division emulation (_divdi3, _udivdi3), \
                     software floating-point emulation, and libc string/memory functions. \
                     Review whether 64-bit division and float arithmetic can be replaced \
                     with 32-bit integer or fixed-point equivalents. Check the Object Files \
                     tab for the individual library members and their sizes."
                        .into(),
                saving: format!("Up to {} bytes of .text", lib_text / 2),
            });
        }
    }

    // ── 7. Discarded dead code ────────────────────────────────────────────────
    if m.discarded_total > 0 {
        hints.push(Hint {
            severity: Severity::Info,
            title: format!(
                "{} bytes of dead code/data discarded by --gc-sections",
                m.discarded_total
            ),
            detail:
                "These sections were compiled into object files but were unreachable from \
                 the entry point and removed at link time. This is correct behaviour with \
                 --gc-sections. Adding -flto (Link-Time Optimisation) enables the compiler \
                 to perform cross-translation-unit dead-code elimination earlier, \
                 often reducing the final binary further and improving inlining."
                    .into(),
            saving: format!(
                "{} bytes already saved; LTO may save an additional 5–15%",
                m.discarded_total
            ),
        });
    }

    // ── 8. Common symbols (weak linkage / missing initialisation) ────────────
    if m.common_symbols.len() > 10 {
        hints.push(Hint {
            severity: Severity::Info,
            title: format!(
                "{} common (COMMON) symbols found",
                m.common_symbols.len()
            ),
            detail:
                "COMMON symbols are global variables declared without explicit initialisation \
                 in C (e.g. `int x;` at file scope). The linker merges them into the BSS \
                 section. While harmless, explicitly initialising variables (`int x = 0;`) \
                 gives the compiler and linker more information and avoids unintended \
                 symbol merging across translation units. It also makes dependencies clearer."
                    .into(),
            saving: "No direct size saving; improves code clarity and link behaviour".into(),
        });
    }

    // ── 9. Alignment padding ─────────────────────────────────────────────────
    if m.fill_bytes > 64 {
        hints.push(Hint {
            severity: Severity::Info,
            title: format!("{} bytes lost to alignment padding (*fill*)", m.fill_bytes),
            detail:
                "Fill regions are inserted by the linker to satisfy alignment constraints. \
                 Reordering struct fields from largest to smallest (e.g. u32 before u16 \
                 before u8) and grouping same-sized variables together reduces padding. \
                 Use __attribute__((packed)) cautiously — only on structs that are not \
                 accessed via DMA and where unaligned access is supported by the CPU."
                    .into(),
            saving: format!("~{} bytes", m.fill_bytes),
        });
    }

    hints
}
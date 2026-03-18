use crate::parsed_map::{ParsedMap, SecFamily, sec_family, ArchiveDep, Symbol, DiscardedEntry, ObjFile, FuncEntry, family_name};
use std::collections::HashMap;

pub fn parse_map(contents: &str) -> ParsedMap {
    let mut out = ParsedMap::default();
    let lines: Vec<&str> = contents.lines().collect();
    let n = lines.len();

    // ── Block 1: archive members 
    {
        let mut in_archive = false;
        let mut last_member = String::new();

        for line in &lines {
            let s = line.trim_end_matches('\r').trim();
            if s.starts_with("Archive member included") {
                in_archive = true;
                continue;
            }
            if in_archive && (s.starts_with("Allocating") || s.starts_with("Discarded")) {
                break;
            }
            if !in_archive || s.is_empty() {
                continue;
            }
            // the archive member itself
            let raw = line.trim_end_matches('\r');
            if !raw.starts_with(|c: char| c.is_whitespace()) {
                last_member = norm_path(s);
            } else { 
                // the thing that needed the member
                let parts: Vec<&str> = s.splitn(2, '(').collect();
                let needed_by = norm_path(parts[0]);
                let symbol = if parts.len() > 1 {
                    parts[1].trim_end_matches(')').to_string()
                } 
                else {
                    String::new()
                };
                if !last_member.is_empty() && !needed_by.is_empty() {
                    out.archive_deps.push(ArchiveDep {
                        member: last_member.clone(),
                        needed_by,
                        symbol,
                    });
                }
            }
        }
    }

    // ── Block 2: common symbols
    {
        let mut in_common = false;
        for line in &lines {
            let s = line.trim_end_matches('\r').trim();
            if s.starts_with("Allocating common symbols") {
                in_common = true;
                continue;
            }
            if s.starts_with("Discarded") {
                break;
            }
            if !in_common || s.is_empty() {
                continue;
            }
            let parts: Vec<&str> = s.split_whitespace().collect();
            //Common symbol  size  file
            if parts.len() >= 2 && parts[1] != "size" && parts[1].starts_with("0x") {
                if let Some(sz) = parse_hex(parts[1]) {
                    out.common_symbols.push(Symbol {
                        name: parts[0].to_string(),
                        address: 0,
                        size: sz,
                    });
                }
            }
        }
    }

    // ── Block 3: discarded sections 
    {
        let mut in_disc = false;
        for line in &lines {
            let s = line.trim_end_matches('\r').trim();
            if s.starts_with("Discarded input sections") {
                in_disc = true;
                continue;
            }
            if in_disc && s.starts_with("Linker script") {
                break;
            }
            if !in_disc || s.is_empty() {
                continue;
            }
            // " .section   0xADDR   0xSIZE   file.o"
            let parts: Vec<&str> = s
                .splitn(5, |c: char| c.is_whitespace())
                .filter(|p| !p.is_empty())
                .collect();
            if parts.len() >= 4
                && parts[0].starts_with('.')
                && parse_hex(parts[1]).is_some()
            {
                if let Some(sz) = parse_hex(parts[2]) {
                    if sz > 0 {
                        out.discarded_total += sz;
                        out.discarded.push(DiscardedEntry {
                            section: parts[0].to_string(),
                            size: sz,
                            obj: norm_path(parts[3]),
                        });
                    }
                }
            }
        }
    }

    // ── Block 4: memory map
    {
        // path -> ObjFile
        let mut obj_map: HashMap<String, ObjFile> = HashMap::new();

        let mut in_map = false;
        // The section family that is "current" while we scan lines
        let mut cur_family: Option<SecFamily> = None;
        // The last top-level section name (for `all_sections`)
        let mut cur_top_sec = String::new();
        // Size pending to be assigned to the next symbol line
        let mut pending_sym_size: u64 = 0;

        let mut i = 0;
        while i < n {
            let raw = lines[i].trim_end_matches('\r');
            let s = raw.trim();
            let parts: Vec<&str> = s.split_whitespace().collect();

            if s.starts_with("Linker script and memory map") {
                in_map = true;
                i += 1;
                continue;
            }
            if !in_map || s.is_empty() {
                i += 1;
                continue;
            }

            // Is this line at column 0 (no leading whitespace)?
            let is_toplevel =
                raw.starts_with(|c: char| !c.is_whitespace());

            // ── Fill / padding
            if s.starts_with("*fill*") && parts.len() >= 3 {
                if let Some(sz) = parse_hex(parts[2]) {
                    out.fill_bytes += sz;
                }
                i += 1;
                continue;
            }

            // Skip linker-script expressions / wildcards
            if s.starts_with("*(") || s.starts_with("*(.") {
                i += 1;
                continue;
            }

            //  "name  0xADDR  0xSIZE [...]"
            if is_toplevel && parts.len() >= 3 {
                let maybe_addr = parse_hex(parts[1]);
                let maybe_size = parse_hex(parts[2]);
                if maybe_addr.is_some() && maybe_size.is_some() {
                    let sec_name = parts[0];
                    let addr = maybe_addr.unwrap();
                    let sz = maybe_size.unwrap();
                    let fam = sec_family(sec_name);

                    // Only accumulate into main totals for the four families
                    
                    //  top-level entry AND appear inside a grouped section)
                    match fam {
                        SecFamily::Other => {
                            // Record in all_sections but not in main totals
                        }
                        _ => {
                            // Only add if this is a genuinely independent section
                            // (i.e. not a sub-entry of a grouped section we already counted)
                             // We detect grouped sections by checking if cur_top_sec has
                              // the same family and this one has the same name prefix
                            let same_grouped = cur_top_sec == family_name(fam)
                                || cur_top_sec == sec_name;
                            if !same_grouped {
                                out.totals[fam as usize] += sz;
                            }
                        }
                    }

                    // Track string literal sub-total
                    if sec_name.starts_with(".rodata.str") {
                        out.rodata_str_size += sz;
                    }

                    cur_top_sec = sec_name.to_string();
                    cur_family = Some(fam);
                    pending_sym_size = 0;

                    if sz > 0 {
                        out.all_sections.push((sec_name.to_string(), addr, sz));
                    }

                    i += 1;
                    continue;
                }
            }

            // ".text.funcname" at col 0, single token 
            // Produced by -ffunction-sections / -fdata-sections
            if is_toplevel && parts.len() == 1 && parts[0].starts_with('.') {
                let sec_name = parts[0];
                let fam = sec_family(sec_name);
                cur_family = Some(fam);
                pending_sym_size = 0;

                
                let mut j = i + 1;
                while j < n && lines[j].trim_end_matches('\r').trim().is_empty() {
                    j += 1;
                }
                if j < n {
                    let np: Vec<&str> = lines[j]
                        .trim_end_matches('\r')
                        .trim()
                        .split_whitespace()
                        .collect();
                    if np.len() == 2
                        && np[0].starts_with("0x")
                        && np[1].starts_with("0x")
                    {
                        let addr = parse_hex(np[0]).unwrap_or(0);
                        let sz = parse_hex(np[1]).unwrap_or(0);
                        pending_sym_size = sz;
                        out.totals[fam as usize] += sz;

                        if sec_name.starts_with(".rodata.str") {
                            out.rodata_str_size += sz;
                        }

                        // For .text.* → record as a function entry
                        if fam == SecFamily::Text && sec_name.len() > 6 {
                            let func_name = sec_name[6..].to_string(); // strip ".text."
                            // Find source file from the first indented sub-line
                            let mut src = String::new();
                            let mut k = j + 1;
                            while k < n && lines[k].trim_end_matches('\r').trim().is_empty() {
                                k += 1;
                            }
                            if k < n {
                                let kp: Vec<&str> = lines[k]
                                    .trim_end_matches('\r')
                                    .trim()
                                    .splitn(5, |c: char| c.is_whitespace())
                                    .filter(|p| !p.is_empty())
                                    .collect();
                                if kp.len() >= 4 {
                                    src = norm_path(kp[3]);
                                }
                            }
                            out.functions.push(FuncEntry {
                                name: func_name,
                                size: sz,
                                address: addr,
                                src,
                            });
                        }

                        if sz > 0 {
                            out.all_sections.push((sec_name.to_string(), addr, sz));
                        }
                        i = j + 1;
                        continue;
                    }
                }

                i += 1;
                continue;
            }

            //  " .section  0xADDR  0xSIZE  file.o" ──
            if !is_toplevel && parts.len() >= 4 && parts[0].starts_with('.') {
                if let (Some(_addr), Some(sz)) =
                    (parse_hex(parts[1]), parse_hex(parts[2]))
                {
                    if sz > 0 {
                        let file_path = norm_path(&parts[3..].join(" "));
                        let key = path_basename(&file_path);
                        let fam = sec_family(parts[0]);
                        let entry = obj_map
                            .entry(file_path.clone())
                            .or_insert_with(|| ObjFile {
                                name: key,
                                path: file_path,
                                ..Default::default()
                            });
                        entry.add(fam, sz);
                    }
                }
            }

            // ── "        0xADDR   sym_name" (2 tokens)
            if parts.len() == 2
                && parts[0].starts_with("0x")
                && looks_like_symbol(parts[1])
            {
                if let (Some(addr), Some(fam)) = (parse_hex(parts[0]), cur_family) {
                    out.symbols[fam as usize].push(Symbol {
                        name: parts[1].to_string(),
                        address: addr,
                        size: pending_sym_size,
                    });
                    pending_sym_size = 0;
                }
            }

            i += 1;
        }

        // ── Post-process ──────────────────────────────────────────────────

        // Add common symbols into BSS symbol list
        for cs in &out.common_symbols {
            out.symbols[SecFamily::Bss as usize].push(cs.clone());
        }

        // Deduplicate symbol lists (same name+address can appear in grouped
        // and ungrouped section entries)
        for syms in &mut out.symbols {
            dedup_symbols(syms);
        }

        // Collect + sort object files
        out.obj_files = obj_map.into_values().collect();
        out.obj_files.sort_by(|a, b| b.total().cmp(&a.total()));

        // Sort functions by size descending
        out.functions.sort_by(|a, b| b.size.cmp(&a.size));

        // Sort discarded by size descending
        out.discarded.sort_by(|a, b| b.size.cmp(&a.size));
    }

    // ── Fix double-counting in section totals 
   
    {
        let mut recomputed = [0u64; 5];
        for o in &out.obj_files {
            for (i, &sz) in o.sizes.iter().enumerate() {
                recomputed[i] += sz;
            }
        }
        // Add common symbols to BSS (they live in BSS but may not have subsection lines)
        let common_bss: u64 = out.common_symbols.iter().map(|s| s.size).sum();
        recomputed[SecFamily::Bss as usize] += common_bss;

        // Only override if the recomputed values look plausible (> 0)
        for i in 0..5 {
            if recomputed[i] > 0 {
                out.totals[i] = recomputed[i];
            }
        }
    }

    out
}

fn parse_hex(s: &str) -> Option<u64> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(h, 16).ok()
}

fn looks_like_symbol(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let c = s.chars().next().unwrap();
    if !(c.is_alphabetic() || c == '_' || c == '$') {
        return false;
    }
    // Filter out linker-script keywords
    !matches!(
        s,
        "PROVIDE"
            | "ASSERT"
            | "FILL"
            | "BYTE"
            | "SHORT"
            | "LONG"
            | "QUAD"
            | "ALIGN"
            | "LOADADDR"
            | "SIZEOF"
            | "ORIGIN"
            | "LENGTH"
    ) && !s.contains('(')
        && !s.contains('=')
        && !s.contains('*')
}

///  forward slashes, trimmed.
fn norm_path(s: &str) -> String {
    s.replace('\\', "/").trim().to_string()
}

/// Basename of a path.
pub fn path_basename(path: &str) -> String {
    let p = path.replace('\\', "/");
    //  "path/lib.a(member.o)" → "lib.a(member.o)"
    if p.contains('(') {
        let start = p.rfind('/').map(|i| i + 1).unwrap_or(0);
        return p[start..].to_string();
    }
    p.rsplit('/')
        .next()
        .unwrap_or(&p)
        .to_string()
}

fn dedup_symbols(v: &mut Vec<Symbol>) {
    let mut seen = std::collections::HashSet::new();
    v.retain(|s| seen.insert(format!("{:016x}{}", s.address, s.name)));
}

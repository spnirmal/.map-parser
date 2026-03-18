//! Generic GCC/LD linker map file analyser.

//! Cargo.toml dependencies:
//!   eframe = "0.27"
//!   rfd   = "0.14"

use eframe::egui;
use rfd::FileDialog;
use std::collections::HashMap;
use std::fs;

mod parser;
mod parsed_map;
mod hints;

use parsed_map::{ParsedMap, SecFamily, sec_family, family_name, FuncEntry, ObjFile, Symbol, ArchiveDep};
use parser::{parse_map, path_basename};
use hints::{Severity, generate_hints};
// ════════════════════════════════════════════════════════════════════════════
//  Entry point
// ═══════════════════════════════════════════════════════════════════════════

fn main() -> Result<(), eframe::Error> {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("icon.png")).unwrap();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1450.0, 880.0])
            .with_min_inner_size([1100.0, 700.0])
            .with_title("GCC Map Analyser")
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "GCC Map Analyser",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(MapApp::default())
        }),
    )
}


// ════════════════════════════════════════════════════════════════════════════
//  App state
// ════════════════════════════════════════════════════════════════════════

#[derive(Clone, PartialEq)]
enum Tab {
    Overview,
    Sections,
    Functions,
    ObjectFiles,
    Symbols,
    Discarded,
    Dependencies,
    Optimize,
}

#[derive(Clone, PartialEq)]
enum ObjSort {
    Total,
    Text,
    Rodata,
    Data,
    Bss,
    Name,
    Module,
}

#[derive(Clone, PartialEq)]
enum FnSort {
    Size,
    Name,
    File,
    Address,
}

struct MapApp {
    path: String,
    map: Option<ParsedMap>,
    tab: Tab,
    sym_family: SecFamily,
    sym_filter: String,
    fn_filter: String,
    fn_sort: FnSort,
    obj_sort: ObjSort,
    obj_filter: String,
    dep_filter: String,
    sec_filter: String,
}

impl Default for MapApp {
    fn default() -> Self {
        Self {
            path: String::new(),
            map: None,
            tab: Tab::Overview,
            sym_family: SecFamily::Bss,
            sym_filter: String::new(),
            fn_filter: String::new(),
            fn_sort: FnSort::Size,
            obj_sort: ObjSort::Total,
            obj_filter: String::new(),
            dep_filter: String::new(),
            sec_filter: String::new(),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Visual helpers
// ════════════════════════════════════════════════════════════════════════════

const C_TEXT: egui::Color32 = egui::Color32::from_rgb(90, 155, 240);
const C_RODATA: egui::Color32 = egui::Color32::from_rgb(160, 110, 230);
const C_DATA: egui::Color32 = egui::Color32::from_rgb(65, 195, 125);
const C_BSS: egui::Color32 = egui::Color32::from_rgb(230, 165, 45);
const C_OTHER: egui::Color32 = egui::Color32::from_gray(110);

fn family_color(f: SecFamily) -> egui::Color32 {
    match f {
        SecFamily::Text => C_TEXT,
        SecFamily::Rodata => C_RODATA,
        SecFamily::Data => C_DATA,
        SecFamily::Bss => C_BSS,
        SecFamily::Other => C_OTHER,
    }
}

const MODULE_PALETTE: [egui::Color32; 12] = [
    egui::Color32::from_rgb(90, 155, 240),
    egui::Color32::from_rgb(230, 165, 45),
    egui::Color32::from_rgb(65, 195, 125),
    egui::Color32::from_rgb(210, 65, 65),
    egui::Color32::from_rgb(160, 110, 230),
    egui::Color32::from_rgb(55, 195, 210),
    egui::Color32::from_rgb(220, 120, 50),
    egui::Color32::from_rgb(150, 205, 75),
    egui::Color32::from_rgb(200, 135, 185),
    egui::Color32::from_rgb(100, 220, 175),
    egui::Color32::from_rgb(235, 100, 150),
    egui::Color32::from_rgb(180, 200, 80),
];

fn module_color(i: usize) -> egui::Color32 {
    MODULE_PALETTE[i % MODULE_PALETTE.len()]
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.2} MB ({} B)", b as f64 / 1_048_576.0, b)
    } else if b >= 1024 {
        format!("{:.1} KB ({} B)", b as f64 / 1024.0, b)
    } else {
        format!("{} B", b)
    }
}

fn fmt_bytes_short(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.1}M", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1}K", b as f64 / 1024.0)
    } else {
        format!("{}", b)
    }
}

fn pct(part: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { 100.0 * part as f64 / total as f64 }
}

/// Draw a thin horizontal progress bar.
fn hbar(ui: &mut egui::Ui, frac: f32, color: egui::Color32, h: f32) {
    let avail = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(avail, h), egui::Sense::hover());
    ui.painter().rect_filled(rect, 2.0, egui::Color32::from_gray(38));
    let w = (avail * frac.clamp(0.0, 1.0)).max(0.0);
    if w > 0.0 {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(w, h)),
            2.0,
            color,
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  eframe App
// ════════════════════════════════════════════════════════════════════════════

impl eframe::App for MapApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ── Sidebar ──────────────────────────────────────────────────────────
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .min_width(190.0)
            .max_width(190.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("⚙  GCC MAP ANALYSER")
                        .strong()
                        .size(12.5)
                        .color(egui::Color32::from_gray(215)),
                );
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(6.0);

                if ui
                    .add(
                        egui::Button::new("📂  Open .map file")
                            .min_size(egui::vec2(172.0, 28.0)),
                    )
                    .clicked()
                {
                    if let Some(p) = FileDialog::new()
                        .add_filter("Linker map", &["map", "MAP"])
                        .pick_file()
                    {
                        match fs::read_to_string(&p) {
                            Ok(c) => {
                                self.path = p.display().to_string();
                                self.map = Some(parse_map(&c));
                                self.tab = Tab::Overview;
                            }
                            Err(e) => {
                                self.path = format!("Error: {}", e);
                            }
                        }
                    }
                }

                if !self.path.is_empty() {
                    ui.add_space(3.0);
                    let norm = self.path.replace('\\', "/");
                    let fname = norm.rsplit('/').next().unwrap_or(&norm);
                    ui.label(
                        egui::RichText::new(fname)
                            .small()
                            .color(egui::Color32::from_gray(125)),
                    );
                }

                if self.map.is_some() {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(6.0);

                    let tabs = [
                        (Tab::Overview, "📊", "Overview"),
                        (Tab::Sections, "📦", "Sections"),
                        (Tab::Functions, "⚙", "Functions"),
                        (Tab::ObjectFiles, "📁", "Object Files"),
                        (Tab::Symbols, "🏷", "Symbols"),
                        (Tab::Discarded, "🗑", "Discarded"),
                        (Tab::Dependencies, "🔗", "Dependencies"),
                        (Tab::Optimize, "💡", "Optimise"),
                    ];
                    for (t, icon, label) in tabs {
                        let sel = self.tab == t;
                        let fill = if sel {
                            egui::Color32::from_rgb(30, 55, 95)
                        } else {
                            egui::Color32::TRANSPARENT
                        };
                        let col = if sel {
                            egui::Color32::WHITE
                        } else {
                            egui::Color32::from_gray(170)
                        };
                        let btn = egui::Button::new(
                            egui::RichText::new(format!("{}  {}", icon, label))
                                .size(12.5)
                                .color(col),
                        )
                        .min_size(egui::vec2(172.0, 24.0))
                        .fill(fill);
                        if ui.add(btn).clicked() {
                            self.tab = t;
                        }
                    }

                    if let Some(m) = &self.map {
                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(5.0);

                        let total = m.total();
                        ui.label(
                            egui::RichText::new("Total footprint")
                                .small()
                                .color(egui::Color32::from_gray(115)),
                        );
                        ui.label(egui::RichText::new(fmt_bytes(total)).strong().size(13.0));
                        ui.add_space(5.0);

                        for fam in [
                            SecFamily::Text,
                            SecFamily::Rodata,
                            SecFamily::Data,
                            SecFamily::Bss,
                        ] {
                            let sz = m.totals[fam as usize];
                            ui.horizontal(|ui| {
                                ui.colored_label(family_color(fam), "■");
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {}",
                                        family_name(fam),
                                        fmt_bytes_short(sz)
                                    ))
                                    .small()
                                    .color(egui::Color32::from_gray(165)),
                                );
                            });
                        }

                        // Optimise badge
                        let hints = generate_hints(m);
                        let nc = hints.iter().filter(|h| h.severity == Severity::Critical).count();
                        let nw = hints.iter().filter(|h| h.severity == Severity::Warning).count();
                        if nc + nw > 0 {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(4.0);
                            if nc > 0 {
                                ui.label(
                                    egui::RichText::new(format!("🔴 {} critical", nc))
                                        .small()
                                        .color(egui::Color32::from_rgb(220, 60, 60)),
                                );
                            }
                            if nw > 0 {
                                ui.label(
                                    egui::RichText::new(format!("🟡 {} warnings", nw))
                                        .small()
                                        .color(egui::Color32::from_rgb(220, 165, 30)),
                                );
                            }
                        }
                    }
                }
            });

        // ── Central panel ────────────────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.map.is_none() {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(
                            egui::RichText::new("GCC / GNU ld  Map File Analyser")
                                .size(22.0)
                                .strong()
                                .color(egui::Color32::from_gray(200)),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new(
                                "Open any .map file produced by GCC/ld to begin analysis.\n\
                                 Works with ARM, RISC-V, x86, MIPS, AVR and any other GCC target.",
                            )
                            .size(14.0)
                            .color(egui::Color32::from_gray(110)),
                        );
                    });
                });
                return;
            }
            let m = self.map.as_ref().unwrap().clone();
            match self.tab.clone() {
                Tab::Overview => self.tab_overview(ui, &m),
                Tab::Sections => self.tab_sections(ui, &m),
                Tab::Functions => self.tab_functions(ui, &m),
                Tab::ObjectFiles => self.tab_object_files(ui, &m),
                Tab::Symbols => self.tab_symbols(ui, &m),
                Tab::Discarded => self.tab_discarded(ui, &m),
                Tab::Dependencies => self.tab_dependencies(ui, &m),
                Tab::Optimize => self.tab_optimize(ui, &m),
            }
        });
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  Tab: Overview
// ════════════════════════════════════════════════════════════════════════════

impl MapApp {
    fn tab_overview(&self, ui: &mut egui::Ui, m: &ParsedMap) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Firmware Memory Overview");
            ui.add_space(8.0);

            let total = m.total();

            // ── Stat cards ────────────────────────────────────────────────────
            ui.columns(4, |cols| {
                for (i, fam) in [
                    SecFamily::Text,
                    SecFamily::Rodata,
                    SecFamily::Data,
                    SecFamily::Bss,
                ]
                .iter()
                .enumerate()
                {
                    let sz = m.totals[*fam as usize];
                    let p = pct(sz, total) as f32 / 100.0;
                    let col = family_color(*fam);
                    let (desc, mem_type) = match fam {
                        SecFamily::Text => ("Executable code", "Flash (XIP)"),
                        SecFamily::Rodata => ("Read-only constants", "Flash"),
                        SecFamily::Data => ("Initialised globals", "Flash + RAM"),
                        SecFamily::Bss => ("Zero-init RAM", "RAM only"),
                        _ => ("", ""),
                    };
                    egui::Frame::none()
                        .fill(egui::Color32::from_gray(26))
                        .rounding(6.0)
                        .inner_margin(10.0_f32)
                        .show(&mut cols[i], |ui| {
                            ui.label(
                                egui::RichText::new(family_name(*fam))
                                    .strong()
                                    .size(15.0)
                                    .color(col),
                            );
                            ui.label(egui::RichText::new(fmt_bytes(sz)).size(12.5));
                            ui.label(
                                egui::RichText::new(format!("{:.1}% of total", pct(sz, total)))
                                    .small()
                                    .color(egui::Color32::from_gray(145)),
                            );
                            ui.add_space(4.0);
                            hbar(ui, p, col, 5.0);
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(desc).small().color(egui::Color32::from_gray(130)),
                            );
                            ui.label(
                                egui::RichText::new(mem_type)
                                    .small()
                                    .color(col.linear_multiply(0.7)),
                            );
                        });
                }
            });

            ui.add_space(10.0);

            // ── Proportional memory bar
            ui.label(egui::RichText::new("Section proportions").strong());
            ui.add_space(4.0);
            let avail = ui.available_width();
            let (rect, _) =
                ui.allocate_exact_size(egui::vec2(avail, 32.0), egui::Sense::hover());
            let mut x = rect.min.x;
            for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                let sz = m.totals[fam as usize];
                let w = avail * (pct(sz, total) as f32 / 100.0);
                if w >= 1.0 {
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(
                            egui::pos2(x, rect.min.y),
                            egui::vec2(w, 32.0),
                        ),
                        0.0,
                        family_color(fam),
                    );
                    if w > 50.0 {
                        ui.painter().text(
                            egui::pos2(x + w / 2.0, rect.min.y + 16.0),
                            egui::Align2::CENTER_CENTER,
                            fmt_bytes_short(sz),
                            egui::FontId::proportional(10.0),
                            egui::Color32::from_gray(230),
                        );
                    }
                    x += w;
                }
            }
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                    ui.colored_label(family_color(fam), format!("■ {}", family_name(fam)));
                    ui.add_space(6.0);
                }
            });

            ui.add_space(14.0);

            // ── Two columns
            ui.columns(2, |cols| {
                cols[0].label(egui::RichText::new("BSS contribution by module").strong());
                cols[0].add_space(4.0);

                let mut mod_bss: Vec<(String, u64)> = {
                    let mut map: HashMap<String, u64> = HashMap::new();
                    for o in &m.obj_files {
                        *map.entry(o.module()).or_default() += o.get(SecFamily::Bss);
                    }
                    map.into_iter().filter(|(_, v)| *v > 0).collect()
                };
                mod_bss.sort_by(|a, b| b.1.cmp(&a.1));
                let bss_max = mod_bss.first().map(|x| x.1).unwrap_or(1);

                for (idx, (mname, bss)) in mod_bss.iter().take(12).enumerate() {
                    let col = module_color(idx);
                    cols[0].horizontal(|ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(130.0, 14.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                let label = if mname.len() > 18 {
                                    &mname[..18]
                                } else {
                                    mname.as_str()
                                };
                                ui.label(egui::RichText::new(label).small().color(col));
                            },
                        );
                        let size_w = 44.0;
                        let bw = ((ui.available_width() - size_w)
                            * (*bss as f32 / bss_max as f32))
                            .max(2.0);
                        let (r, _) = ui.allocate_exact_size(
                            egui::vec2(bw, 13.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(r, 2.0, col);
                        ui.label(
                            egui::RichText::new(fmt_bytes_short(*bss))
                                .small()
                                .color(egui::Color32::from_gray(155)),
                        );
                    });
                }

                cols[1].label(egui::RichText::new("Function size distribution").strong());
                cols[1].add_space(4.0);

                let ranges: &[(u64, u64, &str)] = &[
                    (0, 64, "<64"),
                    (64, 128, "64-128"),
                    (128, 256, "128-256"),
                    (256, 512, "256-512"),
                    (512, 1024, "512-1K"),
                    (1024, 2048, "1K-2K"),
                    (2048, u64::MAX, ">2K"),
                ];
                let buckets: Vec<u64> = ranges
                    .iter()
                    .map(|(lo, hi, _)| {
                        m.functions
                            .iter()
                            .filter(|f| f.size >= *lo && f.size < *hi)
                            .count() as u64
                    })
                    .collect();
                let bmax = buckets.iter().copied().max().unwrap_or(1);
                let avail1 = cols[1].available_width();
                let bw1 = (avail1 - 8.0) / ranges.len() as f32;
                let ch = 110.0;
                let (cr, _) = cols[1].allocate_exact_size(
                    egui::vec2(avail1, ch + 22.0),
                    egui::Sense::hover(),
                );

                for (idx, (cnt, (_, _, label))) in
                    buckets.iter().zip(ranges.iter()).enumerate()
                {
                    let bh = ch * (*cnt as f32 / bmax as f32);
                    let x = cr.min.x + idx as f32 * bw1;
                    let y = cr.min.y + ch - bh;
                    let color = if idx >= 6 {
                        egui::Color32::from_rgb(220, 60, 60)
                    } else if idx >= 5 {
                        egui::Color32::from_rgb(220, 165, 30)
                    } else {
                        C_TEXT
                    };
                    if bh > 0.0 {
                        cols[1].painter().rect_filled(
                            egui::Rect::from_min_size(
                                egui::pos2(x + 2.0, y),
                                egui::vec2(bw1 - 4.0, bh),
                            ),
                            2.0,
                            color,
                        );
                    }
                    cols[1].painter().text(
                        egui::pos2(x + bw1 / 2.0, cr.min.y + ch + 3.0),
                        egui::Align2::CENTER_TOP,
                        label,
                        egui::FontId::proportional(9.0),
                        egui::Color32::from_gray(145),
                    );
                    if *cnt > 0 {
                        cols[1].painter().text(
                            egui::pos2(x + bw1 / 2.0, y - 2.0),
                            egui::Align2::CENTER_BOTTOM,
                            cnt.to_string(),
                            egui::FontId::proportional(9.0),
                            color,
                        );
                    }
                }
            });

            ui.add_space(14.0);
            ui.separator();
            ui.add_space(8.0);

            // ── Key metrics + top functions 
            ui.columns(2, |cols| {
                cols[0].label(egui::RichText::new("Key metrics").strong());
                cols[0].add_space(4.0);
                egui::Grid::new("kv").spacing([14.0, 4.0]).show(&mut cols[0], |ui| {
                    let rows: &[(&str, String)] = &[
                        ("Flash (text+rodata+data)", fmt_bytes(m.flash_total())),
                        ("RAM (data+bss)", fmt_bytes(m.ram_total())),
                        ("String literals (.rodata.str*)", fmt_bytes(m.rodata_str_size)),
                        ("Functions (with sizes)", m.functions.len().to_string()),
                        (
                            "Largest function",
                            m.functions
                                .first()
                                .map(|f| format!("{} ({} B)", f.name, f.size))
                                .unwrap_or_else(|| "n/a (no -ffunction-sections)".into()),
                        ),
                        ("Object files", m.obj_files.len().to_string()),
                        ("BSS symbols", m.symbols[SecFamily::Bss as usize].len().to_string()),
                        ("Common symbols", m.common_symbols.len().to_string()),
                        ("Alignment padding", fmt_bytes(m.fill_bytes)),
                        ("Discarded (dead code)", fmt_bytes(m.discarded_total)),
                        ("Archive dependencies", m.archive_deps.len().to_string()),
                    ];
                    for (k, v) in rows {
                        ui.label(
                            egui::RichText::new(*k).small().color(egui::Color32::from_gray(145)),
                        );
                        ui.label(egui::RichText::new(v).strong().small());
                        ui.end_row();
                    }
                });

                // Top 10 functions bar 
                cols[1].label(egui::RichText::new("Top 10 largest functions").strong());
                cols[1].add_space(4.0);
                if m.functions.is_empty() {
                    cols[1].label(
                        egui::RichText::new(
                            "No function sections found.\nBuild with -ffunction-sections.",
                        )
                        .small()
                        .color(egui::Color32::from_gray(120)),
                    );
                } else {
                    let max_sz = m.functions.first().map(|f| f.size).unwrap_or(1);
                    let avail = cols[1].available_width() - 130.0;
                    for f in m.functions.iter().take(10) {
                        cols[1].horizontal(|ui| {
                            let col = if f.size >= 2000 {
                                egui::Color32::from_rgb(220, 60, 60)
                            } else if f.size >= 1000 {
                                egui::Color32::from_rgb(220, 165, 30)
                            } else {
                                C_TEXT
                            };
                            let bw = (avail * f.size as f32 / max_sz as f32).max(2.0);
                            let (r, _) = ui.allocate_exact_size(
                                egui::vec2(bw, 14.0),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(r, 2.0, col);
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(format!("{} — {} B", f.name, f.size))
                                    .small()
                                    .color(col),
                            );
                        });
                    }
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Sections
    // ════════════════════════════════════════════════════════════════════════

    fn tab_sections(&mut self, ui: &mut egui::Ui, m: &ParsedMap) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Memory Sections");
            ui.add_space(6.0);

            let total = m.total();

            // ── Per-module stacked bars ───────────────────────────────────────
            ui.label(egui::RichText::new("Per-module breakdown (stacked by section family)").strong());
            ui.add_space(5.0);

            let mut mod_sizes: HashMap<String, [u64; 4]> = HashMap::new();
            for o in &m.obj_files {
                let e = mod_sizes.entry(o.module()).or_insert([0u64; 4]);
                e[0] += o.get(SecFamily::Text);
                e[1] += o.get(SecFamily::Rodata);
                e[2] += o.get(SecFamily::Data);
                e[3] += o.get(SecFamily::Bss);
            }
            let mut mods: Vec<(String, [u64; 4])> = mod_sizes.into_iter().collect();
            mods.sort_by(|a, b| {
                let ta: u64 = a.1.iter().sum();
                let tb: u64 = b.1.iter().sum();
                tb.cmp(&ta)
            });

            let label_w = 160.0;
            let size_text_w = 52.0;

            for (idx, (mname, sizes)) in mods.iter().enumerate() {
                let mt: u64 = sizes.iter().sum();
                if mt == 0 { continue; }
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(label_w, 16.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            let lbl = if mname.len() > 22 { &mname[..22] } else { mname.as_str() };
                            ui.label(egui::RichText::new(lbl).small().color(module_color(idx)));
                        },
                    );
                    let bar_w = (ui.available_width() - size_text_w).max(4.0);
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(bar_w, 16.0),
                        egui::Sense::hover(),
                    );
                    let fams = [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss];
                    let mut x = rect.min.x;
                    for (fi, fam) in fams.iter().enumerate() {
                        let w = bar_w * (sizes[fi] as f32 / total.max(1) as f32);
                        if w >= 1.0 {
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(
                                    egui::pos2(x, rect.min.y),
                                    egui::vec2(w, 16.0),
                                ),
                                0.0,
                                family_color(*fam),
                            );
                            x += w;
                        }
                    }
                    ui.label(
                        egui::RichText::new(fmt_bytes_short(mt))
                            .small()
                            .color(egui::Color32::from_gray(165)),
                    );
                });
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                    ui.colored_label(family_color(fam), format!("■ {}", family_name(fam)));
                    ui.add_space(8.0);
                }
            });

            ui.add_space(14.0);
            ui.separator();
            ui.add_space(8.0);

            // ── Section family summary 
            ui.label(egui::RichText::new("Section family summary").strong());
            ui.add_space(4.0);
            egui::Grid::new("secsum").striped(true).spacing([20.0, 5.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Family").strong());
                ui.label(egui::RichText::new("Size").strong());
                ui.label(egui::RichText::new("% total").strong());
                ui.label(egui::RichText::new("Symbols").strong());
                ui.label(egui::RichText::new("Memory").strong());
                ui.end_row();

                for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                    let sz = m.totals[fam as usize];
                    let nsyms = m.symbols[fam as usize].len();
                    let mem = match fam {
                        SecFamily::Text => "Flash (XIP)",
                        SecFamily::Rodata => "Flash",
                        SecFamily::Data => "Flash + RAM",
                        SecFamily::Bss => "RAM only",
                        _ => "",
                    };
                    ui.colored_label(family_color(fam), egui::RichText::new(family_name(fam)).monospace().strong());
                    ui.label(fmt_bytes(sz));
                    ui.label(format!("{:.1}%", pct(sz, total)));
                    ui.label(nsyms.to_string());
                    ui.label(egui::RichText::new(mem).small().color(egui::Color32::from_gray(145)));
                    ui.end_row();
                }
                if m.rodata_str_size > 0 {
                    ui.colored_label(C_RODATA, egui::RichText::new("  ↳ .rodata.str*").monospace().small());
                    ui.label(egui::RichText::new(fmt_bytes(m.rodata_str_size)).small());
                    ui.label(egui::RichText::new(format!("{:.0}% of .rodata", pct(m.rodata_str_size, m.totals[SecFamily::Rodata as usize]))).small());
                    ui.label(""); ui.label(""); ui.end_row();
                }
                ui.separator(); ui.separator(); ui.separator(); ui.separator(); ui.separator(); ui.end_row();
                ui.label(egui::RichText::new("TOTAL").strong());
                ui.label(egui::RichText::new(fmt_bytes(total)).strong());
                ui.label("100%"); ui.label(""); ui.label(""); ui.end_row();
            });

            ui.add_space(14.0);
            ui.separator();
            ui.add_space(8.0);

            // ── All individual sections (filterable) 
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("All sections").strong());
                ui.add_space(10.0);
                ui.label("🔍");
                ui.text_edit_singleline(&mut self.sec_filter);
                if !self.sec_filter.is_empty() && ui.button("✕").clicked() {
                    self.sec_filter.clear();
                }
            });
            ui.add_space(4.0);

            let sf = self.sec_filter.to_lowercase();
            let filtered_secs: Vec<&(String, u64, u64)> = m
                .all_sections
                .iter()
                .filter(|(name, _, _)| sf.is_empty() || name.to_lowercase().contains(&sf))
                .collect();

            egui::ScrollArea::vertical().id_source("sec_tbl").max_height(300.0).show(ui, |ui| {
                egui::Grid::new("sec_grid").striped(true).spacing([18.0, 4.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Section").strong());
                    ui.label(egui::RichText::new("Address").strong());
                    ui.label(egui::RichText::new("Size").strong());
                    ui.label(egui::RichText::new("Family").strong());
                    ui.end_row();
                    for (name, addr, sz) in &filtered_secs {
                        let fam = sec_family(name);
                        let col = family_color(fam);
                        ui.monospace(egui::RichText::new(name.as_str()).color(col));
                        ui.monospace(
                            egui::RichText::new(format!("0x{:08x}", addr))
                                .color(egui::Color32::from_gray(140)),
                        );
                        ui.label(fmt_bytes(*sz));
                        ui.label(egui::RichText::new(family_name(fam)).small().color(col));
                        ui.end_row();
                    }
                });
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Functions
    // ════════════════════════════════════════════════════════════════════════

    fn tab_functions(&mut self, ui: &mut egui::Ui, m: &ParsedMap) {
        ui.heading("Function Analysis");
        ui.add_space(6.0);

        if m.functions.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No per-function sections found in this map file.\n\n\
                     To enable function-level analysis, rebuild with:\n\
                     CFLAGS += -ffunction-sections -fdata-sections\n\
                     LDFLAGS += -Wl,--gc-sections",
                )
                .color(egui::Color32::from_gray(160)),
            );
            return;
        }

        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.text_edit_singleline(&mut self.fn_filter);
            if !self.fn_filter.is_empty() && ui.button("✕").clicked() {
                self.fn_filter.clear();
            }
            ui.add_space(16.0);
            ui.label("Sort:");
            for (s, lbl) in [
                (FnSort::Size, "Size"),
                (FnSort::Name, "Name"),
                (FnSort::File, "Source"),
                (FnSort::Address, "Address"),
            ] {
                if ui.selectable_label(self.fn_sort == s, lbl).clicked() {
                    self.fn_sort = s;
                }
            }
        });

        ui.add_space(6.0);

        let fl = self.fn_filter.to_lowercase();
        let mut funcs: Vec<&FuncEntry> = m
            .functions
            .iter()
            .filter(|f| {
                fl.is_empty()
                    || f.name.to_lowercase().contains(&fl)
                    || f.src.to_lowercase().contains(&fl)
            })
            .collect();

        match self.fn_sort {
            FnSort::Size => funcs.sort_by(|a, b| b.size.cmp(&a.size)),
            FnSort::Name => funcs.sort_by(|a, b| a.name.cmp(&b.name)),
            FnSort::File => funcs.sort_by(|a, b| a.src.cmp(&b.src)),
            FnSort::Address => funcs.sort_by(|a, b| a.address.cmp(&b.address)),
        }

        let total_text = m.totals[SecFamily::Text as usize];
        let shown_sz: u64 = funcs.iter().map(|f| f.size).sum();

        ui.label(
            egui::RichText::new(format!(
                "{} functions — {} ({:.1}% of .text)",
                funcs.len(),
                fmt_bytes(shown_sz),
                pct(shown_sz, total_text)
            ))
            .color(egui::Color32::from_gray(150)),
        );
        ui.add_space(4.0);

        // Top-20 horizontal bar chart
        let top = 20.min(funcs.len());
        if top > 0 {
            let max_sz = funcs[0].size.max(1);
            egui::ScrollArea::vertical()
                .id_source("fn_bars")
                .max_height(240.0)
                .show(ui, |ui| {
                    for f in funcs.iter().take(top) {
                        ui.horizontal(|ui| {
                            let col = if f.size >= 2000 {
                                egui::Color32::from_rgb(220, 60, 60)
                            } else if f.size >= 1000 {
                                egui::Color32::from_rgb(220, 165, 30)
                            } else {
                                C_TEXT
                            };
                            // Reserve space for name label (right side), bar fhe rest
                           let label_reserve = 280.0;
                            let bw = ((ui.available_width() - label_reserve)
                                * (f.size as f32 / max_sz as f32))
                                .max(2.0);
                            let (r, _) = ui.allocate_exact_size(
                                egui::vec2(bw, 14.0),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(r, 2.0, col);
                            ui.add_space(4.0);
                            ui.monospace(egui::RichText::new(&f.name).size(11.0).color(col));
                            ui.label(
                                egui::RichText::new(format!("  {} B", f.size))
                                    .small()
                                    .color(egui::Color32::from_gray(145)),
                            );
                        });
                    }
                });
            ui.add_space(6.0);
        }

         ui.separator();
        ui.add_space(4.0);

        egui::ScrollArea::vertical().id_source("fn_tbl").show(ui, |ui| {
            egui::Grid::new("fn_grid").striped(true).spacing([18.0, 4.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Function").strong());
                ui.label(egui::RichText::new("Size (B)").strong());
                ui.label(egui::RichText::new("Address").strong());
                ui.label(egui::RichText::new("Source file").strong());
                ui.end_row();
                for f in &funcs {
                    ui.monospace(&f.name);
                    let col = if f.size >= 2000 {
                        egui::Color32::from_rgb(220, 60, 60)
                    } else if f.size >= 1000 {
                        egui::Color32::from_rgb(220, 165, 30)
                    } else {
                        egui::Color32::from_gray(205)
                    };
                    ui.label(egui::RichText::new(f.size.to_string()).color(col));
                    ui.monospace(
                        egui::RichText::new(format!("0x{:08x}", f.address))
                            .small()
                            .color(egui::Color32::from_gray(130)),
                    );
                    ui.label(
                        egui::RichText::new(path_basename(&f.src))
                            .small()
                            .color(egui::Color32::from_gray(130)),
                    );
                    ui.end_row();
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Object Files
    // ════════════════════════════════════════════════════════════════════════

    fn tab_object_files(&mut self, ui: &mut egui::Ui, m: &ParsedMap) {
        ui.heading("Object File Breakdown");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.text_edit_singleline(&mut self.obj_filter);
            if !self.obj_filter.is_empty() && ui.button("✕").clicked() {
                self.obj_filter.clear();
            }
            ui.add_space(14.0);
            ui.label("Sort:");
            for (s, lbl) in [
                (ObjSort::Total, "Total"),
                (ObjSort::Text, ".text"),
                (ObjSort::Rodata, ".rodata"),
                (ObjSort::Data, ".data"),
                (ObjSort::Bss, ".bss"),
                (ObjSort::Name, "Name"),
                (ObjSort::Module, "Module"),
            ] {
                if ui.selectable_label(self.obj_sort == s, lbl).clicked() {
                    self.obj_sort = s;
                }
            }
        });

        ui.add_space(6.0);

        let of = self.obj_filter.to_lowercase();
        let mut objs: Vec<&ObjFile> = m
            .obj_files
            .iter()
            .filter(|o| {
                o.total() > 0
                    && (of.is_empty()
                        || o.name.to_lowercase().contains(&of)
                        || o.path.to_lowercase().contains(&of)
                        || o.module().to_lowercase().contains(&of))
            })
            .collect();

        match self.obj_sort {
            ObjSort::Total => objs.sort_by(|a, b| b.total().cmp(&a.total())),
            ObjSort::Text => objs.sort_by(|a, b| b.get(SecFamily::Text).cmp(&a.get(SecFamily::Text))),
            ObjSort::Rodata => objs.sort_by(|a, b| b.get(SecFamily::Rodata).cmp(&a.get(SecFamily::Rodata))),
            ObjSort::Data => objs.sort_by(|a, b| b.get(SecFamily::Data).cmp(&a.get(SecFamily::Data))),
            ObjSort::Bss => objs.sort_by(|a, b| b.get(SecFamily::Bss).cmp(&a.get(SecFamily::Bss))),
            ObjSort::Name => objs.sort_by(|a, b| a.name.cmp(&b.name)),
            ObjSort::Module => objs.sort_by(|a, b| a.module().cmp(&b.module())),
        }

        ui.label(
            egui::RichText::new(format!("{} objects", objs.len()))
                .color(egui::Color32::from_gray(150)),
        );
        ui.add_space(4.0);

        let max_total = objs.first().map(|o| o.total()).unwrap_or(1);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("obj_g").striped(true).spacing([8.0, 3.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Object file").strong());
                ui.label(egui::RichText::new("Bar").strong());
                ui.label(egui::RichText::new(".text").strong().color(C_TEXT));
                ui.label(egui::RichText::new(".rodata").strong().color(C_RODATA));
                ui.label(egui::RichText::new(".data").strong().color(C_DATA));
                ui.label(egui::RichText::new(".bss").strong().color(C_BSS));
                ui.label(egui::RichText::new("Total").strong());
                ui.label(egui::RichText::new("Module").strong());
                ui.end_row();

                for o in &objs {
                    let tot = o.total();
                    let bw = (250.0 * tot as f32 / max_total as f32).max(2.0);
                    ui.monospace(egui::RichText::new(&o.name).size(11.0));

                    // Stacked bar
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(bw, 14.0),
                        egui::Sense::hover(),
                    );
                    let mut x = rect.min.x;
                    for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                        let sz = o.get(fam);
                        if sz > 0 {
                            let pw = bw * sz as f32 / tot as f32;
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(
                                    egui::pos2(x, rect.min.y),
                                    egui::vec2(pw, 14.0),
                                ),
                                0.0,
                                family_color(fam),
                            );
                            x += pw;
                        }
                    }

                    for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                        let sz = o.get(fam);
                        ui.label(
                            egui::RichText::new(if sz > 0 { sz.to_string() } else { "—".into() })
                                .small()
                                .color(if sz > 0 {
                                    family_color(fam)
                                } else {
                                    egui::Color32::from_gray(55)
                                }),
                        );
                    }
                    ui.label(egui::RichText::new(fmt_bytes_short(tot)).strong().small());
                    ui.label(
                        egui::RichText::new(o.module())
                            .small()
                            .color(egui::Color32::from_gray(130)),
                    );
                    ui.end_row();
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Symbols
    // ════════════════════════════════════════════════════════════════════════

    fn tab_symbols(&mut self, ui: &mut egui::Ui, m: &ParsedMap) {
        ui.heading("Symbol Table");
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss] {
                let col = family_color(fam);
                if ui
                    .selectable_label(
                        self.sym_family == fam,
                        egui::RichText::new(family_name(fam)).color(col),
                    )
                    .clicked()
                {
                    self.sym_family = fam;
                }
            }
            ui.add_space(16.0);
            ui.label("🔍");
            ui.text_edit_singleline(&mut self.sym_filter);
            if !self.sym_filter.is_empty() && ui.button("✕").clicked() {
                self.sym_filter.clear();
            }
        });

        ui.add_space(6.0);

        let syms = &m.symbols[self.sym_family as usize];
        let sf = self.sym_filter.to_lowercase();
        let filtered: Vec<&Symbol> = syms
            .iter()
            .filter(|s| sf.is_empty() || s.name.to_lowercase().contains(&sf))
            .collect();

        ui.label(
            egui::RichText::new(format!("{} of {} symbols", filtered.len(), syms.len()))
                .color(egui::Color32::from_gray(145)),
        );
        ui.add_space(4.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("sym_g").striped(true).spacing([18.0, 4.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Symbol").strong());
                ui.label(egui::RichText::new("Address").strong());
                ui.label(egui::RichText::new("Size (B)").strong());
                ui.end_row();
                for s in &filtered {
                    ui.monospace(&s.name);
                    ui.monospace(
                        egui::RichText::new(format!("0x{:08x}", s.address))
                            .color(egui::Color32::from_gray(135)),
                    );
                    if s.size > 0 {
                        ui.monospace(s.size.to_string());
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::from_gray(55)));
                    }
                    ui.end_row();
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Discarded
    // ════════════════════════════════════════════════════════════════════════

    fn tab_discarded(&self, ui: &mut egui::Ui, m: &ParsedMap) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Discarded Input Sections");
            ui.add_space(4.0);
            if m.discarded.is_empty() {
                ui.label(egui::RichText::new(
                    "No discarded sections found.\n\
                     This may mean --gc-sections was not used, or all code was reachable."
                ).color(egui::Color32::from_gray(150)));
                return;
            }
            ui.label(
                egui::RichText::new(format!(
                    "{} sections discarded — {} of dead code/data eliminated at link time.",
                    m.discarded.len(),
                    fmt_bytes(m.discarded_total)
                ))
                .color(egui::Color32::from_gray(155)),
            );
            ui.add_space(8.0);

            // Group by section family for bar
            let mut by_fam: HashMap<SecFamily, u64> = HashMap::new();
            for d in &m.discarded {
                *by_fam.entry(sec_family(&d.section)).or_default() += d.size;
            }
            let max_v = by_fam.values().copied().max().unwrap_or(1);
            let avail = ui.available_width();
            let bw = (avail / by_fam.len().max(1) as f32 - 10.0).max(30.0);

            ui.horizontal(|ui| {
                for fam in [SecFamily::Text, SecFamily::Rodata, SecFamily::Data, SecFamily::Bss, SecFamily::Other] {
                    if let Some(sz) = by_fam.get(&fam) {
                        if *sz == 0 { continue; }
                        let bh = 20.0 + 60.0 * (*sz as f32 / max_v as f32);
                        let col = family_color(fam);
                        ui.vertical(|ui| {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(bw, bh), egui::Sense::hover());
                            ui.painter().rect_filled(r, 3.0, col);
                            ui.label(egui::RichText::new(family_name(fam)).small().color(col));
                            ui.label(egui::RichText::new(fmt_bytes_short(*sz)).small().strong());
                        });
                        ui.add_space(6.0);
                    }
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            egui::Grid::new("disc_g").striped(true).spacing([14.0, 4.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Section").strong());
                ui.label(egui::RichText::new("Size (B)").strong());
                ui.label(egui::RichText::new("Object file").strong());
                ui.end_row();
                for d in &m.discarded {
                    let col = family_color(sec_family(&d.section));
                    ui.monospace(egui::RichText::new(&d.section).small().color(col));
                    ui.label(d.size.to_string());
                    ui.label(
                        egui::RichText::new(path_basename(&d.obj))
                            .small()
                            .color(egui::Color32::from_gray(130)),
                    );
                    ui.end_row();
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Dependencies (archive members)
    // ════════════════════════════════════════════════════════════════════════

    fn tab_dependencies(&mut self, ui: &mut egui::Ui, m: &ParsedMap) {
        ui.heading("Archive Dependencies");
        ui.add_space(4.0);

        if m.archive_deps.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No archive member dependency records found.\n\
                     These are present only when the linker pulls in library members."
                )
                .color(egui::Color32::from_gray(150)),
            );
            return;
        }

        ui.label(
            egui::RichText::new(format!(
                "{} archive members pulled in. Filter to trace which object file \
                 required which library.",
                m.archive_deps.len()
            ))
            .color(egui::Color32::from_gray(155)),
        );
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.text_edit_singleline(&mut self.dep_filter);
            if !self.dep_filter.is_empty() && ui.button("✕").clicked() {
                self.dep_filter.clear();
            }
        });
        ui.add_space(4.0);

        let df = self.dep_filter.to_lowercase();
        let filtered: Vec<&ArchiveDep> = m
            .archive_deps
            .iter()
            .filter(|d| {
                df.is_empty()
                    || d.member.to_lowercase().contains(&df)
                    || d.needed_by.to_lowercase().contains(&df)
                    || d.symbol.to_lowercase().contains(&df)
            })
            .collect();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("dep_g").striped(true).spacing([14.0, 4.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Library member").strong());
                ui.label(egui::RichText::new("Needed by").strong());
                ui.label(egui::RichText::new("Symbol").strong());
                ui.end_row();
                for d in &filtered {
                    ui.monospace(
                        egui::RichText::new(path_basename(&d.member))
                            .small()
                            .color(C_RODATA),
                    );
                    ui.label(
                        egui::RichText::new(path_basename(&d.needed_by))
                            .small()
                            .color(egui::Color32::from_gray(165)),
                    );
                    ui.label(
                        egui::RichText::new(&d.symbol)
                            .small()
                            .color(egui::Color32::from_gray(130)),
                    );
                    ui.end_row();
                }
            });
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Tab: Optimise
    // ════════════════════════════════════════════════════════════════════════

    fn tab_optimize(&self, ui: &mut egui::Ui, m: &ParsedMap) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("💡 Optimisation Recommendations");
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "All findings are derived automatically from the map file's own data. \
                     No project-specific assumptions are made.",
                )
                .small()
                .color(egui::Color32::from_gray(145)),
            );
            ui.add_space(10.0);

            let hints = generate_hints(m);

            if hints.is_empty() {
                ui.label(egui::RichText::new("No actionable issues detected.").color(egui::Color32::from_gray(150)));
            } else {
                // Summary badges
                ui.horizontal(|ui| {
                    for sev in [Severity::Critical, Severity::Warning, Severity::Info] {
                        let cnt = hints.iter().filter(|h| h.severity == sev).count();
                        if cnt == 0 { continue; }
                        egui::Frame::none()
                            .fill(sev.bg())
                            .rounding(4.0)
                            .inner_margin(egui::vec2(8.0, 4.0))
                            .show(ui, |ui| {
                                let icon = match sev {
                                    Severity::Critical => "🔴",
                                    Severity::Warning => "🟡",
                                    Severity::Info => "🔵",
                                };
                                ui.label(
                                    egui::RichText::new(format!("{}  {} {}", icon, cnt, sev.label()))
                                        .strong()
                                        .color(sev.color()),
                                );
                            });
                        ui.add_space(4.0);
                    }
                });
                ui.add_space(10.0);

                for hint in &hints {
                    egui::Frame::none()
                        .fill(hint.severity.bg())
                        .rounding(6.0)
                        .inner_margin(12.0_f32)
                        .outer_margin(egui::vec2(0.0, 4.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let col = hint.severity.color();
                                egui::Frame::none()
                                    .fill(col.linear_multiply(0.2))
                                    .rounding(3.0)
                                    .inner_margin(egui::vec2(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new(hint.severity.label())
                                                .strong()
                                                .small()
                                                .color(col),
                                        );
                                    });
                                ui.add_space(6.0);
                                ui.label(egui::RichText::new(&hint.title).strong().size(13.0));
                            });
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(&hint.detail)
                                    .size(12.0)
                                    .color(egui::Color32::from_gray(198)),
                            );
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new("Estimated saving: ")
                                        .small()
                                        .color(egui::Color32::from_gray(125)),
                                );
                                ui.label(
                                    egui::RichText::new(&hint.saving)
                                        .small()
                                        .strong()
                                        .color(egui::Color32::from_rgb(95, 220, 120)),
                                );
                            });
                        });
                }
            }

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);

            ui.label(egui::RichText::new("General GCC firmware optimisation checklist").strong().size(14.0));
            ui.add_space(6.0);

            let tips: &[(&str, &str)] = &[
                ("Dead-code elimination",
                 "-ffunction-sections -fdata-sections (CFLAGS)  +  -Wl,--gc-sections (LDFLAGS)"),
                ("Link-Time Optimisation",
                 "-flto in both CFLAGS and LDFLAGS enables cross-file dead code elimination and inlining"),
                ("Optimisation level",
                 "-Os optimises for size; -Oz (Clang) is even more aggressive. Avoid -O0 in production."),
                ("Debug strings",
                 "Guard all printf/log/trace calls with #ifndef NDEBUG to remove string literals from flash"),
                ("64-bit arithmetic",
                 "64-bit / and % pull in libgcc emulation (~2 KB). Replace with 32-bit where value range allows"),
                ("Floating point",
                 "float/double operations pull in soft-FP library code. Use integer or Q-format fixed-point instead"),
                ("Static buffers",
                 "Audit large static arrays in BSS. Use dynamic allocation for infrequently-used large buffers"),
                ("Struct packing",
                 "Order struct fields large→small to reduce padding. Use __attribute__((packed)) only where safe"),
                ("String pooling",
                 "Deduplicate string literals. Use const char *const table[] instead of per-function strings"),
                ("Common symbols",
                 "Explicitly initialise globals (int x = 0;) to move them from COMMON to .data and clarify ownership"),
            ];

            for (topic, tip) in tips {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("▸").color(egui::Color32::from_gray(85)));
                    ui.allocate_ui_with_layout(
                        egui::vec2(200.0, 16.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| ui.label(egui::RichText::new(*topic).strong().size(12.0)),
                    );
                    ui.label(
                        egui::RichText::new(*tip)
                            .size(12.0)
                            .color(egui::Color32::from_gray(182)),
                    );
                });
                ui.add_space(2.0);
            }
        });
    }
}

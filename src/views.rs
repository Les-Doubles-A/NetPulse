//! Rendu de l'interface (egui).

use crate::app::{NetPulseApp, Tab, ToolTab};
use crate::model::{Device, PortState, Severity};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::net::Ipv4Addr;

const GREEN: Color32 = Color32::from_rgb(46, 160, 67);
const RED: Color32 = Color32::from_rgb(207, 54, 54);
const ORANGE: Color32 = Color32::from_rgb(230, 126, 34);
const YELLOW: Color32 = Color32::from_rgb(214, 170, 30);
const BLUE: Color32 = Color32::from_rgb(52, 120, 220);
const GRAY: Color32 = Color32::from_rgb(140, 140, 140);
const ACCENT: Color32 = Color32::from_rgb(0, 150, 200);

fn sev_color(s: &Severity) -> Color32 {
    match s {
        Severity::Critical => RED,
        Severity::High => ORANGE,
        Severity::Medium => YELLOW,
        Severity::Low => BLUE,
        Severity::Info => GRAY,
    }
}

fn score_color(score: i32) -> Color32 {
    match score {
        90..=100 => GREEN,
        75..=89 => Color32::from_rgb(120, 190, 60),
        60..=74 => YELLOW,
        40..=59 => ORANGE,
        _ => RED,
    }
}

fn latency_color(ms: Option<u32>) -> Color32 {
    match ms {
        None => RED,
        Some(v) if v < 30 => GREEN,
        Some(v) if v < 100 => YELLOW,
        Some(_) => ORANGE,
    }
}

fn fmt_bytes(b: u64) -> String {
    let units = ["o", "Ko", "Mo", "Go", "To"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', ';']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

type Cards = Vec<(String, RichText, String)>;

fn card(cards: &mut Cards, title: &str, value: impl Into<RichText>, sub: &str) {
    cards.push((title.to_string(), value.into(), sub.to_string()));
}

/// Affiche des cartes de statistiques sur une grille qui s'adapte a la largeur.
fn card_row(ui: &mut egui::Ui, build: impl FnOnce(&mut Cards)) {
    let mut cards = Cards::new();
    build(&mut cards);
    if cards.is_empty() {
        return;
    }
    let per_row = ((ui.available_width() / 190.0).floor() as usize).clamp(1, cards.len());
    for chunk in cards.chunks(per_row) {
        ui.columns(per_row, |cols| {
            for (i, (title, value, sub)) in chunk.iter().enumerate() {
                egui::Frame::group(cols[i].style()).inner_margin(12.0).corner_radius(8.0).show(&mut cols[i], |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.set_min_height(64.0);
                    ui.label(RichText::new(title).small().color(GRAY));
                    ui.add(egui::Label::new(value.clone().size(22.0).strong()).truncate());
                    if !sub.is_empty() {
                        ui.add(egui::Label::new(RichText::new(sub).small()).truncate());
                    }
                });
            }
        });
        ui.add_space(4.0);
    }
}

fn save_dialog(name: &str, ext: &str, label: &str) -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_file_name(name).add_filter(label, &[ext]).save_file()
}

pub fn draw(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    egui::Panel::top("top_bar").show(ui, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("NetPulse").size(22.0).strong().color(ACCENT));
            ui.label(RichText::new(format!("v{}", crate::VERSION)).small().color(GRAY));
            ui.add_space(16.0);
            let tabs = [
                (Tab::Dashboard, "Tableau de bord"),
                (Tab::Devices, "Appareils"),
                (Tab::Ports, "Ports & sécurité"),
                (Tab::Tools, "Outils"),
                (Tab::Connections, "Connexions"),
                (Tab::Interfaces, "Interfaces & trafic"),
                (Tab::History, "Historique"),
                (Tab::Settings, "Paramètrès"),
            ];
            for (t, label) in tabs {
                if ui.selectable_label(app.tab == t, RichText::new(label).size(15.0)).clicked() {
                    app.tab = t;
                    if t == Tab::Connections && app.connections.is_empty() {
                        app.refresh_connections();
                    }
                }
            }
        });
        ui.add_space(4.0);
    });

    egui::Panel::bottom("status_bar").show(ui, |ui| {
        ui.horizontal(|ui| {
            if app.scanning {
                ui.spinner();
            }
            ui.label(&app.status);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(format!("Base fabricants : {} entrées", crate::oui::entries())).small().color(GRAY));
                ui.separator();
                let online = app.devices.values().filter(|d| d.online).count();
                ui.label(RichText::new(format!("{online} en ligne / {} connus", app.devices.len())).small());
                ui.separator();
                ui.label(
                    RichText::new(format!(
                        "Passerelle : {}",
                        app.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into())
                    ))
                    .small(),
                );
            });
        });
    });

    egui::CentralPanel::default().show(ui, |ui| match app.tab {
        Tab::Dashboard => dashboard(app, ui),
        Tab::Devices => devices(app, ui),
        Tab::Ports => ports_tab(app, ui),
        Tab::Tools => tools_tab(app, ui),
        Tab::Connections => connections(app, ui),
        Tab::Interfaces => interfaces(app, ui),
        Tab::History => history(app, ui),
        Tab::Settings => settings(app, ui),
    });

    // Notifications ephemeres
    if !app.toasts.is_empty() {
        let ctx = ui.ctx().clone();
        egui::Area::new(egui::Id::unique("netpulse_toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -40.0])
            .show(&ctx, |ui| {
                for (t, _) in app.toasts.iter().rev().take(4) {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.set_max_width(420.0);
                        ui.label(t);
                    });
                }
            });
    }

    confirm_dialogs(app, ui);
}

fn confirm_dialogs(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    if app.confirm_clear_devices {
        egui::Window::new("Effacer les appareils ?").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(&ctx, |ui| {
            ui.label("Tous les appareils connus (noms, notes, approbations) seront supprimés.");
            ui.horizontal(|ui| {
                if ui.button("Effacer").clicked() {
                    app.clear_devices();
                    app.confirm_clear_devices = false;
                }
                if ui.button("Annuler").clicked() {
                    app.confirm_clear_devices = false;
                }
            });
        });
    }
    if app.confirm_clear_history {
        egui::Window::new("Vider l'historique ?").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(&ctx, |ui| {
            ui.label("Événements, scans de ports, scores et mesures de latence seront supprimés.");
            ui.horizontal(|ui| {
                if ui.button("Vider").clicked() {
                    app.clear_history();
                    app.confirm_clear_history = false;
                }
                if ui.button("Annuler").clicked() {
                    app.confirm_clear_history = false;
                }
            });
        });
    }
}

// ----------------------------------------------------------------------
// Tableau de bord
// ----------------------------------------------------------------------
fn dashboard(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading("Vue d'ensemble");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if app.scanning {
                    if ui.button("Arrêter l'analyse").clicked() {
                        app.cancel_scan();
                    }
                } else if ui.button(RichText::new("Analyser le réseau").strong()).clicked() {
                    app.start_scan();
                }
                if let Some(gw) = app.gateway {
                    if ui.button("Ouvrir l'interface de la box").clicked() {
                        ui.ctx().open_url(egui::OpenUrl::new_tab(format!("http://{gw}")));
                    }
                }
                if ui.button("Test de débit").clicked() {
                    app.tab = Tab::Tools;
                    app.tool_tab = ToolTab::Speed;
                }
            });
        });
        if app.scanning {
            let (d, t) = app.scan_progress;
            ui.add(egui::ProgressBar::new(if t > 0 { d as f32 / t as f32 } else { 0.0 }).text(format!("Analyse {d}/{t}")));
        }
        ui.add_space(8.0);

        let online = app.devices.values().filter(|d| d.online).count();
        let untrusted = app.devices.values().filter(|d| d.online && !d.trusted).count();
        let scores: Vec<i32> = app.devices.values().filter_map(|d| d.last_score).collect();
        let avg_score = if scores.is_empty() { None } else { Some(scores.iter().sum::<i32>() / scores.len() as i32) };
        let local = app.locals.first();
        let gw_lat = app.gateway.and_then(|g| app.monitor_last.get(&g.to_string()).copied());
        let inet = app.settings.monitor_targets.split([',', ' ']).map(str::trim).find(|s| !s.is_empty()).unwrap_or("").to_string();
        let inet_lat = app.monitor_last.get(&inet).copied();

        card_row(ui, |ui| {
            card(ui, "Appareils en ligne", RichText::new(online.to_string()).color(GREEN), &format!("{} connus au total", app.devices.len()));
            card(
                ui,
                "Non approuvés",
                RichText::new(untrusted.to_string()).color(if untrusted > 0 { ORANGE } else { GREEN }),
                "en ligne, à vérifier",
            );
            card(
                ui,
                "Passerelle",
                RichText::new(match gw_lat {
                    Some(Some(v)) => format!("{v} ms"),
                    Some(None) => "injoignable".into(),
                    None => "-".into(),
                })
                .color(latency_color(gw_lat.flatten())),
                &app.gateway.map(|g| g.to_string()).unwrap_or_else(|| "non détectée".into()),
            );
            card(
                ui,
                "Internet",
                RichText::new(match inet_lat {
                    Some(Some(v)) => format!("{v} ms"),
                    Some(None) => "hors ligne".into(),
                    None => "-".into(),
                })
                .color(latency_color(inet_lat.flatten())),
                &inet,
            );
            card(
                ui,
                "Cet ordinateur",
                local.map(|l| l.ip.to_string()).unwrap_or_else(|| "-".into()),
                &local.map(|l| format!("{} ({})", l.cidr, l.iface)).unwrap_or_default(),
            );
            let public = match &app.public_info {
                Some(Ok(i)) => i.ip.clone(),
                Some(Err(_)) => "erreur".into(),
                None => "-".into(),
            };
            card(
                ui,
                "IP publique",
                public,
                &match &app.public_info {
                    Some(Ok(i)) => i.org.clone(),
                    _ => "cliquez sur Actualiser".into(),
                },
            );
            card(
                ui,
                "Score moyen",
                RichText::new(avg_score.map(|s| format!("{s}/100")).unwrap_or_else(|| "-".into()))
                    .color(avg_score.map(score_color).unwrap_or(GRAY)),
                &format!("{} appareil(s) audité(s)", scores.len()),
            );
            card(ui, "Dernière analyse", RichText::new(app.last_scan_str.clone()).size(15.0), if app.settings.auto_scan { "analyse automatique active" } else { "" });
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(!app.public_busy, egui::Button::new("Actualiser l'IP publique")).clicked() {
                app.fetch_public_ip();
            }
        });

        ui.add_space(10.0);
        ui.columns(2, |cols| {
            cols[0].label(RichText::new("Latence (ms)").strong());
            Plot::new("dash_latency").height(220.0).legend(Legend::default()).include_y(0.0).allow_scroll(false).show(&mut cols[0], |p| {
                for (name, pts) in &app.monitor {
                    let v: Vec<[f64; 2]> = pts.iter().copied().collect();
                    p.line(Line::new(name.clone(), PlotPoints::new(v)).width(1.5));
                }
            });
            cols[1].label(RichText::new("Trafic total (Mbit/s)").strong());
            Plot::new("dash_traffic").height(220.0).legend(Legend::default()).include_y(0.0).allow_scroll(false).show(&mut cols[1], |p| {
                let rx: Vec<[f64; 2]> = app.traffic.iter().map(|v| [v[0], v[1]]).collect();
                let tx: Vec<[f64; 2]> = app.traffic.iter().map(|v| [v[0], v[2]]).collect();
                p.line(Line::new("Réception", PlotPoints::new(rx)).color(GREEN));
                p.line(Line::new("Émission", PlotPoints::new(tx)).color(BLUE));
            });
        });

        ui.add_space(10.0);
        ui.columns(2, |cols| {
            cols[0].label(RichText::new("Répartition par type").strong());
            let mut types: std::collections::BTreeMap<String, usize> = Default::default();
            for d in app.devices.values() {
                *types.entry(if d.device_type.is_empty() { "Inconnu".into() } else { d.device_type.clone() }).or_default() += 1;
            }
            let max = types.values().copied().max().unwrap_or(1) as f32;
            for (t, n) in types {
                cols[0].horizontal(|ui| {
                    ui.add_sized([180.0, 18.0], egui::Label::new(t).truncate());
                    ui.add(egui::ProgressBar::new(n as f32 / max).desired_width(200.0).text(n.to_string()));
                });
            }
            cols[1].label(RichText::new("Événements récents").strong());
            for e in app.events.iter().take(12) {
                cols[1].horizontal(|ui| {
                    ui.label(RichText::new(&e.timestamp[11.min(e.timestamp.len())..]).small().color(GRAY));
                    ui.label(RichText::new(&e.kind).small().strong());
                    ui.add(egui::Label::new(RichText::new(&e.description).small()).truncate());
                });
            }
        });
    });
}

// ----------------------------------------------------------------------
// Appareils
// ----------------------------------------------------------------------
fn devices(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Cible :").strong());
        ui.add(egui::TextEdit::singleline(&mut app.scan_target).desired_width(260.0).hint_text("192.168.1.0/24, 10.0.0.1-50"));
        egui::ComboBox::from_id_salt("locals").selected_text("Réseaux locaux").show_ui(ui, |ui| {
            for l in app.locals.clone() {
                if ui.selectable_label(false, format!("{}  ({}, {})", l.cidr, l.iface, l.ip)).clicked() {
                    app.scan_target = l.cidr.clone();
                }
            }
        });
        if app.scanning {
            if ui.button("Arrêter").clicked() {
                app.cancel_scan();
            }
            let (d, t) = app.scan_progress;
            ui.add(egui::ProgressBar::new(if t > 0 { d as f32 / t as f32 } else { 0.0 }).desired_width(220.0).text(format!("{d}/{t}")));
        } else if ui.button(RichText::new("Analyser le réseau").strong()).clicked() {
            app.start_scan();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Effacer la liste").clicked() {
                app.confirm_clear_devices = true;
            }
            ui.menu_button("Exporter", |ui| {
                if ui.button("CSV").clicked() {
                    export_devices_csv(app);
                    ui.close();
                }
                if ui.button("JSON").clicked() {
                    if let Some(p) = save_dialog("netpulse-appareils.json", "json", "JSON") {
                        let list: Vec<&Device> = app.devices.values().collect();
                        let res = std::fs::write(&p, serde_json::to_string_pretty(&list).unwrap_or_default());
                        app.toast(match res {
                            Ok(_) => format!("Exporté vers {}", p.display()),
                            Err(e) => format!("Erreur : {e}"),
                        });
                    }
                    ui.close();
                }
            });
        });
    });
    ui.horizontal(|ui| {
        ui.label("Filtrer :");
        ui.add(egui::TextEdit::singleline(&mut app.device_search).desired_width(220.0).hint_text("IP, nom, MAC, fabricant..."));
        for (i, l) in ["Tous", "En ligne", "Hors ligne", "Non approuvés", "Favoris"].iter().enumerate() {
            ui.selectable_value(&mut app.device_filter, i, *l);
        }
    });
    ui.separator();

    if let Some(sel) = app.selected {
        egui::Panel::right("device_details").default_size(360.0).resizable(true).show(ui, |ui| {
            device_details(app, ui, sel);
        });
    }

    let q = app.device_search.to_lowercase();
    let mut list: Vec<Device> = app
        .devices
        .values()
        .filter(|d| match app.device_filter {
            1 => d.online,
            2 => !d.online,
            3 => !d.trusted,
            4 => d.favorite,
            _ => true,
        })
        .filter(|d| {
            q.is_empty()
                || [&d.ip, &d.mac, &d.vendor, &d.hostname, &d.name, &d.device_type, &d.notes]
                    .iter()
                    .any(|f| f.to_lowercase().contains(&q))
        })
        .cloned()
        .collect();
    let asc = app.sort_asc;
    list.sort_by(|a, b| {
        let o = match app.sort_col {
            0 => b.favorite.cmp(&a.favorite),
            1 => b.online.cmp(&a.online),
            3 => a.display_name().to_lowercase().cmp(&b.display_name().to_lowercase()),
            4 => a.mac.cmp(&b.mac),
            5 => a.vendor.cmp(&b.vendor),
            6 => a.device_type.cmp(&b.device_type),
            7 => a.latency_ms.unwrap_or(u32::MAX).cmp(&b.latency_ms.unwrap_or(u32::MAX)),
            8 => a.last_seen.cmp(&b.last_seen),
            _ => a.ipv4().cmp(&b.ipv4()),
        };
        if asc { o } else { o.reverse() }
    });

    if list.is_empty() {
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("Aucun appareil. Lancez une analyse du réseau.").size(16.0).color(GRAY));
        });
        return;
    }

    let headers = ["*", "État", "Adresse IP", "Nom", "Adresse MAC", "Fabricant", "Type", "Latence", "Dernière vue"];
    let mut clicked: Option<Ipv4Addr> = None;
    let mut toggle_fav: Option<Ipv4Addr> = None;
    let mut sort_click: Option<usize> = None;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(22.0))
        .column(Column::exact(70.0))
        .column(Column::initial(115.0))
        .column(Column::initial(170.0).clip(true))
        .column(Column::initial(140.0))
        .column(Column::initial(200.0).clip(true))
        .column(Column::initial(140.0).clip(true))
        .column(Column::initial(65.0))
        .column(Column::remainder())
        .header(24.0, |mut h| {
            for (i, name) in headers.iter().enumerate() {
                h.col(|ui| {
                    let arrow = if app.sort_col == i { if app.sort_asc { " ^" } else { " v" } } else { "" };
                    if ui.add(egui::Label::new(RichText::new(format!("{name}{arrow}")).strong()).sense(Sense::click())).clicked() {
                        sort_click = Some(i);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(24.0, list.len(), |mut row| {
                let d = &list[row.index()];
                let ip = d.ipv4();
                row.set_selected(app.selected == Some(ip));
                row.col(|ui| {
                    let star = if d.favorite { RichText::new("*").color(YELLOW).strong() } else { RichText::new(".").color(GRAY) };
                    if ui.add(egui::Label::new(star).sense(Sense::click())).clicked() {
                        toggle_fav = Some(ip);
                    }
                });
                row.col(|ui| {
                    let (c, t) = if d.online { (GREEN, "En ligne") } else { (GRAY, "Hors ligne") };
                    ui.label(RichText::new(t).color(c));
                });
                row.col(|ui| {
                    ui.label(RichText::new(&d.ip).monospace());
                });
                row.col(|ui| {
                    let mut t = RichText::new(d.display_name());
                    if !d.trusted {
                        t = t.italics();
                    }
                    ui.label(t);
                    if !d.trusted && d.online {
                        ui.label(RichText::new("nouveau").small().color(ORANGE));
                    }
                });
                row.col(|ui| {
                    ui.label(RichText::new(&d.mac).monospace());
                });
                row.col(|ui| {
                    ui.label(&d.vendor);
                });
                row.col(|ui| {
                    ui.label(&d.device_type);
                });
                row.col(|ui| {
                    if d.online {
                        ui.label(RichText::new(d.latency_ms.map(|l| format!("{l} ms")).unwrap_or_default()).color(latency_color(d.latency_ms)));
                    }
                });
                row.col(|ui| {
                    ui.label(RichText::new(&d.last_seen).small());
                });
                if row.response().clicked() {
                    clicked = Some(ip);
                }
            });
        });
    if let Some(c) = sort_click {
        if app.sort_col == c {
            app.sort_asc = !app.sort_asc;
        } else {
            app.sort_col = c;
            app.sort_asc = true;
        }
    }
    if let Some(ip) = toggle_fav {
        if let Some(d) = app.devices.get_mut(&ip) {
            d.favorite = !d.favorite;
        }
        app.save_device(ip);
    } else if let Some(ip) = clicked {
        app.selected = if app.selected == Some(ip) { None } else { Some(ip) };
    }
}

fn export_devices_csv(app: &mut NetPulseApp) {
    if let Some(p) = save_dialog("netpulse-appareils.csv", "csv", "CSV") {
        let mut out = String::from("ip,nom,hôte,mac,fabricant,type,état,latence_ms,approuvé,favori,première_vue,dernière_vue,score,ports_ouverts,notes\n");
        for d in app.devices.values() {
            out.push_str(
                &[
                    d.ip.clone(),
                    d.name.clone(),
                    d.hostname.clone(),
                    d.mac.clone(),
                    d.vendor.clone(),
                    d.device_type.clone(),
                    if d.online { "en ligne".into() } else { "hors ligne".into() },
                    d.latency_ms.map(|v| v.to_string()).unwrap_or_default(),
                    d.trusted.to_string(),
                    d.favorite.to_string(),
                    d.first_seen.clone(),
                    d.last_seen.clone(),
                    d.last_score.map(|v| v.to_string()).unwrap_or_default(),
                    d.open_ports.clone(),
                    d.notes.clone(),
                ]
                .iter()
                .map(|s| csv_escape(s))
                .collect::<Vec<_>>()
                .join(","),
            );
            out.push('\n');
        }
        let res = std::fs::write(&p, format!("\u{feff}{out}"));
        app.toast(match res {
            Ok(_) => format!("Exporté vers {}", p.display()),
            Err(e) => format!("Erreur : {e}"),
        });
    }
}

fn device_details(app: &mut NetPulseApp, ui: &mut egui::Ui, ip: Ipv4Addr) {
    let Some(snapshot) = app.devices.get(&ip).cloned() else {
        app.selected = None;
        return;
    };
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(&snapshot.ip);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Fermer").clicked() {
                    app.selected = None;
                }
            });
        });
        ui.label(RichText::new(if snapshot.online { "En ligne" } else { "Hors ligne" }).color(if snapshot.online { GREEN } else { GRAY }));
        ui.separator();

        let mut changed = false;
        if let Some(d) = app.devices.get_mut(&ip) {
            ui.label("Nom personnalisé");
            changed |= ui.add(egui::TextEdit::singleline(&mut d.name).hint_text(&snapshot.hostname).desired_width(f32::INFINITY)).changed();
            ui.label("Type");
            changed |= ui.add(egui::TextEdit::singleline(&mut d.device_type).desired_width(f32::INFINITY)).changed();
            ui.label("Notes");
            changed |= ui.add(egui::TextEdit::multiline(&mut d.notes).desired_rows(3).desired_width(f32::INFINITY)).changed();
            ui.horizontal(|ui| {
                changed |= ui.checkbox(&mut d.trusted, "Appareil approuvé").changed();
                changed |= ui.checkbox(&mut d.favorite, "Favori").changed();
            });
        }
        if changed {
            app.save_device(ip);
        }

        ui.separator();
        egui::Grid::new("dev_grid").num_columns(2).striped(true).show(ui, |ui| {
            let rows = [
                ("Nom d'hôte", snapshot.hostname.clone()),
                ("Adresse MAC", snapshot.mac.clone()),
                ("Fabricant", snapshot.vendor.clone()),
                ("Latence", snapshot.latency_ms.map(|v| format!("{v} ms")).unwrap_or_else(|| "-".into())),
                ("Première détection", snapshot.first_seen.clone()),
                ("Dernière détection", snapshot.last_seen.clone()),
                ("Score sécurité", snapshot.last_score.map(|v| format!("{v}/100")).unwrap_or_else(|| "non audité".into())),
                ("Ports ouverts", if snapshot.open_ports.is_empty() { "-".into() } else { snapshot.open_ports.clone() }),
                ("MAC privée", if crate::oui::is_randomized(&snapshot.mac) { "oui".into() } else { "non".into() }),
            ];
            for (k, v) in rows {
                ui.label(RichText::new(k).color(GRAY));
                ui.label(v);
                ui.end_row();
            }
        });

        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Scanner les ports").clicked() {
                app.scan_ports_of(ip);
            }
            if ui.button("Ping continu").clicked() {
                app.ping_target = ip.to_string();
                app.tab = Tab::Tools;
                app.tool_tab = ToolTab::Ping;
            }
            if ui.button("Traceroute").clicked() {
                app.trace_target = ip.to_string();
                app.tab = Tab::Tools;
                app.tool_tab = ToolTab::Trace;
            }
            if !snapshot.mac.is_empty() && ui.button("Réveiller (WoL)").clicked() {
                app.send_wol(snapshot.mac.clone());
            }
            if ui.button("Ouvrir http://").clicked() {
                ui.ctx().open_url(egui::OpenUrl::new_tab(format!("http://{ip}")));
            }
            if ui.button("Ouvrir https://").clicked() {
                ui.ctx().open_url(egui::OpenUrl::new_tab(format!("https://{ip}")));
            }
            if ui.button("Copier l'IP").clicked() {
                ui.ctx().copy_text(ip.to_string());
            }
            if !snapshot.mac.is_empty() && ui.button("Copier la MAC").clicked() {
                ui.ctx().copy_text(snapshot.mac.clone());
            }
            if ui.button(RichText::new("Supprimer").color(RED)).clicked() {
                app.delete_device(ip);
            }
        });

        ui.separator();
        ui.label(RichText::new("Historique de l'appareil").strong());
        let ips = ip.to_string();
        let mut n = 0;
        for e in app.events.iter().filter(|e| e.ip == ips).take(30) {
            ui.label(RichText::new(format!("{}  {}", e.timestamp, e.kind)).small().strong());
            ui.label(RichText::new(&e.description).small());
            n += 1;
        }
        if n == 0 {
            ui.label(RichText::new("Aucun événement.").small().color(GRAY));
        }
    });
}

// ----------------------------------------------------------------------
// Ports & securite
// ----------------------------------------------------------------------
fn ports_tab(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Hôte :").strong());
        ui.add(egui::TextEdit::singleline(&mut app.port_target).desired_width(200.0).hint_text("IP ou nom d'hôte"));
        egui::ComboBox::from_id_salt("known_hosts").selected_text("Appareils connus").width(160.0).show_ui(ui, |ui| {
            let list: Vec<(String, String)> = app.devices.values().map(|d| (d.ip.clone(), d.display_name().to_string())).collect();
            for (ip, name) in list {
                if ui.selectable_label(false, format!("{ip}  {name}")).clicked() {
                    app.port_target = ip.clone();
                    app.score_history = app.db.score_history(&ip);
                }
            }
        });
        ui.label("Présélection :");
        let presets = crate::ports::PRESETS;
        egui::ComboBox::from_id_salt("preset").selected_text(presets[app.port_preset.min(presets.len() - 1)].0).show_ui(ui, |ui| {
            for (i, (name, spec)) in presets.iter().enumerate() {
                if ui.selectable_value(&mut app.port_preset, i, *name).clicked() {
                    app.port_spec = spec.to_string();
                }
            }
        });
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("Ports :").strong());
        ui.add(egui::TextEdit::singleline(&mut app.port_spec).desired_width(520.0).hint_text("22,80,443 ou 1-1024"));
        ui.label("Délai");
        ui.add(egui::DragValue::new(&mut app.settings.port_timeout_ms).range(100..=10000).suffix(" ms"));
        ui.label("Threads");
        ui.add(egui::DragValue::new(&mut app.settings.port_threads).range(1..=1000));
        ui.checkbox(&mut app.settings.grab_banners, "Bannières");
        if app.port_scanning {
            if ui.button("Arrêter").clicked() {
                app.cancel_port_scan();
            }
        } else if ui.button(RichText::new("Lancer le scan").strong()).clicked() {
            app.start_port_scan();
        }
    });
    if app.port_scanning {
        let (d, t) = app.port_progress;
        ui.add(egui::ProgressBar::new(if t > 0 { d as f32 / t as f32 } else { 0.0 }).text(format!("{d}/{t} ports - {} ouvert(s)", app.port_live.len())));
    }
    if let Some(e) = &app.port_error {
        ui.colored_label(RED, e);
    }
    ui.separator();

    egui::Panel::right("security_panel").default_size(430.0).resizable(true).show(ui, |ui| {
        security_panel(app, ui);
    });

    let rows: Vec<crate::model::PortResult> = match &app.port_outcome {
        Some(o) if app.port_show_closed && !o.all.is_empty() => o.all.clone(),
        Some(o) => o.open.clone(),
        None => app.port_live.clone(),
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} résultat(s)", rows.len())).strong());
        if let Some(o) = &app.port_outcome {
            ui.label(format!(
                "- {} testés en {:.1} s, {} fermés, {} filtrés{}",
                o.scanned,
                o.duration_s,
                o.closed,
                o.filtered,
                if o.cancelled { " (interrompu)" } else { "" }
            ));
            if !o.all.is_empty() {
                ui.checkbox(&mut app.port_show_closed, "Afficher fermés/filtrés");
            }
        }
    });
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(70.0))
        .column(Column::initial(140.0))
        .column(Column::exact(80.0))
        .column(Column::exact(70.0))
        .column(Column::remainder().clip(true))
        .header(22.0, |mut h| {
            for t in ["Port", "Service", "État", "Latence", "Bannière / information"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(22.0, rows.len(), |mut row| {
                let r = &rows[row.index()];
                row.col(|ui| {
                    ui.label(RichText::new(r.port.to_string()).monospace());
                });
                row.col(|ui| {
                    ui.label(&r.service);
                });
                row.col(|ui| {
                    let c = match r.state {
                        PortState::Open => GREEN,
                        PortState::Closed => GRAY,
                        PortState::Filtered => YELLOW,
                    };
                    ui.label(RichText::new(r.state.label()).color(c));
                });
                row.col(|ui| {
                    if r.state == PortState::Open {
                        ui.label(format!("{} ms", r.latency_ms));
                    }
                });
                row.col(|ui| {
                    ui.label(&r.banner).on_hover_text(&r.banner);
                });
            });
        });
}

fn security_panel(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Analyse de sécurité");
        let Some(o) = app.port_outcome.clone() else {
            ui.label(RichText::new("Lancez un scan pour obtenir un score et des recommandations.").color(GRAY));
            return;
        };
        let r = &o.report;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{}", r.score)).size(48.0).strong().color(score_color(r.score)));
            ui.vertical(|ui| {
                ui.label(RichText::new(format!("Note {}", r.grade)).size(20.0).strong());
                ui.label(format!("{} - {}", r.label, o.target));
            });
        });
        ui.horizontal(|ui| {
            if ui.button("Rapport HTML").clicked() {
                if let Some(p) = save_dialog(&format!("rapport-netpulse-{}.html", o.ip), "html", "HTML") {
                    let res = std::fs::write(&p, crate::ports::html_report(&o));
                    if res.is_ok() {
                        ui.ctx().open_url(egui::OpenUrl::new_tab(format!("file:///{}", p.display().to_string().replace('\\', "/"))));
                    }
                    app.toast(match res {
                        Ok(_) => format!("Rapport enregistré : {}", p.display()),
                        Err(e) => format!("Erreur : {e}"),
                    });
                }
            }
            if ui.button("Export JSON").clicked() {
                if let Some(p) = save_dialog(&format!("scan-{}.json", o.ip), "json", "JSON") {
                    let res = std::fs::write(&p, serde_json::to_string_pretty(&o).unwrap_or_default());
                    app.toast(match res {
                        Ok(_) => format!("Exporté vers {}", p.display()),
                        Err(e) => format!("Erreur : {e}"),
                    });
                }
            }
        });
        ui.separator();
        for f in &r.findings {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(f.severity.label()).strong().color(sev_color(&f.severity)));
                    ui.label(RichText::new(&f.title).strong());
                });
                ui.label(&f.detail);
                ui.label(RichText::new(format!("Conseil : {}", f.recommendation)).italics());
            });
        }
        if app.score_history.len() > 1 {
            ui.separator();
            ui.label(RichText::new("Évolution du score").strong());
            let pts: Vec<[f64; 2]> = app.score_history.iter().enumerate().map(|(i, (_, s))| [i as f64, *s as f64]).collect();
            Plot::new("score_hist").height(140.0).include_y(0.0).include_y(100.0).allow_scroll(false).show(ui, |p| {
                p.line(Line::new("Score", PlotPoints::new(pts)).color(ACCENT).width(2.0));
            });
        }
    });
}

// ----------------------------------------------------------------------
// Outils
// ----------------------------------------------------------------------
fn tools_tab(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        for (t, l) in [
            (ToolTab::Ping, "Ping"),
            (ToolTab::Trace, "Traceroute"),
            (ToolTab::Dns, "DNS"),
            (ToolTab::Wol, "Wake-on-LAN"),
            (ToolTab::PublicIp, "IP publique"),
            (ToolTab::Speed, "Test de débit"),
            (ToolTab::Http, "Vérification HTTP"),
            (ToolTab::Subnet, "Calculateur IP"),
            (ToolTab::MacLookup, "Fabricant MAC"),
        ] {
            ui.selectable_value(&mut app.tool_tab, t, l);
        }
    });
    ui.separator();
    match app.tool_tab {
        ToolTab::Ping => tool_ping(app, ui),
        ToolTab::Trace => tool_trace(app, ui),
        ToolTab::Dns => tool_dns(app, ui),
        ToolTab::Wol => tool_wol(app, ui),
        ToolTab::PublicIp => tool_public(app, ui),
        ToolTab::Speed => tool_speed(app, ui),
        ToolTab::Http => tool_http(app, ui),
        ToolTab::Subnet => tool_subnet(app, ui),
        ToolTab::MacLookup => tool_mac(app, ui),
    }
}

fn tool_ping(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Hôte :");
        ui.add_enabled(!app.ping_running, egui::TextEdit::singleline(&mut app.ping_target).desired_width(220.0));
        ui.label("Intervalle");
        ui.add_enabled(!app.ping_running, egui::DragValue::new(&mut app.ping_interval_ms).range(200..=10000).suffix(" ms"));
        if ui.button(if app.ping_running { "Arrêter" } else { "Démarrer" }).clicked() {
            app.start_ping();
        }
    });
    let s = &app.ping_stats;
    card_row(ui, |ui| {
        card(ui, "Envoyés / reçus", format!("{} / {}", s.sent, s.received), "");
        card(ui, "Perte", RichText::new(format!("{:.1} %", s.loss())).color(if s.loss() > 0.0 { ORANGE } else { GREEN }), "");
        card(ui, "Min / moy / max", format!("{} / {:.1} / {} ms", s.min, s.avg(), s.max), "");
        card(ui, "Gigue", format!("{:.1} ms", s.jitter()), "");
    });
    ui.columns(2, |cols| {
        Plot::new("ping_plot").height(320.0).include_y(0.0).allow_scroll(false).show(&mut cols[0], |p| {
            p.line(Line::new("RTT (ms)", PlotPoints::new(app.ping_points.clone())).color(ACCENT).width(1.5));
        });
        egui::ScrollArea::vertical().id_salt("ping_log").max_height(320.0).show(&mut cols[1], |ui| {
            for l in &app.ping_log {
                ui.label(RichText::new(l).monospace());
            }
        });
    });
}

fn tool_trace(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Destination :");
        ui.add(egui::TextEdit::singleline(&mut app.trace_target).desired_width(240.0));
        if ui.button(if app.trace_running { "Arrêter" } else { "Lancer" }).clicked() {
            app.start_trace();
        }
        if app.trace_running {
            ui.spinner();
        }
        ui.label(&app.trace_msg);
    });
    ui.separator();
    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(50.0))
        .column(Column::initial(140.0))
        .column(Column::initial(80.0))
        .column(Column::initial(80.0))
        .column(Column::initial(80.0))
        .column(Column::remainder())
        .header(22.0, |mut h| {
            for t in ["Saut", "Adresse", "Essai 1", "Essai 2", "Essai 3", "Nom"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(22.0, app.trace_hops.len(), |mut row| {
                let h = &app.trace_hops[row.index()];
                row.col(|ui| {
                    ui.label(h.ttl.to_string());
                });
                row.col(|ui| {
                    ui.label(RichText::new(h.ip.map(|i| i.to_string()).unwrap_or_else(|| "*".into())).monospace());
                });
                for i in 0..3 {
                    row.col(|ui| {
                        let v = h.rtts.get(i).copied().flatten();
                        ui.label(RichText::new(v.map(|v| format!("{v} ms")).unwrap_or_else(|| "*".into())).color(latency_color(v)));
                    });
                }
                row.col(|ui| {
                    ui.label(&h.host);
                });
            });
        });
}

fn tool_dns(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Nom ou adresse IP :");
        let r = ui.add(egui::TextEdit::singleline(&mut app.dns_query).desired_width(280.0));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.add_enabled(!app.dns_busy, egui::Button::new("Résoudre")).clicked() || enter) && !app.dns_busy {
            app.start_dns();
        }
        if app.dns_busy {
            ui.spinner();
        }
    });
    ui.separator();
    match &app.dns_result {
        Some(Ok((rows, ms))) => {
            for r in rows {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(r).monospace().size(15.0));
                    if ui.small_button("Copier").clicked() {
                        ui.ctx().copy_text(r.split_whitespace().last().unwrap_or("").to_string());
                    }
                });
            }
            ui.label(RichText::new(format!("Résolu en {ms:.1} ms par le résolveur système")).color(GRAY));
        }
        Some(Err(e)) => {
            ui.colored_label(RED, e);
        }
        None => {
            ui.label(RichText::new("Résolution directe (A/AAAA) d'un nom ou inverse (PTR) d'une adresse.").color(GRAY));
        }
    }
}

fn tool_wol(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.label("Réveille un ordinateur compatible Wake-on-LAN en envoyant un paquet magique sur le réseau local.");
    ui.horizontal(|ui| {
        ui.label("Adresse MAC :");
        ui.add(egui::TextEdit::singleline(&mut app.wol_mac).desired_width(200.0).hint_text("AA:BB:CC:DD:EE:FF"));
        egui::ComboBox::from_id_salt("wol_known").selected_text("Appareils connus").show_ui(ui, |ui| {
            let list: Vec<(String, String)> = app
                .devices
                .values()
                .filter(|d| !d.mac.is_empty())
                .map(|d| (d.mac.clone(), format!("{}  {}  {}", d.ip, d.mac, d.display_name())))
                .collect();
            for (mac, label) in list {
                if ui.selectable_label(false, label).clicked() {
                    app.wol_mac = mac;
                }
            }
        });
        if ui.button("Envoyer").clicked() {
            app.send_wol(app.wol_mac.clone());
        }
    });
    if !app.wol_status.is_empty() {
        ui.label(&app.wol_status);
    }
}

fn tool_public(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        if ui.add_enabled(!app.public_busy, egui::Button::new("Interroger ipinfo.io")).clicked() {
            app.fetch_public_ip();
        }
        if app.public_busy {
            ui.spinner();
        }
        ui.label(RichText::new("Votre adresse publique est envoyée à ipinfo.io pour obtenir ces informations.").small().color(GRAY));
    });
    ui.separator();
    match &app.public_info {
        Some(Ok(i)) => {
            egui::Grid::new("pub_grid").num_columns(2).striped(true).show(ui, |ui| {
                for (k, v) in [
                    ("Adresse IP", &i.ip),
                    ("Nom d'hôte", &i.hostname),
                    ("Fournisseur (AS)", &i.org),
                    ("Ville", &i.city),
                    ("Région", &i.region),
                    ("Pays", &i.country),
                    ("Code postal", &i.postal),
                    ("Coordonnées", &i.loc),
                    ("Fuseau horaire", &i.timezone),
                ] {
                    ui.label(RichText::new(k).color(GRAY));
                    ui.label(RichText::new(v).strong());
                    ui.end_row();
                }
            });
            if !i.loc.is_empty() && ui.button("Voir sur la carte").clicked() {
                let (lat, lon) = i.loc.split_once(',').unwrap_or(("0", "0"));
                ui.ctx().open_url(egui::OpenUrl::new_tab(format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=11/{lat}/{lon}")));
            }
        }
        Some(Err(e)) => {
            ui.colored_label(RED, e);
        }
        None => {}
    }
}

fn tool_speed(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        if ui.button(RichText::new(if app.speed.running { "Arrêter" } else { "Lancer le test" }).strong()).clicked() {
            app.start_speed();
        }
        if app.speed.running {
            ui.spinner();
        }
        ui.label(&app.speed.phase);
        ui.label(RichText::new("Serveur : speed.cloudflare.com (50 Mo descendant, 20 Mo montant max.)").small().color(GRAY));
    });
    if app.speed.running {
        ui.add(egui::ProgressBar::new(app.speed.progress).show_percentage());
    }
    if let Some(e) = &app.speed.error {
        ui.colored_label(RED, e);
    }
    card_row(ui, |ui| {
        card(ui, "Latence", app.speed.latency.map(|v| format!("{v:.0} ms")).unwrap_or_else(|| "-".into()), "");
        card(
            ui,
            "Descendant",
            RichText::new(format!("{:.1} Mbit/s", app.speed.down.unwrap_or(app.speed.live_down))).color(GREEN),
            "",
        );
        card(ui, "Montant", RichText::new(format!("{:.1} Mbit/s", app.speed.up.unwrap_or(app.speed.live_up))).color(BLUE), "");
    });
    if !app.speed.samples.is_empty() {
        Plot::new("speed_plot").height(260.0).include_y(0.0).allow_scroll(false).show(ui, |p| {
            p.line(Line::new("Débit descendant (Mbit/s)", PlotPoints::new(app.speed.samples.clone())).color(GREEN).width(2.0));
        });
    }
}

fn tool_http(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("URL :");
        let r = ui.add(egui::TextEdit::singleline(&mut app.http_url).desired_width(420.0));
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.add_enabled(!app.http_busy, egui::Button::new("Vérifier")).clicked() || enter) && !app.http_busy {
            app.start_http();
        }
        if app.http_busy {
            ui.spinner();
        }
    });
    ui.separator();
    match &app.http_result {
        Some(Ok(h)) => {
            let c = match h.status {
                200..=299 => GREEN,
                300..=399 => BLUE,
                400..=499 => ORANGE,
                _ => RED,
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("{} {}", h.status, h.reason)).size(22.0).strong().color(c));
                ui.label(format!("{} en {:.0} ms - {} - {}", h.url, h.time_ms, fmt_bytes(h.size as u64), if h.https { "HTTPS" } else { "HTTP non chiffré" }));
            });
            if !h.missing_security_headers.is_empty() {
                ui.label(RichText::new(format!("En-têtes de sécurité absents : {}", h.missing_security_headers.join(", "))).color(ORANGE));
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("http_headers").num_columns(2).striped(true).show(ui, |ui| {
                    for (k, v) in &h.headers {
                        ui.label(RichText::new(k).monospace().color(GRAY));
                        ui.label(RichText::new(v).monospace());
                        ui.end_row();
                    }
                });
            });
        }
        Some(Err(e)) => {
            ui.colored_label(RED, e);
        }
        None => {
            ui.label(RichText::new("Code de réponse, temps, taille et en-têtes HTTP (avec contrôle des en-têtes de sécurité).").color(GRAY));
        }
    }
}

fn tool_subnet(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Adresse/préfixe ou adresse/masque :");
        ui.add(egui::TextEdit::singleline(&mut app.subnet_input).desired_width(240.0));
    });
    ui.separator();
    match crate::tools::subnet_calc(&app.subnet_input) {
        Ok(info) => {
            egui::Grid::new("subnet_grid").num_columns(2).striped(true).show(ui, |ui| {
                for (k, v) in info.rows {
                    ui.label(RichText::new(k).color(GRAY));
                    ui.label(RichText::new(v).monospace());
                    ui.end_row();
                }
            });
        }
        Err(e) => {
            ui.colored_label(ORANGE, e);
        }
    }
}

fn tool_mac(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("Adresse MAC ou préfixe :");
        ui.add(egui::TextEdit::singleline(&mut app.mac_input).desired_width(220.0).hint_text("B8:27:EB:12:34:56"));
    });
    ui.separator();
    let hex: String = app.mac_input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() >= 6 {
        let v = crate::oui::lookup(&app.mac_input).unwrap_or_else(|| "Fabricant inconnu".into());
        ui.label(RichText::new(v).size(20.0).strong());
        ui.label(format!(
            "Adresse administrée localement (aléatoire) : {}",
            if crate::oui::is_randomized(&app.mac_input) { "oui" } else { "non" }
        ));
        if let Ok(b) = u8::from_str_radix(&hex[0..2], 16) {
            ui.label(format!("Type : {}", if b & 1 == 1 { "multicast" } else { "unicast" }));
        }
    } else {
        ui.label(RichText::new("Saisissez au moins 6 chiffres hexadécimaux.").color(GRAY));
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(format!("Base locale : {} fabricants.", crate::oui::entries()));
        if ui.add_enabled(!app.oui_busy, egui::Button::new("Mettre à jour depuis l'IEEE")).clicked() {
            app.update_oui();
        }
        if app.oui_busy {
            ui.spinner();
        }
    });
}

// ----------------------------------------------------------------------
// Connexions
// ----------------------------------------------------------------------
fn connections(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        if ui.button("Actualiser").clicked() {
            app.refresh_connections();
        }
        ui.checkbox(&mut app.conn_auto, "Actualisation auto (2 s)");
        ui.label("Filtrer :");
        ui.add(egui::TextEdit::singleline(&mut app.conn_filter).desired_width(200.0).hint_text("IP, port, processus..."));
        for (i, l) in ["Toutes", "Établies", "En écoute", "UDP"].iter().enumerate() {
            ui.selectable_value(&mut app.conn_state, i, *l);
        }
    });
    let q = app.conn_filter.to_lowercase();
    let rows: Vec<&(crate::platform::SocketEntry, String)> = app
        .connections
        .iter()
        .filter(|(e, _)| match app.conn_state {
            1 => e.state == "ETABLIE",
            2 => e.state == "ECOUTE",
            3 => e.proto == "UDP",
            _ => true,
        })
        .filter(|(e, name)| {
            q.is_empty()
                || name.to_lowercase().contains(&q)
                || e.local.to_string().contains(&q)
                || e.remote.map(|r| r.to_string().contains(&q)).unwrap_or(false)
                || e.local_port.to_string() == q
                || e.remote_port.to_string() == q
                || e.pid.to_string() == q
        })
        .collect();
    let est = app.connections.iter().filter(|(e, _)| e.state == "ETABLIE").count();
    let lis = app.connections.iter().filter(|(e, _)| e.state == "ECOUTE").count();
    ui.label(format!(
        "{} socket(s) IPv4 : {est} établie(s), {lis} en écoute, {} UDP - {} affichée(s)",
        app.connections.len(),
        app.connections.iter().filter(|(e, _)| e.proto == "UDP").count(),
        rows.len()
    ));
    ui.separator();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::exact(50.0))
        .column(Column::initial(130.0))
        .column(Column::exact(70.0))
        .column(Column::initial(130.0))
        .column(Column::exact(70.0))
        .column(Column::initial(110.0))
        .column(Column::exact(70.0))
        .column(Column::remainder())
        .header(22.0, |mut h| {
            for t in ["Proto", "Adresse locale", "Port", "Adresse distante", "Port", "État", "PID", "Processus"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, rows.len(), |mut row| {
                let (e, name) = rows[row.index()];
                row.col(|ui| {
                    ui.label(e.proto);
                });
                row.col(|ui| {
                    ui.label(RichText::new(e.local.to_string()).monospace());
                });
                row.col(|ui| {
                    ui.label(e.local_port.to_string());
                });
                row.col(|ui| {
                    ui.label(RichText::new(e.remote.map(|r| r.to_string()).unwrap_or_default()).monospace());
                });
                row.col(|ui| {
                    if e.remote_port != 0 {
                        ui.label(e.remote_port.to_string());
                    }
                });
                row.col(|ui| {
                    let c = match e.state {
                        "ETABLIE" => GREEN,
                        "ECOUTE" => BLUE,
                        _ => GRAY,
                    };
                    ui.label(RichText::new(e.state).color(c));
                });
                row.col(|ui| {
                    ui.label(e.pid.to_string());
                });
                row.col(|ui| {
                    ui.label(name);
                });
            });
        });
}

// ----------------------------------------------------------------------
// Interfaces & trafic
// ----------------------------------------------------------------------
fn interfaces(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.heading("Interfaces réseau");
        if ui.button("Actualiser").clicked() {
            app.refresh_interfaces();
        }
    });
    ui.label(format!(
        "Passerelle par défaut : {}   |   Nom de l'ordinateur : {}",
        app.gateway.map(|g| g.to_string()).unwrap_or_else(|| "-".into()),
        dns_lookup::get_hostname().unwrap_or_default()
    ));
    ui.add_space(6.0);
    Plot::new("iface_traffic").height(200.0).legend(Legend::default()).include_y(0.0).allow_scroll(false).show(ui, |p| {
        let rx: Vec<[f64; 2]> = app.traffic.iter().map(|v| [v[0], v[1]]).collect();
        let tx: Vec<[f64; 2]> = app.traffic.iter().map(|v| [v[0], v[2]]).collect();
        p.line(Line::new("Réception (Mbit/s)", PlotPoints::new(rx)).color(GREEN));
        p.line(Line::new("Émission (Mbit/s)", PlotPoints::new(tx)).color(BLUE));
    });
    ui.separator();
    let list = app.network_list();
    egui::ScrollArea::vertical().show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(240.0).clip(true))
            .column(Column::initial(140.0))
            .column(Column::initial(260.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(90.0))
            .column(Column::initial(90.0))
            .column(Column::initial(110.0))
            .column(Column::remainder())
            .header(22.0, |mut h| {
                for t in ["Interface", "MAC", "Adresses", "MTU", "Reçu", "Envoyé", "Débit reçu", "Débit envoyé"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, list.len(), |mut row| {
                    let (name, mac, ips, rx, tx, mtu, (rr, tr)) = &list[row.index()];
                    row.col(|ui| {
                        ui.label(name).on_hover_text(name);
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(mac).monospace());
                    });
                    row.col(|ui| {
                        let t = ips.join(", ");
                        ui.label(&t).on_hover_text(&t);
                    });
                    row.col(|ui| {
                        ui.label(mtu.to_string());
                    });
                    row.col(|ui| {
                        ui.label(fmt_bytes(*rx));
                    });
                    row.col(|ui| {
                        ui.label(fmt_bytes(*tx));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format!("{rr:.2} Mbit/s")).color(if *rr > 0.01 { GREEN } else { GRAY }));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format!("{tr:.2} Mbit/s")).color(if *tr > 0.01 { BLUE } else { GRAY }));
                    });
                });
            });
    });
}

// ----------------------------------------------------------------------
// Historique
// ----------------------------------------------------------------------
fn history(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    let kinds: std::collections::BTreeSet<String> = app.events.iter().map(|e| e.kind.clone()).collect();
    ui.horizontal(|ui| {
        ui.label("Rechercher :");
        ui.add(egui::TextEdit::singleline(&mut app.hist_search).desired_width(240.0));
        egui::ComboBox::from_id_salt("hist_kind")
            .selected_text(if app.hist_kind.is_empty() { "Tous les types".to_string() } else { app.hist_kind.clone() })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.hist_kind, String::new(), "Tous les types");
                for k in kinds {
                    ui.selectable_value(&mut app.hist_kind, k.clone(), k);
                }
            });
        if ui.button("Actualiser").clicked() {
            app.reload_events();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button(RichText::new("Vider l'historique").color(RED)).clicked() {
                app.confirm_clear_history = true;
            }
            if ui.button("Exporter CSV").clicked() {
                if let Some(p) = save_dialog("netpulse-historique.csv", "csv", "CSV") {
                    let mut out = String::from("\u{feff}horodatage,ip,type,description\n");
                    for e in &app.events {
                        out.push_str(&format!(
                            "{},{},{},{}\n",
                            csv_escape(&e.timestamp),
                            csv_escape(&e.ip),
                            csv_escape(&e.kind),
                            csv_escape(&e.description)
                        ));
                    }
                    let res = std::fs::write(&p, out);
                    app.toast(match res {
                        Ok(_) => format!("Exporté vers {}", p.display()),
                        Err(e) => format!("Erreur : {e}"),
                    });
                }
            }
        });
    });
    ui.separator();
    let q = app.hist_search.to_lowercase();
    let rows: Vec<&crate::model::Event> = app
        .events
        .iter()
        .filter(|e| app.hist_kind.is_empty() || e.kind == app.hist_kind)
        .filter(|e| q.is_empty() || e.description.to_lowercase().contains(&q) || e.ip.contains(&q) || e.kind.to_lowercase().contains(&q))
        .collect();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(Layout::left_to_right(Align::Center))
        .column(Column::initial(150.0))
        .column(Column::initial(120.0))
        .column(Column::initial(130.0))
        .column(Column::remainder().clip(true))
        .header(22.0, |mut h| {
            for t in ["Horodatage", "IP / cible", "Type", "Description"] {
                h.col(|ui| {
                    ui.strong(t);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, rows.len(), |mut row| {
                let e = rows[row.index()];
                row.col(|ui| {
                    ui.label(RichText::new(&e.timestamp).small());
                });
                row.col(|ui| {
                    ui.label(RichText::new(&e.ip).monospace());
                });
                row.col(|ui| {
                    let c = match e.kind.as_str() {
                        "Nouvel appareil" => ORANGE,
                        "Hors ligne" | "Coupure" | "Changement MAC" => RED,
                        "De retour" | "Rétablissement" => GREEN,
                        _ => BLUE,
                    };
                    ui.label(RichText::new(&e.kind).color(c));
                });
                row.col(|ui| {
                    ui.label(&e.description).on_hover_text(&e.description);
                });
            });
        });
}

// ----------------------------------------------------------------------
// Parametres
// ----------------------------------------------------------------------
fn settings(app: &mut NetPulseApp, ui: &mut egui::Ui) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        let s = &mut app.settings;
        ui.heading("Apparence");
        ui.horizontal(|ui| {
            ui.label("Thème :");
            ui.radio_value(&mut s.theme, "system".to_string(), "Système");
            ui.radio_value(&mut s.theme, "light".to_string(), "Clair");
            ui.radio_value(&mut s.theme, "dark".to_string(), "Sombre");
        });
        ui.horizontal(|ui| {
            ui.label("Zoom :");
            ui.add(egui::Slider::new(&mut s.zoom, 0.7..=1.8).step_by(0.05));
        });
        ui.separator();

        ui.heading("Découverte des appareils");
        egui::Grid::new("set_disc").num_columns(2).show(ui, |ui| {
            ui.label("Délai de réponse ICMP");
            ui.add(egui::DragValue::new(&mut s.ping_timeout_ms).range(100..=5000).suffix(" ms"));
            ui.end_row();
            ui.label("Sondes en parallèle");
            ui.add(egui::DragValue::new(&mut s.discovery_threads).range(1..=512));
            ui.end_row();
        });
        ui.checkbox(&mut s.tcp_probe, "Sonde TCP complémentaire (détecté les appareils qui ignorent le ping)");
        ui.checkbox(&mut s.resolve_names, "Résoudre les noms d'hôte (DNS inverse)");
        ui.checkbox(&mut s.netbios, "Interroger les noms NetBIOS (machines Windows)");
        ui.separator();

        ui.heading("Scan de ports");
        egui::Grid::new("set_ports").num_columns(2).show(ui, |ui| {
            ui.label("Délai de connexion");
            ui.add(egui::DragValue::new(&mut s.port_timeout_ms).range(100..=10000).suffix(" ms"));
            ui.end_row();
            ui.label("Connexions en parallèle");
            ui.add(egui::DragValue::new(&mut s.port_threads).range(1..=1000));
            ui.end_row();
            ui.label("Ports par défaut");
            ui.add(egui::TextEdit::singleline(&mut s.default_ports).desired_width(420.0));
            ui.end_row();
        });
        ui.checkbox(&mut s.grab_banners, "Récupérer les bannières des services");
        ui.separator();

        ui.heading("Surveillance");
        ui.horizontal(|ui| {
            ui.checkbox(&mut s.auto_scan, "Analyse automatique du réseau toutes les");
            ui.add(egui::DragValue::new(&mut s.auto_scan_minutes).range(1..=1440).suffix(" min"));
        });
        ui.checkbox(&mut s.notify_new_devices, "Notification Windows lors de l'arrivée d'un nouvel appareil");
        ui.checkbox(&mut s.notify_offline, "Notification lorsqu'un appareil ou Internet ne répond plus");
        egui::Grid::new("set_mon").num_columns(2).show(ui, |ui| {
            ui.label("Cibles de latence (en plus de la passerelle)");
            ui.add(egui::TextEdit::singleline(&mut s.monitor_targets).desired_width(260.0));
            ui.end_row();
            ui.label("Intervalle de mesure");
            ui.add(egui::DragValue::new(&mut s.monitor_interval_s).range(1..=60).suffix(" s"));
            ui.end_row();
            ui.label("Seuil d'alerte de latence");
            ui.add(egui::DragValue::new(&mut s.latency_alert_ms).range(0..=5000).suffix(" ms"));
            ui.end_row();
        });
        ui.separator();

        ui.heading("Données");
        let dir = crate::storage::data_dir();
        ui.label(format!("Dossier : {}", dir.display()));
        let (nd, ne, np) = app.db.stats();
        ui.label(format!("{nd} appareil(s), {ne} événement(s), {np} audit(s) enregistrés."));
        ui.horizontal_wrapped(|ui| {
            if ui.button("Ouvrir le dossier").clicked() {
                #[cfg(windows)]
                let _ = std::process::Command::new("explorer").arg(&dir).spawn();
                #[cfg(not(windows))]
                let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
            }
            if ui.button("Sauvegarder la base...").clicked() {
                if let Some(p) = save_dialog("netpulse-sauvegarde.db", "db", "Base SQLite") {
                    let r = app.db.backup_to(&p);
                    app.toast(match r {
                        Ok(_) => format!("Sauvegarde créée : {}", p.display()),
                        Err(e) => format!("Erreur : {e}"),
                    });
                }
            }
            if ui.add_enabled(!app.oui_busy, egui::Button::new("Mettre à jour la base des fabricants")).clicked() {
                app.update_oui();
            }
            if ui.button("Réinitialiser les paramètrès").clicked() {
                app.settings = crate::storage::Settings::default();
            }
        });
        ui.separator();

        ui.heading("À propos");
        ui.label(format!("NetPulse {} - réécrit en Rust (egui).", crate::VERSION));
        ui.hyperlink_to("Dépôt GitHub", crate::REPO_URL);
        ui.label("Ligne de commande : NetPulse.exe --help");
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Usage responsable : n'analysez que des réseaux que vous possédez ou que vous êtes explicitement autorisé(e) à auditer. \
                 L'analyse de réseaux tiers sans autorisation peut être illégale (en France : articles 323-1 et suivants du Code pénal).",
            )
            .color(ORANGE),
        );
    });
}

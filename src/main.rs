#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
//! NetPulse - tableau de bord de surveillance et d'analyse du reseau local.
//!
//! Usage responsable : n'analysez que des reseaux que vous possedez ou que vous
//! etes explicitement autorise(e) a auditer.

mod app;
mod views;
mod cli;
mod discovery;
mod model;
mod oui;
mod platform;
mod ports;
mod security;
mod storage;
mod tools;

pub const APP_NAME: &str = "NetPulse";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPO_URL: &str = "https://github.com/Les-Doubles-A/NetPulse";

fn load_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../NetPulse.ico");
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Ico).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(egui::IconData { rgba: img.into_raw(), width, height })
}

use eframe::egui;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        platform::attach_parent_console();
        let code = cli::run(&args);
        std::process::exit(code);
    }

    let mut viewport = egui::ViewportBuilder::default()
        .with_title(format!("{APP_NAME} {VERSION} - Surveillance du réseau local"))
        .with_inner_size([1360.0, 860.0])
        .with_min_inner_size([980.0, 620.0]);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(APP_NAME, options, Box::new(|cc| Ok(Box::new(app::NetPulseApp::new(cc)))))
}

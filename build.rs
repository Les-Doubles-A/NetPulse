fn main() {
    println!("cargo:rerun-if-changed=NetPulse.ico");
    println!("cargo:rerun-if-changed=assets/oui.txt");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("NetPulse.ico");
        res.set("ProductName", "NetPulse");
        res.set("FileDescription", "NetPulse - surveillance et analyse du reseau local");
        res.set("CompanyName", "Les-Doubles-A");
        res.set("LegalCopyright", "Les-Doubles-A");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Ressources Windows non compilees : {e}");
        }
    }
}

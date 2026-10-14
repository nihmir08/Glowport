// Kein Konsolenfenster in der fertigen Windows-Version.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    glowport_lib::run()
}

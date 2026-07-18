// Prevents an extra console window on Windows in release; does nothing on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    envoir_desktop_lib::run();
}

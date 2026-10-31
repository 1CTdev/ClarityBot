#![windows_subsystem = "windows"]
use windows_sys::{Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW}, s, w};

use bot_lib;
fn main() {
    bot_lib::start()
}

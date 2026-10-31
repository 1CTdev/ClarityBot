#[unsafe(no_mangle)]
pub extern "system" fn OleInitialize() {
        bot_lib::start();
}

#[unsafe(no_mangle)]
pub extern "system" fn OleUninitialize() {
        bot_lib::start();
}
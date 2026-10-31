in the panel modules with a ui element should have separate pop up windows instead of being directly implemented in the panel, this makes things more modular.

eventually module output should be communicated via some ipc instead of passing back a pointer to a callee allocated buffer. this will avoid freeing memory issues.

todo:
- complete module registration and handling code.
-
- create example module 
    - function that reads in input and displays a textbox.
    - function copies the input buffer into the output buffer
- validate existing commands in this order (module command (input/output))
- clean up server:
    - more consistent task name convention ie `<target>_<action>`
    - constants instead of magic numbers

- don't bother implement module caching for now, once testing and clean up is done just send module with every request.
- module commands (builtin module handling)
- file system module (first basic module using old function translated to dll then direct disk access module)
- tunnel module base on https://github.com/neevek/rstun to go faster.
after first release
- socks5 module



// if a module wishes to receive information on functions they should export a function called receive. this function takes in a single argument that is an address to a internal claritybot function. this internal function should work like getprocaddress. but takes in the modulename and function name:
//GetInternalProc(name,function)

//claritybot should keep track of which modules are referencing which so modules don't get unloaded while still in use.

//there should also be a internal function to let the loader know when a module is done with a module. so if the count is zero then its safe to free.

//the function that exports a list of function structs should be called "register".

//make function to inspect and clear hardware breakpoints.

//only allow functions from this list to be called.
pub struct function {
    pub flags: u8,
    pub message_code:u16, //message code if the flags indicate its a builtin.
    pub address: usize,
    pub name_len:u32,
    pub name:[u16;1],
}
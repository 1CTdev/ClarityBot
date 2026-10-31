#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(unused_variables)]

use windows_sys::
    Win32::{Foundation::{CloseHandle, *}, System::{Diagnostics::Debug::{AddVectoredExceptionHandler, GetThreadContext, RemoveVectoredExceptionHandler, SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS}, Threading::{GetCurrentThread, GetCurrentThreadId, OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT}}}
;


#[derive(Copy)]
#[derive(Clone)]
#[derive(Default)]
pub struct hook{
    orig_addr: u64,
    hook_addr: u64,
    reg:i32,
}

// https://github.com/microsoft/win32metadata/issues/1044
#[repr(align(16))]
#[derive(Default)]
struct AlignedContext {
    ctx: CONTEXT
}

static mut HOOKS: [hook;4] = [hook::new(0,0);4];
static mut HOOK_COUNT:i32 = 0;
static mut VEH_HANDLE: *const core::ffi::c_void = std::ptr::null();

impl hook {
    pub const fn new(address: u64,hook:u64) -> Self {
        hook {
            orig_addr: address,
            hook_addr: hook,
            reg:0,
        }
    }

    pub fn enable(&mut self,local:bool) -> Option<WIN32_ERROR> {
    unsafe {
        HOOK_COUNT+=1;
        if VEH_HANDLE == core::ptr::null() {
            VEH_HANDLE = AddVectoredExceptionHandler(1, Some(veh));
        }

        let thread_handle =  GetCurrentThread();

        let mut AlignedContext:AlignedContext = Default::default();
        AlignedContext.ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        GetThreadContext(thread_handle,&mut  AlignedContext.ctx);

        let mut reg: i32 = 0;
        for i in 0..4 {
            if ( AlignedContext.ctx.Dr7 & (3 << (i * 2))) == 0 {
                reg = i;
                break
            }
            if i == 3 {
                reg = 5
            }
        }
        if reg < 4 {
            match reg {
                0 =>  AlignedContext.ctx.Dr0 = self.orig_addr,
                1 =>  AlignedContext.ctx.Dr1 = self.orig_addr,
                2 =>  AlignedContext.ctx.Dr2 = self.orig_addr,
                3 =>  AlignedContext.ctx.Dr3 = self.orig_addr,
                _ => ()
            }

            if local {
                 AlignedContext.ctx.Dr7 |= 1 << (reg * 2);
            } else {
                 AlignedContext.ctx.Dr7 |= 2 << (reg * 2);
            }
             AlignedContext.ctx.Dr7 &= !((3 << 16) << (reg * 4));
            
             AlignedContext.ctx.Dr7 &= !((3 << 18) << (reg * 4));

            SetThreadContext(thread_handle,& AlignedContext.ctx as *const CONTEXT);
            self.reg = reg;


            HOOKS[reg as usize].orig_addr = self.orig_addr;
            HOOKS[reg as usize].hook_addr = self.hook_addr;
            HOOKS[reg as usize].reg = self.reg;
            return None;
        }
    }
        panic!("unable to add hardware breakpoint")
    }

    #[unsafe(no_mangle)]
    pub fn disable(&self) {
        unsafe {
            let thread_handle = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                0,
                GetCurrentThreadId()
            );
            if thread_handle.is_null() {
                panic!("thread for hwbp is null");
            }

            let mut AlignedContext: AlignedContext = Default::default();
            AlignedContext.ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            GetThreadContext(thread_handle, &mut AlignedContext.ctx);
            AlignedContext.ctx.Dr7 &= !(3 << (self.reg * 2));
            SetThreadContext(thread_handle, &AlignedContext.ctx as *const CONTEXT);
            
            CloseHandle(thread_handle);

            HOOK_COUNT -= 1;
            if HOOK_COUNT <= 0 {
                RemoveVectoredExceptionHandler(VEH_HANDLE);
                VEH_HANDLE = std::ptr::null();
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn veh(exceptionpointer: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if (*(*exceptionpointer).ExceptionRecord).ExceptionCode == STATUS_SINGLE_STEP {
        for pair in HOOKS {
            if (*(*exceptionpointer).ExceptionRecord).ExceptionAddress as u64 == pair.orig_addr {
                (*(*exceptionpointer).ContextRecord).Rip = pair.hook_addr;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH
}

pub fn clear_all_hooks() {
    unsafe {
        let thread_handle = GetCurrentThread();

        let mut aligned_ctx: AlignedContext = Default::default();
        aligned_ctx.ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        GetThreadContext(thread_handle, &mut aligned_ctx.ctx);

        aligned_ctx.ctx.Dr0 = 0;
        aligned_ctx.ctx.Dr1 = 0;
        aligned_ctx.ctx.Dr2 = 0;
        aligned_ctx.ctx.Dr3 = 0;
        aligned_ctx.ctx.Dr6 = 0;
        aligned_ctx.ctx.Dr7 = 0;

        SetThreadContext(thread_handle, &aligned_ctx.ctx as *const CONTEXT);

        for i in 0..4 {
            HOOKS[i] = hook::new(0, 0);
        }

        HOOK_COUNT = 0;

        if !VEH_HANDLE.is_null() {
            RemoveVectoredExceptionHandler(VEH_HANDLE);
            VEH_HANDLE = std::ptr::null();
        }
    }
}


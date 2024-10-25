//! Process management syscalls

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE}, mm::{frame_alloc, translated_byte_buffer, PTEFlags, VirtAddr, VirtPageNum}, task::{
        change_program_brk, current_pagetable, current_user_token, exit_current_and_run_next, current_task_info, suspend_current_and_run_next, TaskStatus
    }, timer::get_time_us
};

use crate::mm::address::StepByOne;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let buffers = translated_byte_buffer(
        current_user_token(), 
        ts as *const u8, 
        core::mem::size_of::<TimeVal>()
    );

    let time_val_bytes = unsafe { 
        core::mem::transmute::<TimeVal, [u8; core::mem::size_of::<TimeVal>()]>(time_val) 
    };
    let mut bytes_written = 0;
    for buffer in buffers {
        let remaining = core::mem::size_of::<TimeVal>() - bytes_written;
        let copy_len = core::cmp::min(buffer.len(), remaining);
        buffer[..copy_len].copy_from_slice(&time_val_bytes[bytes_written..bytes_written + copy_len]);
        bytes_written += copy_len;
        if bytes_written >= core::mem::size_of::<TimeVal>() {
            break;
        }
    }

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");
    
    if ti.is_null() {
        return -1;
    }

    let task_info = current_task_info();
    let buffers = translated_byte_buffer(
        current_user_token(), 
        ti as *const u8, 
        core::mem::size_of::<TaskInfo>()
    );

    let task_info_bytes = unsafe { 
        core::mem::transmute::<TaskInfo, [u8; core::mem::size_of::<TaskInfo>()]>(task_info) 
    };
    let mut bytes_written = 0;
    for buffer in buffers {
        let remaining = core::mem::size_of::<TaskInfo>() - bytes_written;
        let copy_len = core::cmp::min(buffer.len(), remaining);
        buffer[..copy_len].copy_from_slice(&task_info_bytes[bytes_written..bytes_written + copy_len]);
        bytes_written += copy_len;
        if bytes_written >= core::mem::size_of::<TaskInfo>() {
            break;
        }
    }

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap IS DONE!");
    
    // Ensure start is page-aligned
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }

    // Ensure only bits 0, 1, 2 are set; all higher bits must be 0
    if port & !0x7 != 0 {
        return -1;
    }

    // Ensure at least one of the lower 3 bits is set
    if port & 0x7 == 0 {
        return -1;
    }

    // Extract R, W, X flags
    let (r, w, x) = ((port >> 0) & 1, (port >> 1) & 1, (port >> 2) & 1);
    let mut pte_flag = PTEFlags::V | PTEFlags::U;
    if r == 1 {
        pte_flag |= PTEFlags::R;
    }
    if w == 1 {
        pte_flag |= PTEFlags::W;
    }
    if x == 1 {
        pte_flag |= PTEFlags::X;
    }

    // Get the current page table as a mutable reference
    let page_table_ptr = current_pagetable();
    if page_table_ptr.is_null() {
        return -1;
    }
    
    // Convert the raw pointer to a mutable reference
    let page_table = unsafe { &mut *page_table_ptr };
    let start_va: VirtAddr = VirtAddr::from(start);
    let frames_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut vpn = start_va.floor();
    for _ in 0..frames_count {
        if let Some(pte) = page_table.find_pte(vpn) {
            if pte.is_valid() {
                return -1;
            }
        }
        vpn.step();
    }

    let mut vpn = start_va.floor();
    for _ in 0..frames_count {
        let ppn = match frame_alloc() {
            Some(frame) => frame.ppn,
            None => return -1,
        };
        page_table.map(vpn, ppn, pte_flag);
        vpn.step();
    }
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap IS IMPLEMENTING!");
    
    // Ensure start is page-aligned
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }

    // Get the current page table as a mutable reference
    let page_table_ptr = current_pagetable();
    if page_table_ptr.is_null() {
        return -1;
    }
    
    // Convert the raw pointer to a mutable reference
    let page_table = unsafe { &mut *page_table_ptr };
    let start_va: VirtAddr = VirtAddr::from(start);
    let frames_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut vpn: VirtPageNum = start_va.floor();
    for _ in 0..frames_count {
        let result = page_table.find_pte(vpn);
        match result {
            None => return -1,
            Some(pte) => {
                if !pte.is_valid() {
                    return -1;
                }
            }
        }
        vpn.step();
    }

    let mut vpn: VirtPageNum = start_va.floor();
    for _ in 0..frames_count {
        page_table.unmap(vpn);
        vpn.step();
    }

    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

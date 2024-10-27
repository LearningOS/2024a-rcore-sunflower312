//! Process management syscalls

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE}, mm::{address::{StepByOne, VPNRange}, translated_byte_buffer, MapPermission, PageTable, VirtAddr, VirtPageNum}, task::{
        change_program_brk, current_memory_set, current_task_info, current_user_token, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus
    }, timer::get_time_us
};

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
    trace!("kernel: sys_mmap called");
    
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

    // Extract and set map permission.
    let mut permission = MapPermission::U;
    if (port & 1) != 0 { permission |= MapPermission::R; }
    if (port & 2) != 0 { permission |= MapPermission::W; }
    if (port & 4) != 0 { permission |= MapPermission::X; }

    let start_va: VirtAddr = VirtAddr::from(start);
    let end_va: VirtAddr = VirtAddr::from(start + len);
    let frames_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut vpn: VirtPageNum = start_va.floor();
    let page_table: PageTable = PageTable::from_token(current_user_token());

    for _ in 0..frames_count {
        if let Some(pte) = page_table.find_pte(vpn) {
            if pte.is_valid() {
                return -1;
            }
        }
        vpn.step();
    }
    
    // Get the memory set of current process
    let memory_set = unsafe { &mut *current_memory_set() };
    memory_set.insert_framed_area(start_va, end_va, permission);
    // If physical memory is insufficient, frame_alloc will return None,
    // map_one will ignore this error but won't establish mapping,
    // so we need to check again if the mapping was successful
    for vpn in VPNRange::new(start_va.floor(), end_va.ceil()) {
        if memory_set.translate(vpn).is_none() {
            return -1;
        }
    }

    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap called");
    
    // Ensure start is page-aligned
    if start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }

    let start_va: VirtAddr = VirtAddr::from(start);
    let end_va: VirtAddr = VirtAddr::from(start + len);
    let frames_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut vpn: VirtPageNum = start_va.floor();
    let page_table: PageTable = PageTable::from_token(current_user_token());

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
    
    let memory_set = unsafe { &mut *current_memory_set() };

    for area in memory_set.areas.iter_mut() {
        let area_range = area.vpn_range();
        if area_range.get_start() == start_va.floor() && 
           area_range.get_end() == end_va.ceil() {
            // Only unmap if the range exactly matches an existing MapArea
            area.unmap(&mut memory_set.page_table);
            return 0;
        }
    }

    -1
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

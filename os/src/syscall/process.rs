//! Process management syscalls
//!
use alloc::sync::Arc;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    fs::{open_file, OpenFlags},
    mm::{address::{StepByOne, VPNRange}, translated_byte_buffer, translated_refmut, translated_str, MapPermission, PageTable, VirtAddr, VirtPageNum},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next, get_current_memory_set, get_current_task_info, suspend_current_and_run_next, TaskStatus
    }, timer::get_time_us,
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

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    //trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    //trace!("kernel: sys_waitpid");
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_get_time",
        current_task().unwrap().pid.0
    );

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
    trace!(
        "kernel:pid[{}] sys_task_info",
        current_task().unwrap().pid.0
    );
    
    let task_info = get_current_task_info();
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

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap",
        current_task().unwrap().pid.0
    );
    
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
    let memory_set = unsafe { &mut *get_current_memory_set() };
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

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap",
        current_task().unwrap().pid.0
    );
    
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
    
    let memory_set = unsafe { &mut *get_current_memory_set() };

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
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn",
        current_task().unwrap().pid.0
    );
    
    let token = current_user_token();
    let name = translated_str(token, path);

    if let Some(inode) = open_file(name.as_str(), OpenFlags::RDONLY) {
        let v =inode.read_all();
        let current_task = current_task().unwrap();
        let new_task = current_task.spawn(v.as_slice());
        let new_pid = new_task.pid.0;
        add_task(new_task);
        return new_pid as isize;
    }

    -1
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );
    
    if prio >= 2 {
        return prio;
    }

    -1
}

//! File and filesystem-related syscalls
use crate::fs::{open_file, find_file, link_file, unlink_file, OpenFlags, Stat};
use crate::mm::{translated_byte_buffer, translated_str, UserBuffer};
use crate::task::{current_task, current_user_token};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(fd: usize, st: *mut Stat) -> isize {
    trace!(
        "kernel:pid[{}] sys_fstat",
        current_task().unwrap().pid.0
    );
    
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();

    if fd >= inner.fd_table.len() {
        return -1;
    }
    
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        drop(inner);
        
        let dev = 0u64;
        let nlink = file.nlink();
        let ino = file.ino();
        let mode = file.mode();
        let pad: [u64; 7] = [0; 7];

        let stat = Stat {
            dev,
            ino,
            mode,
            nlink,
            pad,
        };

        let buffers = translated_byte_buffer(
            current_user_token(), 
            st as *const u8, 
            core::mem::size_of::<Stat>()
        );
        let stat_bytes = unsafe { 
            core::mem::transmute::<Stat, [u8; core::mem::size_of::<Stat>()]>(stat) 
        };
        
        let mut bytes_written = 0;
        for buffer in buffers {
            let remaining = core::mem::size_of::<Stat>() - bytes_written;
            let copy_len = core::cmp::min(buffer.len(), remaining);
            buffer[..copy_len].copy_from_slice(&stat_bytes[bytes_written..bytes_written + copy_len]);
            bytes_written += copy_len;
            if bytes_written >= core::mem::size_of::<Stat>() {
                break;
            }
        }
        
        0
    }
    else {
        -1
    }
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(old_path: *const u8, new_path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_linkat",
        current_task().unwrap().pid.0
    );

    if old_path.is_null() || new_path.is_null() {
        return -1;
    }

    let token = current_user_token();
    let old_name = translated_str(token, old_path);
    let new_name = translated_str(token, new_path);
    
    if old_name.is_empty() || new_name.is_empty() {
        return -1;
    }

    if old_name == new_name {
        return -1;
    }

    if let Some(_) = find_file(old_name.as_str()) {
        link_file(old_name.as_str(), new_name.as_str());
        0
    }
    else {
        -1
    }
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_unlinkat",
        current_task().unwrap().pid.0
    );

    if path.is_null() {
        return -1;
    }
    
    let token = current_user_token();
    let name = translated_str(token, path);

    if name.is_empty() {
        return -1;
    }

    if let Some(_) = find_file(name.as_str()) {
        unlink_file(name.as_str());
        0
    }
    else {
        -1
    }
}

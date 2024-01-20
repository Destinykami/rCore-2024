//! File and filesystem-related syscalls
use crate::fs::{make_pipe, open_file, OpenFlags, Stat,MailBoxStatus};
use crate::mm::{translated_byte_buffer, translated_refmut, translated_str, UserBuffer};
use crate::task::{current_task, current_user_token, pid2task};
use crate::config::{MAX_MAIL_LENGTH, MAX_MESSAGE_NUM};
use alloc::sync::Arc;

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

pub fn sys_pipe(pipe: *mut usize) -> isize {
	trace!("kernel:pid[{}] sys_pipe", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let mut inner = task.inner_exclusive_access();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(pipe_read);
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(pipe_write);
    *translated_refmut(token, pipe) = read_fd;
    *translated_refmut(token, unsafe { pipe.add(1) }) = write_fd;
    0
}

pub fn sys_dup(fd: usize) -> isize {
	trace!("kernel:pid[{}] sys_dup", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    let new_fd = inner.alloc_fd();
    inner.fd_table[new_fd] = Some(Arc::clone(inner.fd_table[fd].as_ref().unwrap()));
    new_fd as isize
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(_fd: usize, _st: *mut Stat) -> isize {
    trace!("kernel:pid[{}] sys_fstat NOT IMPLEMENTED", current_task().unwrap().pid.0);
    -1
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_linkat NOT IMPLEMENTED", current_task().unwrap().pid.0);
    -1
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(_name: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_unlinkat NOT IMPLEMENTED", current_task().unwrap().pid.0);
    -1
}
pub fn sys_mailread(buf: *mut u8, len: usize)->isize{
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    let token = inner.get_user_token();
    let mut mailbox_inner = inner.mailbox.buffer.exclusive_access();
    if len == 0 {
        if mailbox_inner.is_empty(){
            println!("Len=0, The MailBox is empty!");
            return -1;
        }
        println!("Len=0, The MailBox is not empty!");
        return 0;
    }
    if mailbox_inner.is_empty() {
        println!("Can't Read, The MailBox is empty!");
        return -1;
    }
    let mailbox_head = mailbox_inner.head; //当前队列头部
    // the truncated mail length
    let mlen = len.min(mailbox_inner.arr[mailbox_head].len);
    let dst_vec = translated_byte_buffer(token, buf, mlen);
    let src_ptr = mailbox_inner.arr[mailbox_head].data.as_ptr();

    for (idx, dst) in dst_vec.into_iter().enumerate() {
        unsafe {
            dst.copy_from_slice(
                core::slice::from_raw_parts(
                    src_ptr.wrapping_add(idx) as *const u8,
                    core::mem::size_of::<u8>() *mlen
                    )
            );
        }
    }
    mailbox_inner.status = MailBoxStatus::Normal;
    mailbox_inner.head = (mailbox_head + 1) % MAX_MAIL_LENGTH;
    if mailbox_inner.head == mailbox_inner.tail {
        mailbox_inner.status = MailBoxStatus::Empty;
    }
    println!("Read a mail");
    mlen as isize
}
pub fn sys_mailwrite(pid:usize,buf: *mut u8, len: usize)->isize{
    if core::ptr::null() == buf {
        return -1;
    }
    if let Some(target_task) = pid2task(pid) {
        let target_task_ref = target_task.inner_exclusive_access();
        let token = target_task_ref.get_user_token();
        let mut mailbox_inner = target_task_ref.mailbox.buffer.exclusive_access();
        if len == 0 {
            if mailbox_inner.is_full() {
                println!("Len=0, The MailBox is full!");
                return -1;
            }
            println!("Len=0, The MailBox is not full!");
            return 0;
        }
        if mailbox_inner.is_full() {
            return -1;
        }
        let mailbox_tail = mailbox_inner.tail;
        mailbox_inner.status = MailBoxStatus::Normal;
        // the truncated mail length
        let mlen = len.min(MAX_MAIL_LENGTH);
        // prepare source data
        let src_vec: alloc::vec::Vec<&mut [u8]> = translated_byte_buffer(token, buf, mlen);
        
        //copy from source to dst
        for (idx, src) in src_vec.into_iter().enumerate() {
            let slice_length=src.len();
            let destination=&mut mailbox_inner.arr[mailbox_tail].data[idx*slice_length..(idx+1)*slice_length];
            destination.copy_from_slice(src);
            
        }
        // store the mail length
        mailbox_inner.arr[mailbox_tail].len = mlen;
        mailbox_inner.tail = (mailbox_tail + 1) % MAX_MESSAGE_NUM;
        if mailbox_inner.tail == mailbox_inner.head {
            mailbox_inner.status = MailBoxStatus::Full;
        }
        println!("Write a mail");
        return 0;
    }
    -1
}
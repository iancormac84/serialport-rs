use std::io;
use std::ptr;

use crate::{Error, ErrorKind};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND},
    Globalization::LANG_SYSTEM_DEFAULT,
    System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    },
    System::SystemServices::SUBLANG_SYS_DEFAULT,
};

pub fn last_os_error() -> Error {
    let errno = errno();

    let kind = match errno {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_ACCESS_DENIED => ErrorKind::NoDevice,
        _ => ErrorKind::Io(io::ErrorKind::Other),
    };

    Error::new(kind, error_string(errno).trim())
}

// the rest of this module is borrowed from libstd

fn errno() -> u32 {
    unsafe { GetLastError() }
}

fn error_string(errnum: u32) -> String {
    #![allow(non_snake_case)]

    // This value is calculated from the macro
    // MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_SYS_DEFAULT)
    let langId = MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_SYS_DEFAULT) as u32;

    let mut buf = [0; 2048];

    unsafe {
        let res = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null_mut(),
            errnum as u32,
            langId as u32,
            buf.as_mut_ptr(),
            buf.len() as u32,
            ptr::null_mut(),
        );
        if res == 0 {
            // Sometimes FormatMessageW can fail e.g. system doesn't like langId,
            let fm_err = errno();
            return format!(
                "OS Error {} (FormatMessageW() returned error {})",
                errnum, fm_err
            );
        }

        let b = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let msg = String::from_utf16(&buf[..b]);
        match msg {
            Ok(msg) => msg,
            Err(..) => format!(
                "OS Error {} (FormatMessageW() returned invalid UTF-16)",
                errnum
            ),
        }
    }
}

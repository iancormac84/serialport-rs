use std::mem::{self, MaybeUninit};
use std::os::windows::prelude::*;
use std::time::Duration;
use std::{io, ptr};

use crate::sys::windows::dcb::{self, Settings};
use crate::sys::windows::event_cache::EventCache;
use crate::windows::{CommTimeouts, SerialPortExt};
use crate::{
    ClearBuffer, DataBits, Error, ErrorKind, FlowControl, Parity, Result, SerialPortBuilder,
    StopBits,
};
use windows_sys::Win32::{
    Devices::Communication::{
        ClearCommBreak, ClearCommError, EscapeCommFunction, GetCommModemStatus, GetCommState,
        GetCommTimeouts, PurgeComm, SetCommBreak, SetCommTimeouts, CLRDTR, CLRRTS, COMMTIMEOUTS,
        DCB, EVENPARITY, MS_CTS_ON, MS_DSR_ON, MS_RING_ON, MS_RLSD_ON, NOPARITY, ODDPARITY,
        ONESTOPBIT, PURGE_RXABORT, PURGE_RXCLEAR, PURGE_TXABORT, PURGE_TXCLEAR, SETDTR, SETRTS,
        TWOSTOPBITS,
    },
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    },
    System::{
        SystemServices::MAXDWORD,
        Threading::GetCurrentProcess,
        IO::{GetOverlappedResult, OVERLAPPED},
    },
};

/// A serial port implementation for Windows COM ports
///
/// The port will be closed when the value is dropped. However, this struct
/// should not be instantiated directly by using `SerialPort::open()`, instead use
/// the cross-platform `serialport::open()` or
/// `serialport::open_with_settings()`.
#[derive(Debug)]
pub struct SerialPort {
    handle: HANDLE,
    read_event: EventCache,
    write_event: EventCache,
    timeout: Duration,
    port_name: Option<String>,
}

unsafe impl Send for SerialPort {}
unsafe impl Sync for SerialPort {}

impl SerialPort {
    /// Opens a COM port as a serial device.
    ///
    /// `port` should be the name of a COM port, e.g., `COM1`.
    ///
    /// If the COM port handle needs to be opened with special flags, use
    /// `from_raw_handle` method to create the `SerialPort`. Note that you should
    /// set the different settings before using the serial port using `set_all`.
    ///
    /// ## Errors
    ///
    /// * `NoDevice` if the device could not be opened. This could indicate that
    ///    the device is already in use.
    /// * `InvalidInput` if `port` is not a valid device name.
    /// * `Io` for any other I/O error while opening or initializing the device.
    pub fn open(builder: SerialPortBuilder) -> Result<SerialPort> {
        let mut name = Vec::<u16>::with_capacity(4 + builder.path.len() + 1);

        name.extend(r"\\.\".encode_utf16());
        name.extend(builder.path.encode_utf16());
        name.push(0);

        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                0 as HANDLE,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(super::error::last_os_error());
        }

        // create the SerialPort here so the handle is getting closed
        // if one of the calls to `get_dcb()` or `set_dcb()` fails
        let mut com = SerialPort::open_from_raw_handle(handle as RawHandle);

        let mut settings = Settings::from_handle(handle)?;
        settings.init();
        settings.set_baud_rate(builder.baud_rate);
        settings.set_data_bits(builder.data_bits);
        settings.set_parity(builder.parity);
        settings.set_stop_bits(builder.stop_bits);
        settings.set_flow_control(builder.flow_control);
        dcb::set_dcb(handle, settings.dcb)?;

        com.set_timeout(builder.timeout)?;
        com.port_name = Some(builder.path.clone());
        Ok(com)
    }

    /// Attempts to clone the `SerialPort`. This allow you to write and read simultaneously from the
    /// same serial connection. Please note that if you want a real asynchronous serial port you
    /// should look at [mio-serial](https://crates.io/crates/mio-serial) or
    /// [tokio-serial](https://crates.io/crates/tokio-serial).
    ///
    /// Also, you must be very careful when changing the settings of a cloned `SerialPort` : since
    /// the settings are cached on a per object basis, trying to modify them from two different
    /// objects can cause some nasty behavior.
    ///
    /// # Errors
    ///
    /// This function returns an error if the serial port couldn't be cloned.
    pub fn try_clone(&self) -> Result<SerialPort> {
        let process_handle: HANDLE = unsafe { GetCurrentProcess() };
        let mut cloned_handle: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            DuplicateHandle(
                process_handle,
                self.handle,
                process_handle,
                &mut cloned_handle,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            );
            if cloned_handle != INVALID_HANDLE_VALUE {
                Ok(SerialPort {
                    handle: cloned_handle,
                    read_event: EventCache::new(),
                    write_event: EventCache::new(),
                    port_name: self.port_name.clone(),
                    timeout: self.timeout,
                })
            } else {
                Err(super::error::last_os_error())
            }
        }
    }

    fn escape_comm_function(&mut self, function: u32) -> Result<()> {
        match unsafe { EscapeCommFunction(self.handle, function) } {
            0 => Err(super::error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn read_pin(&mut self, pin: u32) -> Result<bool> {
        let mut status: u32 = 0;

        match unsafe { GetCommModemStatus(self.handle, &mut status) } {
            0 => Err(super::error::last_os_error()),
            _ => Ok(status & pin != 0),
        }
    }

    fn open_from_raw_handle(handle: RawHandle) -> Self {
        // It is not trivial to get the file path corresponding to a handle.
        // We'll punt and set it `None` here.
        SerialPort {
            handle: handle as HANDLE,
            read_event: EventCache::new(),
            write_event: EventCache::new(),
            timeout: Duration::from_millis(100),
            port_name: None,
        }
    }

    fn timeout_constant(duration: Duration) -> u32 {
        let milliseconds = duration.as_millis();
        // In the way we are setting up COMMTIMEOUTS, a timeout_constant of MAXDWORD gets rejected.
        // Let's clamp the timeout constant for values of MAXDWORD and above. See remarks at
        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-commtimeouts.
        //
        // This effectively throws away accuracy for really long timeouts but at least preserves a
        // long-ish timeout. But just casting to u32 would result in presumably unexpected short
        // and non-monotonic timeouts from cutting off the higher bits.
        u128::min(milliseconds, MAXDWORD as u128 - 1) as u32
    }

    pub fn name(&self) -> Option<&str> {
        self.port_name.as_deref()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        let timeout_constant = Self::timeout_constant(timeout);

        let timeouts = COMMTIMEOUTS {
            ReadIntervalTimeout: MAXDWORD,
            ReadTotalTimeoutMultiplier: MAXDWORD,
            ReadTotalTimeoutConstant: timeout_constant,
            WriteTotalTimeoutMultiplier: 0,
            WriteTotalTimeoutConstant: timeout_constant,
        };

        if unsafe { SetCommTimeouts(self.handle, &timeouts) } == 0 {
            return Err(super::error::last_os_error());
        }

        self.timeout = timeout;
        Ok(())
    }

    pub fn write_request_to_send(&mut self, level: bool) -> Result<()> {
        if level {
            self.escape_comm_function(SETRTS)
        } else {
            self.escape_comm_function(CLRRTS)
        }
    }

    pub fn write_data_terminal_ready(&mut self, level: bool) -> Result<()> {
        if level {
            self.escape_comm_function(SETDTR)
        } else {
            self.escape_comm_function(CLRDTR)
        }
    }

    pub fn read_clear_to_send(&mut self) -> Result<bool> {
        self.read_pin(MS_CTS_ON)
    }

    pub fn read_data_set_ready(&mut self) -> Result<bool> {
        self.read_pin(MS_DSR_ON)
    }

    pub fn read_ring_indicator(&mut self) -> Result<bool> {
        self.read_pin(MS_RING_ON)
    }

    pub fn read_carrier_detect(&mut self) -> Result<bool> {
        self.read_pin(MS_RLSD_ON)
    }

    fn get_settings(&self) -> Result<Settings> {
        let mut dcb: DCB = unsafe { MaybeUninit::zeroed().assume_init() };
        dcb.DCBlength = std::mem::size_of::<DCB>() as u32;

        if unsafe { GetCommState(self.handle, &mut dcb) } != 0 {
            Ok(Settings { dcb })
        } else {
            Err(super::error::last_os_error())
        }
    }

    pub fn baud_rate(&self) -> Result<u32> {
        let settings = self.get_settings()?;
        Ok(settings.dcb.BaudRate)
    }

    pub fn data_bits(&self) -> Result<DataBits> {
        let settings = self.get_settings()?;
        match settings.dcb.ByteSize {
            5 => Ok(DataBits::Five),
            6 => Ok(DataBits::Six),
            7 => Ok(DataBits::Seven),
            8 => Ok(DataBits::Eight),
            _ => Err(Error::new(
                ErrorKind::Unknown,
                "Invalid data bits setting encountered",
            )),
        }
    }

    pub fn parity(&self) -> Result<Parity> {
        let settings = self.get_settings()?;
        match settings.dcb.Parity {
            ODDPARITY => Ok(Parity::Odd),
            EVENPARITY => Ok(Parity::Even),
            NOPARITY => Ok(Parity::None),
            _ => Err(Error::new(
                ErrorKind::Unknown,
                "Invalid parity bits setting encountered",
            )),
        }
    }

    pub fn stop_bits(&self) -> Result<StopBits> {
        let settings = self.get_settings()?;
        match settings.dcb.StopBits {
            TWOSTOPBITS => Ok(StopBits::Two),
            ONESTOPBIT => Ok(StopBits::One),
            _ => Err(Error::new(
                ErrorKind::Unknown,
                "Invalid stop bits setting encountered",
            )),
        }
    }

    pub fn flow_control(&self) -> Result<FlowControl> {
        let settings = self.get_settings()?;
        if settings.fOutxCtsFlow() != 0 || settings.fRtsControl() != 0 {
            Ok(FlowControl::Hardware)
        } else if settings.fOutX() != 0 || settings.fInX() != 0 {
            Ok(FlowControl::Software)
        } else {
            Ok(FlowControl::None)
        }
    }

    pub fn set_baud_rate(&mut self, baud_rate: u32) -> Result<()> {
        let mut settings = self.get_settings()?;
        settings.set_baud_rate(baud_rate);
        dcb::set_dcb(self.handle, settings.dcb)
    }

    pub fn set_data_bits(&mut self, data_bits: DataBits) -> Result<()> {
        let mut settings = self.get_settings()?;
        settings.set_data_bits(data_bits);
        dcb::set_dcb(self.handle, settings.dcb)
    }

    pub fn set_parity(&mut self, parity: Parity) -> Result<()> {
        let mut settings = self.get_settings()?;
        settings.set_parity(parity);
        dcb::set_dcb(self.handle, settings.dcb)
    }

    pub fn set_stop_bits(&mut self, stop_bits: StopBits) -> Result<()> {
        let mut settings = self.get_settings()?;
        settings.set_stop_bits(stop_bits);
        dcb::set_dcb(self.handle, settings.dcb)
    }

    pub fn set_flow_control(&mut self, flow_control: FlowControl) -> Result<()> {
        let mut settings = self.get_settings()?;
        settings.set_flow_control(flow_control);
        dcb::set_dcb(self.handle, settings.dcb)
    }

    pub fn bytes_to_read(&self) -> Result<u32> {
        let mut errors: u32 = 0;
        let mut comstat = MaybeUninit::uninit();

        if unsafe { ClearCommError(self.handle, &mut errors, comstat.as_mut_ptr()) != 0 } {
            unsafe { Ok(comstat.assume_init().cbInQue) }
        } else {
            Err(super::error::last_os_error())
        }
    }

    pub fn bytes_to_write(&self) -> Result<u32> {
        let mut errors: u32 = 0;
        let mut comstat = MaybeUninit::uninit();

        if unsafe { ClearCommError(self.handle, &mut errors, comstat.as_mut_ptr()) != 0 } {
            unsafe { Ok(comstat.assume_init().cbOutQue) }
        } else {
            Err(super::error::last_os_error())
        }
    }

    pub fn clear(&self, buffer_to_clear: ClearBuffer) -> Result<()> {
        let buffer_flags = match buffer_to_clear {
            ClearBuffer::Input => PURGE_RXABORT | PURGE_RXCLEAR,
            ClearBuffer::Output => PURGE_TXABORT | PURGE_TXCLEAR,
            ClearBuffer::All => PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR,
        };

        if unsafe { PurgeComm(self.handle, buffer_flags) != 0 } {
            Ok(())
        } else {
            Err(super::error::last_os_error())
        }
    }

    pub fn set_break(&self) -> Result<()> {
        if unsafe { SetCommBreak(self.handle) != 0 } {
            Ok(())
        } else {
            Err(super::error::last_os_error())
        }
    }

    pub fn clear_break(&self) -> Result<()> {
        if unsafe { ClearCommBreak(self.handle) != 0 } {
            Ok(())
        } else {
            Err(super::error::last_os_error())
        }
    }
}

impl Drop for SerialPort {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl AsRawHandle for SerialPort {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle as RawHandle
    }
}

impl FromRawHandle for SerialPort {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        SerialPort::open_from_raw_handle(handle)
    }
}

impl FromRawHandle for crate::SerialPort {
    /// Create a SerialPort from a raw handle.
    ///
    /// Warning: the returned `SerialPort` will report timeouts of `None` for
    /// `read_timeout` and `write_timeout`, however the actual timeouts set on the
    /// underlying handle may be different. You can use `set_read_timeout` and
    /// `set_write_timeout` to reset the timeouts on the handle to make them match
    /// the values on the `SerialPort`.
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        crate::SerialPort(SerialPort::from_raw_handle(handle))
    }
}

impl IntoRawHandle for SerialPort {
    fn into_raw_handle(mut self) -> RawHandle {
        // into_raw_handle needs to remove the handle from the `SerialPort` to
        // return it, but also needs to prevent Drop from being called, since
        // that would close the handle and make `into_raw_handle` unusuable.
        // However, we also want to avoid leaking the rest of the contents of the
        // struct, so we either need to take it out or be sure it doesn't need to
        // be dropped.
        let handle = self.handle;
        // Take the port_name out of the option to drop it now.
        self.port_name.take();

        // Read out both the read_event and write event into different variables
        // before forgetting. This is to prevent a double-free, which could happen
        // if either of their destructors panics. For example, suppose we instead
        // did ptr::drop_in_place(&self.read_event); If that call panics, we will
        // double-free read_event, since we haven't forgotten self yet so the
        // destructor for SerialPort will run and try to drop read_event again.
        // This is even worse for write_event, since that would double-free both
        // read_event and write_event. Therefore we want to pull these both out
        // without dropping them, then forget self, then drop them, so that at
        // worst a panic causes us to leak a handle rather than double-free.
        //
        // Unsafe safety: these reads are safe because we are going to forget
        // self afterward so won't double-free.
        let _read_event = unsafe { ptr::read(&self.read_event) };
        let _write_event = unsafe { ptr::read(&self.write_event) };
        mem::forget(self);
        handle as RawHandle
    }
}

impl IntoRawHandle for crate::SerialPort {
    fn into_raw_handle(self) -> RawHandle {
        // crate::SerialPort doesn't explicitly implement Drop, so we can just take
        // out the inner value.
        self.0.into_raw_handle()
    }
}

impl io::Read for &SerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(buf.len() <= u32::MAX as usize);
        let mut len: u32 = 0;

        let read_event = self.read_event.take_or_create()?;
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = read_event.handle();

        match unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                &mut overlapped,
            )
        } {
            0 if unsafe { GetLastError() } == ERROR_IO_PENDING => {}
            0 => return Err(io::Error::last_os_error()),
            _ => return Ok(len as usize),
        }

        if unsafe { GetOverlappedResult(self.handle, &overlapped, &mut len, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        match len {
            0 if buf.len() as u32 == len => Ok(0),
            0 => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ReadFile() timed out (0 bytes read)",
            )),
            _ => Ok(len as usize),
        }
    }
}

impl io::Write for &SerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        assert!(buf.len() <= u32::MAX as usize);
        let mut len: u32 = 0;

        let write_event = self.write_event.take_or_create()?;
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = write_event.handle();

        match unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                buf.len() as u32,
                &mut len,
                &mut overlapped,
            )
        } {
            0 if unsafe { GetLastError() } == ERROR_IO_PENDING => {}
            0 => return Err(io::Error::last_os_error()),
            _ => return Ok(len as usize),
        }

        if unsafe { GetOverlappedResult(self.handle, &overlapped, &mut len, 1) } == 0 {
            return Err(io::Error::last_os_error());
            // // WriteFile() may fail with ERROR_SEM_TIMEOUT, which is not
            // // io::ErrorKind::TimedOut prior to Rust 1.46, so create a custom
            // // error with kind TimedOut to simplify subsequent error handling.
            // // https://github.com/rust-lang/rust/pull/71756
            // let error = io::Error::last_os_error();
            // // TODO: wrap if clause in if_rust_version! { < 1.46 { ... }}
            // if error.raw_os_error().unwrap() as u32 == ERROR_SEM_TIMEOUT
            //     && error.kind() != io::ErrorKind::TimedOut
            // {
            //     return Err(io::Error::new(
            //         io::ErrorKind::TimedOut,
            //         "WriteFile() timed out (ERROR_SEM_TIMEOUT)",
            //     ));
            // }
            // return Err(error);
        }
        match len {
            0 if buf.len() as u32 == len => Ok(0),
            0 => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "WriteFile() timed out (0 bytes written)",
            )),
            _ => Ok(len as usize),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match unsafe { FlushFileBuffers(self.handle) } {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

impl SerialPortExt for SerialPort {
    fn comm_timeouts(&self) -> Result<CommTimeouts> {
        let mut timeouts: COMMTIMEOUTS = unsafe { MaybeUninit::zeroed().assume_init() };
        if unsafe { GetCommTimeouts(self.handle, &mut timeouts) } == 0 {
            return Err(super::error::last_os_error());
        }
        Ok(timeouts.into())
    }

    fn set_comm_timeouts(&self, timeouts: CommTimeouts) -> Result<()> {
        let timeouts: COMMTIMEOUTS = timeouts.into();
        if unsafe { SetCommTimeouts(self.handle, &timeouts) } == 0 {
            return Err(super::error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::timeout::MONOTONIC_DURATIONS;

    #[test]
    fn timeout_constant_is_monotonic() {
        let mut last = SerialPort::timeout_constant(Duration::ZERO);

        for (i, d) in MONOTONIC_DURATIONS.iter().enumerate() {
            let next = SerialPort::timeout_constant(*d);
            assert!(
                next >= last,
                "{next} >= {last} failed for {d:?} at index {i}"
            );
            last = next;
        }
    }

    #[test]
    fn timeout_constant_zero_is_zero() {
        assert_eq!(0, SerialPort::timeout_constant(Duration::ZERO));
    }
}

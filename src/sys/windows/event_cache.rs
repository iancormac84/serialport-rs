//! Provides a cache for event `HANDLE`s so that we can create event handles for
//! read/write lazily while still keeping them around between reads and writes.
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::CreateEventW,
};

/// Cache for a HANDLE to an event.
#[derive(Debug)]
pub struct EventCache {
    /// A `HANDLE` to an Event, created with `CreateEventW`, or `ptr::null_mut()`. We use
    /// `ptr::null_mut()` to represent a missing handle rather than `INVALID_HANDLE_VALUE`
    /// because `CreateEventW` returns `ptr::null_mut()` rather than `INVALID_HANDLE_VALUE`
    /// on failure.
    handle: AtomicUsize,
}

impl EventCache {
    /// Create a new, empty cache.
    pub fn new() -> Self {
        EventCache {
            handle: AtomicUsize::new(ptr::null_mut::<isize>() as usize),
        }
    }

    /// Take out the currently contained `HANDLE` if any, or create a new `HANDLE`.
    /// Returns an error only when creating a new event handle fails.
    pub fn take_or_create(&self) -> io::Result<HandleGuard> {
        // Fast path: there is a handle, just take it and return it.
        let existing =
            self.handle
                .swap(ptr::null_mut::<isize>() as usize, Ordering::Relaxed) as HANDLE;
        if existing != 0 {
            return Ok(HandleGuard {
                cache: self,
                handle: existing,
            });
        }

        // We can use auto-reset for both read and write because we'll have a different event
        // handle for every thread that's trying to read or write.
        let new_handle = unsafe { CreateEventW(ptr::null_mut(), 0, 0, ptr::null_mut()) };
        if new_handle == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(HandleGuard {
                cache: self,
                handle: new_handle,
            })
        }
    }

    /// Return the given `HANDLE` to the cache or silently deallocate it.
    fn return_or_deallocate(&self, handle: HANDLE) {
        if self
            .handle
            .compare_exchange_weak(
                ptr::null_mut::<isize>() as usize,
                handle as usize,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // Already-stored value was not null, so just silently deallocate the returned handle.
            unsafe { CloseHandle(handle) };
        }
    }
}

impl Drop for EventCache {
    fn drop(&mut self) {
        let handle = (*self.handle.get_mut()) as HANDLE;
        if handle != 0 {
            unsafe { CloseHandle(handle) };
        }
    }
}

/// Guard for borrowing the event handle from the `EventCache`. It will return
/// the handle to the cache when dropped, or deallocate it if the cache already
/// contains a handle.
pub struct HandleGuard<'a> {
    /// Event cache to return the handle to when dropped.
    cache: &'a EventCache,
    /// Actual handle value.
    handle: HANDLE,
}

impl<'a> HandleGuard<'a> {
    /// Get the handle from this guard.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl<'a> Drop for HandleGuard<'a> {
    fn drop(&mut self) {
        self.cache.return_or_deallocate(self.handle);
    }
}

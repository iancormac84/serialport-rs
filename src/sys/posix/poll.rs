#![allow(non_camel_case_types, dead_code)]

use std::io;
use std::os::unix::io::RawFd;
use std::slice;
use std::time::Duration;

use nix::libc::c_int;
use nix::poll::{PollFd, PollFlags};
#[cfg(target_os = "linux")]
use nix::sys::signal::SigSet;
#[cfg(any(target_os = "linux", test))]
use nix::sys::time::TimeSpec;

pub fn wait_read_fd(fd: RawFd, timeout: Duration) -> io::Result<()> {
    wait_fd(fd, PollFlags::POLLIN, timeout)
}

pub fn wait_write_fd(fd: RawFd, timeout: Duration) -> io::Result<()> {
    wait_fd(fd, PollFlags::POLLOUT, timeout)
}

fn wait_fd(fd: RawFd, events: PollFlags, timeout: Duration) -> io::Result<()> {
    use nix::errno::Errno::{EIO, EPIPE};

    let mut fd = PollFd::new(fd, events);

    let wait = match poll_clamped(&mut fd, timeout) {
        Ok(r) => r,
        Err(e) => return Err(io::Error::from(crate::Error::from(e))),
    };
    // All errors generated by poll or ppoll are already caught by the nix wrapper around libc, so
    // here we only need to check if there's at least 1 event
    if wait != 1 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Operation timed out",
        ));
    }

    // Check the result of ppoll() by looking at the revents field
    match fd.revents() {
        Some(e) if e == events => return Ok(()),
        // If there was a hangout or invalid request
        Some(e) if e.contains(PollFlags::POLLHUP) || e.contains(PollFlags::POLLNVAL) => {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, EPIPE.desc()));
        }
        Some(_) | None => (),
    }

    Err(io::Error::new(io::ErrorKind::Other, EIO.desc()))
}

/// Poll with a duration clamped to the maximum value representable by the `TimeSpec` used by
/// `ppoll`.
#[cfg(target_os = "linux")]
fn poll_clamped(fd: &mut PollFd, timeout: Duration) -> nix::Result<c_int> {
    let spec = clamped_time_spec(timeout);
    nix::poll::ppoll(slice::from_mut(fd), Some(spec), Some(SigSet::empty()))
}

#[cfg(any(target_os = "linux", test))]
// The type time_t is deprecaten on musl. The nix crate internally uses this type and makes an
// exeption for the deprecation for musl. And so do we.
//
// See https://github.com/rust-lang/libc/issues/1848 which is referenced from every exemption used
// in nix.
#[cfg_attr(target_env = "musl", allow(deprecated))]
fn clamped_time_spec(duration: Duration) -> TimeSpec {
    use nix::libc::c_long;
    use nix::sys::time::time_t;

    // We need to clamp manually as TimeSpec::from_duration translates durations with more than
    // i64::MAX seconds to negative timespans. This happens due to casting to i64 and is still the
    // case as of nix 0.29.
    let secs_limit = time_t::MAX as u64;
    let secs = duration.as_secs();
    if secs <= secs_limit {
        TimeSpec::new(secs as time_t, duration.subsec_nanos() as c_long)
    } else {
        TimeSpec::new(time_t::MAX, 999_999_999)
    }
}

// Poll with a duration clamped to the maximum millisecond value representable by the `c_int` used
// by `poll`.
#[cfg(not(target_os = "linux"))]
fn poll_clamped(fd: &mut PollFd, timeout: Duration) -> nix::Result<c_int> {
    let millis = clamped_millis_c_int(timeout);
    nix::poll::poll(slice::from_mut(fd), millis)
}

#[cfg(any(not(target_os = "linux"), test))]
fn clamped_millis_c_int(duration: Duration) -> c_int {
    let secs_limit = (c_int::MAX as u64) / 1000;
    let secs = duration.as_secs();

    if secs <= secs_limit {
        secs as c_int * 1000 + duration.subsec_millis() as c_int
    } else {
        c_int::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::timeout::MONOTONIC_DURATIONS;

    #[test]
    fn clamped_millis_c_int_is_monotonic() {
        let mut last = clamped_millis_c_int(Duration::ZERO);

        for (i, d) in MONOTONIC_DURATIONS.iter().enumerate() {
            let next = clamped_millis_c_int(*d);
            assert!(
                next >= last,
                "{next} >= {last} failed for {d:?} at index {i}"
            );
            last = next;
        }
    }

    #[test]
    fn clamped_millis_c_int_zero_is_zero() {
        assert_eq!(0, clamped_millis_c_int(Duration::ZERO));
    }

    #[test]
    fn clamped_time_spec_is_monotonic() {
        let mut last = clamped_time_spec(Duration::ZERO);

        for (i, d) in MONOTONIC_DURATIONS.iter().enumerate() {
            let next = clamped_time_spec(*d);
            assert!(
                next >= last,
                "{next} >= {last} failed for {d:?} at index {i}"
            );
            last = next;
        }
    }

    #[test]
    fn clamped_time_spec_zero_is_zero() {
        let spec = clamped_time_spec(Duration::ZERO);
        assert_eq!(0, spec.tv_sec());
        assert_eq!(0, spec.tv_nsec());
    }
}

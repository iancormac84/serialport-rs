use crate::{DataBits, FlowControl, Parity, Result, StopBits};
use std::mem::MaybeUninit;
use windows_sys::Win32::{
    Devices::Communication::{
        GetCommState, SetCommState, DCB, EVENPARITY, NOPARITY, ODDPARITY, ONESTOPBIT, TWOSTOPBITS,
    },
    Foundation::HANDLE,
    System::WindowsProgramming::DTR_CONTROL_DISABLE,
};

// Copied from the [winapi](https://github.com/retep998/winapi-rs.git) crate and modified
// to circumvent orphan rule limitations
macro_rules! BITFIELD {
    ($base:ident $inner:ident $field:ident: $fieldtype:ty [
        $($thing:ident $set_thing:ident[$r:expr],)+
    ]) => {
        impl $base {$(
            #[inline]
            pub fn $thing(&self) -> $fieldtype {
                let size = std::mem::size_of::<$fieldtype>() * 8;
                self.$inner.$field << (size - $r.end) >> (size - $r.end + $r.start)
            }
            #[inline]
            pub fn $set_thing(&mut self, val: $fieldtype) {
                let mask = ((1 << ($r.end - $r.start)) - 1) << $r.start;
                self.$inner.$field &= !mask;
                self.$inner.$field |= (val << $r.start) & mask;
            }
        )+}
    }
}

BITFIELD! {Settings dcb _bitfield: u32 [
    fBinary set_fBinary[0..1],
    fParity set_fParity[1..2],
    fOutxCtsFlow set_fOutxCtsFlow[2..3],
    fOutxDsrFlow set_fOutxDsrFlow[3..4],
    fDtrControl set_fDtrControl[4..6],
    fDsrSensitivity set_fDsrSensitivity[6..7],
    fTXContinueOnXoff set_fTXContinueOnXoff[7..8],
    fOutX set_fOutX[8..9],
    fInX set_fInX[9..10],
    fErrorChar set_fErrorChar[10..11],
    fNull set_fNull[11..12],
    fRtsControl set_fRtsControl[12..14],
    fAbortOnError set_fAbortOnError[14..15],
    fDummy2 set_fDummy2[15..32],
]}

#[derive(Clone)]
pub(crate) struct Settings {
    pub dcb: DCB,
}

impl Settings {
    pub fn from_handle(handle: HANDLE) -> Result<Settings> {
        let mut dcb: DCB = unsafe { MaybeUninit::zeroed().assume_init() };
        dcb.DCBlength = std::mem::size_of::<DCB>() as u32;

        if unsafe { GetCommState(handle, &mut dcb) } != 0 {
            Ok(Settings { dcb })
        } else {
            Err(super::error::last_os_error())
        }
    }

    /// Initialize the DCB struct
    /// Set all values that won't be affected by `SerialPortBuilder` options.
    pub fn init(&mut self) {
        // dcb.DCBlength
        // dcb.BaudRate
        // dcb.BitFields
        // dcb.wReserved
        // dcb.XonLim
        // dcb.XoffLim
        // dcb.ByteSize
        // dcb.Parity
        // dcb.StopBits
        self.dcb.XonChar = 17;
        self.dcb.XoffChar = 19;
        self.dcb.ErrorChar = 0;
        self.dcb.EofChar = 26;
        // dcb.EvtChar
        // always true for communications resources
        self.set_fBinary(1 as u32);
        // dcb.set_fParity()
        // dcb.set_fOutxCtsFlow()
        // serialport-rs doesn't support toggling DSR: so disable fOutxDsrFlow
        self.set_fOutxDsrFlow(0 as u32);
        self.set_fDtrControl(DTR_CONTROL_DISABLE);
        // disable because fOutxDsrFlow is disabled as well
        self.set_fDsrSensitivity(0 as u32);
        // dcb.set_fTXContinueOnXoff()
        // dcb.set_fOutX()
        // dcb.set_fInX()
        self.set_fErrorChar(0 as u32);
        // fNull: when set to TRUE null bytes are discarded when received.
        // null bytes won't be discarded by serialport-rs
        self.set_fNull(0 as u32);
        // dcb.set_fRtsControl()
        // serialport-rs does not handle the fAbortOnError behaviour, so we must make sure it's not enabled
        self.set_fAbortOnError(0 as u32);
    }

    pub fn set_baud_rate(&mut self, baud_rate: u32) {
        self.dcb.BaudRate = baud_rate as u32;
    }

    pub fn set_data_bits(&mut self, data_bits: DataBits) {
        self.dcb.ByteSize = match data_bits {
            DataBits::Five => 5,
            DataBits::Six => 6,
            DataBits::Seven => 7,
            DataBits::Eight => 8,
        };
    }

    pub fn set_parity(&mut self, parity: Parity) {
        self.dcb.Parity = match parity {
            Parity::None => NOPARITY,
            Parity::Odd => ODDPARITY,
            Parity::Even => EVENPARITY,
        };

        self.set_fParity(if parity == Parity::None { 0 } else { 1 } as u32);
    }

    pub fn set_stop_bits(&mut self, stop_bits: StopBits) {
        self.dcb.StopBits = match stop_bits {
            StopBits::One => ONESTOPBIT,
            StopBits::Two => TWOSTOPBITS,
        };
    }

    pub fn set_flow_control(&mut self, flow_control: FlowControl) {
        match flow_control {
            FlowControl::None => {
                self.set_fOutxCtsFlow(0);
                self.set_fRtsControl(0);
                self.set_fOutX(0);
                self.set_fInX(0);
            }
            FlowControl::Software => {
                self.set_fOutxCtsFlow(0);
                self.set_fRtsControl(0);
                self.set_fOutX(1);
                self.set_fInX(1);
            }
            FlowControl::Hardware => {
                self.set_fOutxCtsFlow(1);
                self.set_fRtsControl(1);
                self.set_fOutX(0);
                self.set_fInX(0);
            }
        }
    }
}

pub(crate) fn set_dcb(handle: HANDLE, mut dcb: DCB) -> Result<()> {
    if unsafe { SetCommState(handle, &mut dcb as *mut _) != 0 } {
        Ok(())
    } else {
        Err(super::error::last_os_error())
    }
}

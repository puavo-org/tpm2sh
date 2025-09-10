// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::device::TpmDeviceError;
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    sync::{Arc, Condvar, Mutex},
};
use tpm2_protocol::constant::TPM_MAX_COMMAND_SIZE;

/// A trait for a transport layer capable of sending and receiving full TPM commands.
pub trait Transport: Send + std::fmt::Debug {
    /// Sends a complete command buffer to the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `TpmDeviceError` on I/O failure.
    fn send(&mut self, command_bytes: &[u8]) -> Result<(), TpmDeviceError>;

    /// Receives a complete response buffer from the TPM.
    ///
    /// This method is responsible for handling TPM response framing, i.e., reading
    /// the header to determine the full message size and then reading the
    /// remainder of the message.
    ///
    /// # Errors
    ///
    /// Returns a `TpmDeviceError` on I/O failure or if the response is malformed.
    fn receive(&mut self) -> Result<Vec<u8>, TpmDeviceError>;
}

/// A transport implementation that wraps a `std::fs::File`.
#[derive(Debug)]
pub struct FileTransport(pub File);

impl Transport for FileTransport {
    fn send(&mut self, command_bytes: &[u8]) -> Result<(), TpmDeviceError> {
        self.0.write_all(command_bytes)?;
        self.0.flush()?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, TpmDeviceError> {
        let mut header = [0u8; 10];
        self.0.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            // This is unreachable with a 10-byte read, but good for safety.
            return Err(TpmDeviceError::ResponseUnderflow);
        };

        let size = u32::from_be_bytes(size_bytes) as usize;
        if size < header.len() {
            return Err(TpmDeviceError::ResponseUnderflow);
        }
        if size > TPM_MAX_COMMAND_SIZE {
            return Err(TpmDeviceError::ResponseOverflow);
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.0.read_exact(&mut resp_buf[header.len()..])?;
        Ok(resp_buf)
    }
}

#[derive(Debug)]
pub struct EndpointState {
    pub buffer: VecDeque<u8>,
    pub writer_dropped: bool,
}

#[derive(Debug)]
pub struct EndpointGuard {
    pub state: Mutex<EndpointState>,
    pub cvar: Condvar,
}

#[derive(Debug)]
pub struct Endpoint(pub Arc<EndpointGuard>);

/// An in-memory pipe transport for testing and simulation.
#[derive(Debug)]
pub struct PipeTransport(pub Endpoint, pub Endpoint);

impl PipeTransport {
    #[must_use]
    pub fn new() -> Self {
        let from_server = Arc::new(EndpointGuard {
            state: Mutex::new(EndpointState {
                buffer: VecDeque::new(),
                writer_dropped: false,
            }),
            cvar: Condvar::new(),
        });
        let from_client = Arc::new(EndpointGuard {
            state: Mutex::new(EndpointState {
                buffer: VecDeque::new(),
                writer_dropped: false,
            }),
            cvar: Condvar::new(),
        });

        PipeTransport(Endpoint(from_client), Endpoint(from_server))
    }
}

impl Default for PipeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for Endpoint {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.0.state.lock().unwrap();
        while !state.writer_dropped && state.buffer.is_empty() {
            state = self.0.cvar.wait(state).unwrap();
        }

        if state.writer_dropped && state.buffer.is_empty() {
            return Ok(0);
        }

        let bytes_to_read = buf.len().min(state.buffer.len());
        for (i, byte) in state.buffer.drain(..bytes_to_read).enumerate() {
            buf[i] = byte;
        }
        Ok(bytes_to_read)
    }
}

impl Write for Endpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.0.state.lock().unwrap();
        if state.writer_dropped {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pipe reader dropped",
            ));
        }
        state.buffer.extend(buf);
        self.0.cvar.notify_one();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.writer_dropped = true;
        self.0.cvar.notify_all();
    }
}

impl Read for PipeTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for PipeTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.1.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

impl Transport for PipeTransport {
    fn send(&mut self, command_bytes: &[u8]) -> Result<(), TpmDeviceError> {
        self.write_all(command_bytes)?;
        self.flush()?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, TpmDeviceError> {
        let mut header = [0u8; 10];
        self.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            return Err(TpmDeviceError::ResponseUnderflow);
        };

        let size = u32::from_be_bytes(size_bytes) as usize;
        if size < header.len() {
            return Err(TpmDeviceError::ResponseUnderflow);
        }
        if size > TPM_MAX_COMMAND_SIZE {
            return Err(TpmDeviceError::ResponseOverflow);
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.read_exact(&mut resp_buf[header.len()..])?;
        Ok(resp_buf)
    }
}

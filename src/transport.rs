// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{Arc, Condvar, Mutex},
};

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

#[derive(Debug)]
pub struct Transport(pub Endpoint, pub Endpoint);

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

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.1.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

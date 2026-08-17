#![allow(dead_code)]
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum CommandType {
    Gpg,
    Ssh,
}

#[derive(Debug)]
pub struct RelayHeader {
    pub cmd: CommandType,
    pub args: Vec<String>,
    pub envs: Vec<(String, String)>,
}

pub enum Frame {
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

fn write_u32<W: Write>(w: &mut W, val: u32) -> io::Result<()> {
    w.write_all(&val.to_be_bytes())
}

fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn write_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    write_u32(w, bytes.len() as u32)?;
    w.write_all(bytes)
}

const MAX_BYTES_LEN: usize = 16 * 1024 * 1024; // 16 MB
const MAX_HEADER_COUNT: usize = 256;

fn read_bytes<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    if len > MAX_BYTES_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Payload length exceeds limit",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    write_bytes(w, s.as_bytes())
}

fn read_string<R: Read>(r: &mut R) -> io::Result<String> {
    let bytes = read_bytes(r)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

impl RelayHeader {
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self.cmd {
            CommandType::Gpg => write_u32(w, 1)?,
            CommandType::Ssh => write_u32(w, 2)?,
        }
        write_u32(w, self.args.len() as u32)?;
        for arg in &self.args {
            write_string(w, arg)?;
        }
        write_u32(w, self.envs.len() as u32)?;
        for (k, v) in &self.envs {
            write_string(w, k)?;
            write_string(w, v)?;
        }
        Ok(())
    }

    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let cmd_val = read_u32(r)?;
        let cmd = match cmd_val {
            1 => CommandType::Gpg,
            2 => CommandType::Ssh,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unknown command type",
                ))
            }
        };
        let arg_count = read_u32(r)? as usize;
        if arg_count > MAX_HEADER_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too many arguments",
            ));
        }
        let mut args = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            args.push(read_string(r)?);
        }
        let env_count = read_u32(r)? as usize;
        if env_count > MAX_HEADER_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too many environment variables",
            ));
        }
        let mut envs = Vec::with_capacity(env_count);
        for _ in 0..env_count {
            envs.push((read_string(r)?, read_string(r)?));
        }
        Ok(Self { cmd, args, envs })
    }
}

pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> io::Result<()> {
    match frame {
        Frame::Stdin(data) => {
            w.write_all(&[1])?;
            write_bytes(w, data)?;
        }
        Frame::Stdout(data) => {
            w.write_all(&[2])?;
            write_bytes(w, data)?;
        }
        Frame::Stderr(data) => {
            w.write_all(&[3])?;
            write_bytes(w, data)?;
        }
        Frame::Exit(code) => {
            w.write_all(&[4])?;
            write_u32(w, *code as u32)?;
        }
    }
    w.flush()
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut typ = [0u8; 1];
    r.read_exact(&mut typ)?;
    match typ[0] {
        1 => Ok(Frame::Stdin(read_bytes(r)?)),
        2 => Ok(Frame::Stdout(read_bytes(r)?)),
        3 => Ok(Frame::Stderr(read_bytes(r)?)),
        4 => Ok(Frame::Exit(read_u32(r)? as i32)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unknown frame type",
        )),
    }
}

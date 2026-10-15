//! Static Node-API admission, never executes a supplied addon during inspection.
use super::{error, read};
use crate::distribution::Result;
use glue_format::DiagnosticCode;
use std::path::Path;
fn bad(message: impl Into<String>) -> glue_format::Diagnostic {
    error(DiagnosticCode::UnsupportedCapability, message)
}
struct Bytes<'a>(&'a [u8]);
impl<'a> Bytes<'a> {
    fn range(&self, o: usize, n: usize) -> Result<&'a [u8]> {
        self.0
            .get(
                o..o.checked_add(n)
                    .ok_or_else(|| bad("addon offset overflow"))?,
            )
            .ok_or_else(|| bad("addon metadata outside image"))
    }
    fn u16(&self, o: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.range(o, 2)?.try_into().unwrap()))
    }
    fn u32(&self, o: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.range(o, 4)?.try_into().unwrap()))
    }
    fn u64(&self, o: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.range(o, 8)?.try_into().unwrap()))
    }
    fn name(&self, o: usize, end: usize) -> Result<String> {
        let bytes = self.range(
            o,
            end.checked_sub(o)
                .ok_or_else(|| bad("invalid addon string range"))?,
        )?;
        let n = bytes
            .iter()
            .take(4097)
            .position(|c| *c == 0)
            .ok_or_else(|| bad("addon symbol string exceeds bound"))?;
        String::from_utf8(bytes[..n].to_vec()).map_err(|_| bad("non-UTF8 addon symbol"))
    }
}
#[derive(Default)]
struct Symbols {
    registration: bool,
    getter: Option<Vec<u8>>,
    legacy: bool,
}
impl Symbols {
    fn note(&mut self, name: &str, defined: bool, body: Option<&[u8]>) {
        if defined && name == "napi_register_module_v1" {
            self.registration = true;
        }
        if defined && name == "node_api_module_get_api_version_v1" {
            self.getter = body.map(|b| b.to_vec());
        }
        if name == "node_module_register"
            || name.starts_with("node_register_module_v")
            || name.starts_with("_ZN2v8")
            || name.starts_with("_ZN4node")
        {
            self.legacy = true;
        }
    }
}
fn slice<'a>(bytes: &'a [u8], target: &str) -> Result<&'a [u8]> {
    if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        let b = Bytes(bytes);
        let wide = bytes[3] == 0xbf;
        let count = u32::from_be_bytes(b.range(4, 4)?.try_into().unwrap()) as usize;
        if count > 64 {
            return Err(bad("too many addon Mach-O slices"));
        }
        let cpu = if target.starts_with("aarch64") {
            0x0100000c
        } else {
            0x01000007
        };
        for i in 0..count {
            let p = 8 + i * if wide { 32 } else { 20 };
            if u32::from_be_bytes(b.range(p, 4)?.try_into().unwrap()) == cpu {
                let (o, n) = if wide {
                    (
                        u64::from_be_bytes(b.range(p + 8, 8)?.try_into().unwrap()),
                        u64::from_be_bytes(b.range(p + 16, 8)?.try_into().unwrap()),
                    )
                } else {
                    (
                        u32::from_be_bytes(b.range(p + 8, 4)?.try_into().unwrap()) as u64,
                        u32::from_be_bytes(b.range(p + 12, 4)?.try_into().unwrap()) as u64,
                    )
                };
                return b.range(
                    usize::try_from(o).map_err(|_| bad("addon slice offset"))?,
                    usize::try_from(n).map_err(|_| bad("addon slice size"))?,
                );
            }
        }
        return Err(bad("addon has no selected Mach-O slice"));
    }
    Ok(bytes)
}
fn elf(bytes: &[u8]) -> Result<Symbols> {
    let b = Bytes(bytes);
    if b.range(0, 6)? != b"\x7fELF\x02\x01" {
        return Err(bad("Node addon must be little-endian ELF64"));
    }
    let shoff = b.u64(40)? as usize;
    let shsize = b.u16(58)? as usize;
    let count = b.u16(60)? as usize;
    if shsize != 64 || count == 0 {
        return Err(bad("Node addon needs bounded ELF section/symbol metadata"));
    }
    b.range(shoff, count * shsize)?;
    let mut result = Symbols::default();
    for i in 0..count {
        let p = shoff + i * 64;
        if b.u32(p + 4)? != 11 {
            continue;
        }
        let offset = b.u64(p + 24)? as usize;
        let size = b.u64(p + 32)? as usize;
        let link = b.u32(p + 40)? as usize;
        if link >= count || b.u64(p + 56)? != 24 || size / 24 > 1_000_000 || size % 24 != 0 {
            return Err(bad("invalid addon dynamic symbols"));
        }
        let strp = shoff + link * 64;
        let strings = b.u64(strp + 24)? as usize;
        let stringsize = b.u64(strp + 32)? as usize;
        b.range(strings, stringsize)?;
        b.range(offset, size)?;
        for sym in (offset..offset + size).step_by(24) {
            let name = b.name(strings + b.u32(sym)? as usize, strings + stringsize)?;
            let section = b.u16(sym + 6)? as usize;
            let binding = b.range(sym + 4, 1)?[0] >> 4;
            let visibility = b.range(sym + 5, 1)?[0] & 3;
            let defined = section > 0
                && section < count
                && [1, 2].contains(&binding)
                && [0, 3].contains(&visibility);
            let body = if defined && name == "node_api_module_get_api_version_v1" {
                let p = shoff + section * 64;
                let address = b.u64(p + 16)?;
                let value = b.u64(sym + 8)?;
                let len = b.u64(p + 32)?;
                let delta = value
                    .checked_sub(address)
                    .filter(|v| *v < len)
                    .ok_or_else(|| bad("addon API getter outside section"))?;
                Some(
                    b.range(
                        b.u64(p + 24)?
                            .checked_add(delta)
                            .ok_or_else(|| bad("addon getter offset overflow"))?
                            as usize,
                        (len - delta).min(64) as usize,
                    )?,
                )
            } else {
                None
            };
            result.note(&name, defined, body);
        }
    }
    Ok(result)
}
fn macho(bytes: &[u8]) -> Result<Symbols> {
    let b = Bytes(bytes);
    if b.u32(0)? != 0xfeedfacf {
        return Err(bad("Node addon must be little-endian Mach-O64"));
    }
    let count = b.u32(16)? as usize;
    let commands = b.u32(20)? as usize;
    if count > 65536 {
        return Err(bad("addon command count exceeds bound"));
    }
    b.range(32, commands)?;
    let mut sections = Vec::new();
    let mut symbols = None;
    let mut p = 32;
    for _ in 0..count {
        let command = b.u32(p)?;
        let size = b.u32(p + 4)? as usize;
        if size < 8 || p + size > 32 + commands {
            return Err(bad("invalid addon load command"));
        }
        if command == 2 {
            symbols = Some((
                b.u32(p + 8)? as usize,
                b.u32(p + 12)? as usize,
                b.u32(p + 16)? as usize,
                b.u32(p + 20)? as usize,
            ));
        }
        if command == 0x19 {
            let n = b.u32(p + 64)? as usize;
            if n > 4096 || 72 + n * 80 > size {
                return Err(bad("invalid addon section table"));
            }
            for i in 0..n {
                let s = p + 72 + i * 80;
                sections.push((b.u64(s + 32)?, b.u64(s + 40)?, b.u32(s + 48)? as u64));
            }
        }
        p += size;
    }
    let (offset, count, strings, stringsize) =
        symbols.ok_or_else(|| bad("addon lacks static symbol metadata"))?;
    if count > 1_000_000 {
        return Err(bad("addon symbols exceed bound"));
    }
    b.range(offset, count * 16)?;
    b.range(strings, stringsize)?;
    let mut result = Symbols::default();
    for i in 0..count {
        let p = offset + i * 16;
        let name = b.name(strings + b.u32(p)? as usize, strings + stringsize)?;
        let name = name.strip_prefix('_').unwrap_or(&name);
        let ty = b.range(p + 4, 1)?[0];
        let section = b.range(p + 5, 1)?[0] as usize;
        let defined = ty & 0x0e == 0x0e && ty & 1 == 1 && section > 0;
        let body = if defined && name == "node_api_module_get_api_version_v1" {
            let (address, size, offset) = *sections
                .get(section - 1)
                .ok_or_else(|| bad("invalid addon getter section"))?;
            let delta = b
                .u64(p + 8)?
                .checked_sub(address)
                .filter(|v| *v < size)
                .ok_or_else(|| bad("addon getter outside section"))?;
            Some(
                b.range(
                    offset
                        .checked_add(delta)
                        .ok_or_else(|| bad("addon getter offset overflow"))?
                        as usize,
                    (size - delta).min(64) as usize,
                )?,
            )
        } else {
            None
        };
        result.note(name, defined, body);
    }
    Ok(result)
}
fn getter(body: &[u8], target: &str) -> Result<u32> {
    if target.starts_with("aarch64") {
        let mut pos = 0;
        for instruction in body.chunks_exact(4) {
            let word = u32::from_le_bytes(instruction.try_into().unwrap());
            if word == 0xd503245f || word == 0xd503201f {
                pos += 4;
            } else {
                break;
            }
        }
        let b = Bytes(body);
        let mov = b.u32(pos)?;
        if mov & 0xffe0001f == 0x52800000 && b.u32(pos + 4)? == 0xd65f03c0 {
            return Ok((mov >> 5) & 0xffff);
        }
    } else {
        let mut p = 0;
        if body.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
            p += 4;
        }
        let frame = body.get(p..p + 4) == Some(&[0x55, 0x48, 0x89, 0xe5]);
        if frame {
            p += 4;
        }
        if body.get(p) == Some(&0xb8) {
            let version = Bytes(body).u32(p + 1)?;
            p += 5;
            if frame && body.get(p) == Some(&0x5d) {
                p += 1;
            }
            if body.get(p) == Some(&0xc3) {
                return Ok(version);
            }
        }
    }
    Err(bad(
        "Node-API version getter is not a recognized constant-return function; minimum ABI cannot be established statically",
    ))
}
/// Supports standard Node-API registration and compiler-emitted constant version
/// getters. Unknown getter bodies fail rather than executing package code.
pub fn required_node_api(path: &Path, target: &str, available: u32) -> Result<u32> {
    let bytes = read(path, 512 * 1024 * 1024)?;
    let bytes = slice(&bytes, target)?;
    let binary = Bytes(bytes);
    let matching = if bytes.starts_with(b"\x7fELF") {
        binary.u16(18)?
            == if target.starts_with("aarch64") {
                183
            } else {
                62
            }
    } else {
        binary.u32(4)?
            == if target.starts_with("aarch64") {
                0x0100000c
            } else {
                0x01000007
            }
    };
    if !matching {
        return Err(error(
            DiagnosticCode::TargetMismatch,
            "Node addon architecture differs from selected runtime",
        ));
    }
    let symbols = if bytes.starts_with(b"\x7fELF") {
        elf(bytes)?
    } else {
        macho(bytes)?
    };
    if symbols.legacy || !symbols.registration {
        return Err(bad(
            "legacy V8/NAN or non-Node-API addon is unsupported; supply an existing Node-API binary",
        ));
    }
    let version = getter(
        symbols
            .getter
            .as_deref()
            .ok_or_else(|| bad("Node-API version getter absent; minimum ABI cannot be proven"))?,
        target,
    )?;
    if version == 0 || version > available {
        return Err(error(
            DiagnosticCode::RuntimeAbiMismatch,
            format!("addon requires Node-API {version}, selected runtime provides {available}"),
        ));
    }
    Ok(version)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_constant_getters() {
        assert_eq!(
            getter(
                &[0x00, 0x01, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
                "aarch64-apple-darwin"
            )
            .unwrap(),
            8
        );
        assert_eq!(
            getter(
                &[0x55, 0x48, 0x89, 0xe5, 0xb8, 8, 0, 0, 0, 0x5d, 0xc3],
                "x86_64-unknown-linux-gnu"
            )
            .unwrap(),
            8
        );
        assert!(getter(&[0; 16], "aarch64-apple-darwin").is_err());
    }
}

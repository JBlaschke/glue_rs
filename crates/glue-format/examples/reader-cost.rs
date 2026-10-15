//! Reproducible OS-level reader comparison; both modes retain archive validation.
use glue_format::{Archive, BufferedReader};
use std::{
    fs::File,
    io::{Read, Seek},
};

fn inspect<R: Read + Seek>(source: R) -> Result<(), Box<dyn std::error::Error>> {
    let archive = Archive::open(source)?;
    println!("validated {} resources", archive.entries().len());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().ok_or("expected plain|buffered ARCHIVE")?;
    let source = File::open(arguments.next().ok_or("expected archive path")?)?;
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    match mode.as_str() {
        "plain" => inspect(source),
        "buffered" => inspect(BufferedReader::new(source)),
        _ => Err("expected plain|buffered".into()),
    }
}

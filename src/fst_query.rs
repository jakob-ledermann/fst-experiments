use fst::{
    automaton::{AlwaysMatch, Str},
    Automaton, IntoStreamer, Map, Streamer,
};
use memmap::Mmap;
use std::fs::File;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mmap = unsafe { Mmap::map(&File::open("pwned-passwords.fst")?)? };
    let map = Map::new(mmap)?;

    for arg in std::env::args() {
        let query = Str::new(&arg).starts_with();
        let mut results = map.search(query).into_stream();
        while let Some((key, value)) = results.next() {
            println!(
                "{}: {:>20}",
                unsafe { std::str::from_utf8_unchecked(key) },
                value
            );
        }
    }

    Ok(())
}

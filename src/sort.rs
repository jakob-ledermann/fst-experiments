#![feature(slice_as_chunks)]
use std::{
    cmp::{Ordering, Reverse},
    io::{BufRead, BufReader, BufWriter, Lines, Read, Seek, Write},
    num::ParseIntError,
    path::Path,
    str::FromStr,
};

use tempfile::{NamedTempFile, TempPath};
use tracing::info;

fn main() {
    tracing_subscriber::fmt::init();

    let input_file = std::fs::File::open("pwned-passwords-sha1-ordered-by-count-v8.part.txt")
        .expect("Could not open input file.");

    let reader = BufReader::new(input_file);
    let tmp_dir = tempfile::tempdir_in("./temp").expect("Can not create temporary folder");

    let limit = 10 * 1024;

    info!("Splitting the original file into sorted runs");
    let mut runs = split_into_sorted_runs(reader, tmp_dir.path(), limit);

    let final_file = if runs.len() > 1 {
        info!("Merging {} files", runs.len());
        merge_runs(&runs, tmp_dir.path(), limit)
    } else {
        info!("Could merge completly in memory");
        runs.pop().expect("Should have at least one run")
    };

    let path = final_file
        .keep()
        .expect("Should be able to persist the final file");
    std::fs::copy(&path, "sorted-output.txt").expect(&format!(
        "Should have been able to copy the final file {} to the output",
        &path.display()
    ));
}

struct Entry {
    hash: [u32; 5], // 160 bits / 8 / 4 = 5
    count: u32,
}

impl FromStr for Entry {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_terminator(":").collect();
        let hash: Vec<u32> = parts[0]
            .as_bytes()
            .chunks_exact(8)
            .map(|x| {
                u32::from_str_radix(std::str::from_utf8(x).expect("Should be valid utf8"), 16)
                    .expect("Should be a valid hex string")
            })
            .collect();
        let count = u32::from_str_radix(parts[1], 10)?;
        let mut hash_array = [0u32; 5];

        hash_array.copy_from_slice(hash.as_slice());

        Ok(Self {
            hash: hash_array,
            count,
        })
    }
}

impl Entry {
    fn to_le_bytes(self) -> [u8; 6 * std::mem::size_of::<u32>()] {
        let mut buffer = [0u8; 6 * std::mem::size_of::<u32>()];
        self.hash
            .iter()
            .map(|x| x.to_le_bytes())
            .enumerate()
            .for_each(|(idx, x)| {
                buffer[idx * std::mem::size_of::<u32>()..(idx + 1) * std::mem::size_of::<u32>()]
                    .copy_from_slice(x.as_slice())
            });
        buffer[20..].copy_from_slice(self.count.to_le_bytes().as_slice());
        buffer
    }

    fn from_le_bytes(bytes: &[u8; 6 * std::mem::size_of::<u32>()]) -> Self {
        let vec: Vec<u32> = bytes
            .as_chunks::<{ std::mem::size_of::<u32>() }>()
            .0
            .iter()
            .map(|x| u32::from_le_bytes(*x))
            .collect();
        let mut hash = [0u32; 5];
        hash.copy_from_slice(&vec[0..5]);
        let count = vec[5];
        Self { hash, count }
    }
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

impl ToString for Entry {
    fn to_string(&self) -> String {
        let mut result = String::with_capacity(50);

        self.hash
            .iter()
            .for_each(|x| write!(&mut result as &mut dyn std::fmt::Write, "{:08X}", x).unwrap());
        write!(&mut result as &mut dyn std::fmt::Write, ":{}", self.count);

        result
    }
}

fn split_into_sorted_runs(
    source: impl BufRead + std::io::Seek,
    folder: &Path,
    limit: usize,
) -> Vec<TempPath> {
    let mut waiting_buffer = Vec::with_capacity(limit);
    let mut result = Vec::new();

    let iterator = source.lines();

    for line in iterator {
        let line = line.unwrap();
        let entry: Entry = line.parse().expect("Should be parsable");
        waiting_buffer.push(entry);

        if waiting_buffer.len() >= waiting_buffer.capacity() - 1 {
            let file = NamedTempFile::new_in(folder).unwrap();
            let mut old_file = BufWriter::new(file);
            waiting_buffer.sort_unstable();
            for element in waiting_buffer.drain(..) {
                old_file.write_all(&element.to_le_bytes()).unwrap();
            }
            old_file.flush().unwrap();
            result.push(old_file.into_inner().unwrap().into_temp_path());
        }
    }

    let file = NamedTempFile::new_in(folder).unwrap();
    let mut old_file = BufWriter::new(file);
    waiting_buffer.sort();
    for element in waiting_buffer.drain(..) {
        old_file.write_all(&element.to_le_bytes()).unwrap();
    }
    old_file.flush().unwrap();
    result.push(old_file.into_inner().unwrap().into_temp_path());
    result
}

struct KeyedCmp<TKey, TValue> {
    key: TKey,
    value: TValue,
}

impl<TKey: PartialEq, TValue> PartialEq for KeyedCmp<TKey, TValue> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<TKey: Eq, TValue> Eq for KeyedCmp<TKey, TValue> {}

impl<TKey: PartialOrd, TValue> PartialOrd for KeyedCmp<TKey, TValue> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.key.partial_cmp(&other.key)
    }
}

impl<TKey: Ord, TValue> Ord for KeyedCmp<TKey, TValue> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

struct Entries<T: Read> {
    reader: T,
}

impl<T: Read> Iterator for Entries<T> {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = [0u8; 6 * std::mem::size_of::<u32>()];
        match self.reader.read_exact(buffer.as_mut_slice()) {
            Ok(_) => Some(Entry::from_le_bytes(&buffer)),
            Err(_) => None,
        }
    }
}

fn merge_runs<T: AsRef<Path>>(sources: &[T], target_folder: &Path, limit: usize) -> TempPath {
    let elements_per_source = usize::max(limit / sources.len(), 1);
    info!(
        "Loading {} elements per file for merging",
        elements_per_source
    );

    let out_file_path = NamedTempFile::new_in(target_folder).expect("Could not create target file");

    let mut out_file = BufWriter::new(out_file_path);
    let mut readers: Vec<Entries<_>> = sources
        .iter()
        .map(|x| {
            let reader = std::fs::File::open(x).expect("Could not open source file");
            let reader = BufReader::new(reader);
            Entries { reader }
        })
        .collect();

    let mut heap = Vec::with_capacity(elements_per_source * sources.len());
    let mut element_counter: Vec<usize> = vec![0; sources.len()];

    for (index, lines) in readers.iter_mut().enumerate() {
        while let Some(entry) = lines.next() {
            heap.push(KeyedCmp {
                key: Reverse(entry),
                value: index,
            });

            element_counter[index] += 1;
            if element_counter[index] >= elements_per_source {
                break;
            }
        }
    }

    heap.sort();

    while let Some(content) = heap.pop() {
        let line = content.key.0;
        let source_index = content.value;

        out_file
            .write_all(line.to_string().as_bytes())
            .expect("should be able to write");
        out_file.write_all(b"\n").expect("should be able to write");

        element_counter[source_index] -= 1;

        if element_counter[source_index] == 0 {
            // Refill the buffer once the element_counter for one reaches zero
            tracing::debug!("refill the buffer");
            for (source_index, count) in element_counter
                .iter_mut()
                .enumerate()
                .filter(|(_, &mut count)| count < elements_per_source)
            {
                while let Some(entry) = readers[source_index].next() {
                    let new_element = KeyedCmp {
                        key: Reverse(entry),
                        value: source_index,
                    };
                    heap.push(new_element);
                    *count += 1;
                    if *count >= elements_per_source {
                        break;
                    }
                }
            }
            heap.sort();
            tracing::debug!("buffer filled and sorted");
        }
    }
    out_file
        .into_inner()
        .expect("Could not access the inner file")
        .into_temp_path()
}

#[test]
fn output_matches_gnu_sort() {
    const REQUIRED: &[u8] = include_bytes!("../gnu-sort.output");

    main();

    let reader = std::fs::File::open("sorted-output.txt").unwrap();
    let act_reader = BufReader::new(reader);
    let req_reader = BufReader::new(std::io::Cursor::new(REQUIRED));
    let mut act_lines = act_reader.lines();

    for (index, req_line) in req_reader.lines().enumerate() {
        let act_line = act_lines.next().unwrap().unwrap();
        let req_line = req_line.unwrap();
        assert_eq!(req_line, act_line, "The line {index} should be equal");
    }
}

use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    io::{BufRead, BufReader, BufWriter, Lines, Seek, Write},
    path::Path,
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

fn split_into_sorted_runs(source: impl BufRead + std::io::Seek, folder: &Path, limit: usize) -> Vec<TempPath> {
    let mut waiting_buffer = Vec::with_capacity(limit);
    let mut run_count = 1;
    let mut result = Vec::new();
    let out_file_path = NamedTempFile::new_in(folder).expect("Could not create run_file");
    let mut out_file = BufWriter::new(out_file_path);
    let mut last_written: Option<String> = None;
    let mut iterator = source.lines();
    let mut input_file_empty = false;

    for line in iterator {
        let line = line.unwrap();
        waiting_buffer.push(line);

        if waiting_buffer.len() >= waiting_buffer.capacity() - 1 {
            run_count += 1;
            let file = NamedTempFile::new_in(folder).unwrap();
            let mut old_file = std::mem::replace(&mut out_file, BufWriter::new(file));
            waiting_buffer.sort();
            for element in waiting_buffer.drain(..) {
                old_file.write_all(element.as_bytes()).unwrap();
                old_file.write_all(b"\n").unwrap();
            }
            old_file.flush().unwrap();
            result.push(old_file.into_inner().unwrap().into_temp_path());
        }
    }

    waiting_buffer.sort();
    for element in waiting_buffer {
        out_file.write_all(element.as_bytes()).unwrap();
        out_file.write_all(b"\n").unwrap();
    }
    out_file.flush().unwrap();

    result.push(
        out_file
            .into_inner()
            .expect("Could not unwrap BufWriter")
            .into_temp_path(),
    );
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

fn merge_runs<T: AsRef<Path>>(sources: &[T], target_folder: &Path, limit: usize) -> TempPath {
    let elements_per_source = usize::max(limit / sources.len(), 1);
    info!(
        "Loading {} elements per file for merging",
        elements_per_source
    );

    let out_file_path = NamedTempFile::new_in(target_folder).expect("Could not create target file");

    let mut out_file = BufWriter::new(out_file_path);
    let mut readers: Vec<Lines<_>> = sources
        .iter()
        .map(|x| {
            let reader = std::fs::File::open(x).expect("Could not open source file");
            let reader = BufReader::new(reader);
            reader.lines()
        })
        .collect();

    let mut heap = Vec::with_capacity(elements_per_source * sources.len());
    let mut element_counter: Vec<usize> = vec![0; sources.len()];

    for (index, lines) in readers.iter_mut().enumerate() {
        while let Some(Ok(line)) = lines.next() {
            heap.push(KeyedCmp {
                key: Reverse(line),
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
            .write_all(line.as_bytes())
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
                while let Some(Ok(line)) = readers[source_index].next() {
                    let new_element = KeyedCmp {
                        key: Reverse(line),
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
    out_file.into_inner().expect("Could not access the inner file").into_temp_path()
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

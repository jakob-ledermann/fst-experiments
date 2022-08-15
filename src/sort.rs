use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    io::{BufRead, BufReader, BufWriter, Lines, Seek, Write},
    path::Path,
};

use tempfile::NamedTempFile;
use tracing::info;

fn main() {
    tracing_subscriber::fmt::init();

    let input_file = std::fs::File::open("pwned-passwords-sha1-ordered-by-count-v8.txt")
        .expect("Could not open input file.");

    let reader = BufReader::new(input_file);
    let tmp_dir = tempfile::tempdir_in("./temp").expect("Can not create temporary folder");

    info!("Splitting the original file into sorted runs");
    let mut runs = split_into_sorted_runs(reader, tmp_dir.path());

    let final_file = if runs.len() > 1 {
        info!("Merging {} files", runs.len());
        merge_runs(&runs, tmp_dir.path())
    } else {
        info!("Could merge completly in memory");
        runs.pop().expect("Should have at least one run")
    };

    let (file, path) = final_file
        .keep()
        .expect("Should be able to persist the final file");
    drop(file);
    std::fs::copy(&path, path.parent().unwrap().join("sorted-output.txt")).expect(&format!(
        "Should have been able to copy the final file {} to the output",
        &path.display()
    ));
}

fn split_into_sorted_runs(
    source: impl BufRead + std::io::Seek,
    folder: &Path,
) -> Vec<NamedTempFile> {
    let mut buffer = BinaryHeap::with_capacity(4096 * 1024);
    let mut waiting_buffer = Vec::with_capacity(4096 * 1024);
    let mut run_count = 1;
    let mut result = Vec::new();
    let out_file_path = NamedTempFile::new_in(folder).expect("Could not create run_file");
    let mut out_file = BufWriter::new(out_file_path);
    let mut last_written: Option<String> = None;
    let mut iterator = source.lines();
    let mut input_file_empty = false;

    loop {
        while !input_file_empty && buffer.len() + waiting_buffer.len() < buffer.capacity() {
            if let Some(Ok(line)) = iterator.next() {
                if let Some(last_written) = last_written.take() {
                    match last_written.cmp(&line) {
                        Ordering::Less | Ordering::Equal => {
                            buffer.push(Reverse(line));
                        }
                        Ordering::Greater => {
                            waiting_buffer.push(line);
                        }
                    }
                } else {
                    buffer.push(Reverse(line));
                };
            } else {
                input_file_empty = true;
                info!(
                    "The input file has been read fully. {} entries in buffer",
                    buffer.len() + waiting_buffer.len()
                );
                break;
            }
        }

        if let Some(content) = buffer.pop() {
            out_file
                .write_all(content.0.as_bytes())
                .expect("Error writing into output_file");
            out_file
                .write_all(b"\n")
                .expect("Error writing into output_file");
            last_written = Some(content.0);
        } else if waiting_buffer.len() == waiting_buffer.capacity() || input_file_empty {
            info!("Run completed. {:?} remaining.", iterator.size_hint());
            // next run
            run_count += 1;
            let file = NamedTempFile::new_in(folder)
                .expect(&format!("Could not create file for run {}", run_count));
            let mut completed_file = std::mem::replace(&mut out_file, BufWriter::new(file));
            {
                completed_file
                    .flush()
                    .expect("Could not write contents to disk");
                completed_file
                    .rewind()
                    .expect("Could not reset file position");
                result.push(
                    completed_file
                        .into_inner()
                        .expect("Could not unwrap BufWriter"),
                );
            }

            buffer.extend(waiting_buffer.drain(..).map(Reverse));
            last_written = None;

            if buffer.is_empty() {
                break;
            }
        } else if waiting_buffer.is_empty() {
            info!("Finished processing the input");
            // waiting buffer is empty
            break;
        }
    }

    out_file.rewind().expect("Could not reset the output");
    result.push(out_file.into_inner().expect("Could not unwrap BufWriter"));
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

fn merge_runs<T: AsRef<Path>>(sources: &[T], target_folder: &Path) -> NamedTempFile {
    let out_file_path = NamedTempFile::new_in(target_folder).expect("Could not create target file");

    let mut out_file = out_file_path;
    let mut readers: Vec<Lines<_>> = sources
        .iter()
        .map(|x| {
            let reader = std::fs::File::open(x).expect("Could not open source file");
            let reader = BufReader::new(reader);
            reader.lines()
        })
        .collect();

    let mut heap = BinaryHeap::with_capacity(sources.len());

    for (index, lines) in readers.iter_mut().enumerate() {
        match lines.next() {
            Some(Ok(line)) => heap.push(KeyedCmp {
                key: Reverse(line),
                value: index,
            }),
            _ => {}
        }
    }

    loop {
        match heap.pop() {
            Some(content) => {
                let line = content.key.0;
                let source_index = content.value;

                out_file
                    .write_all(line.as_bytes())
                    .expect("should be able to write");
                out_file.write_all(b"\n").expect("should be able to write");

                match readers[source_index].next() {
                    Some(Ok(line)) => {
                        heap.push(KeyedCmp {
                            key: Reverse(line),
                            value: source_index,
                        });
                    }
                    _ => {}
                }
            }
            None => {
                break;
            }
        }
    }

    out_file
}

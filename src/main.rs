use std::io::{BufRead, BufReader};
fn main() {
    let sorted_input =
        std::fs::File::open("sorted-output.txt").expect("Should contain exactly one file");
    let file =
        std::fs::File::create("pwned-passwords.fst").expect("Can't create pwned-passwords.fst");
    let mut fst = fst::MapBuilder::new(file).expect("Could not create FST");
    let reader = BufReader::new(sorted_input);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                let comps: Vec<_> = line.split(":").collect();
                let hash = comps[0];
                let value: u64 = comps[1].parse().expect("Could not parse the value");
                fst.insert(hash, value).unwrap();
            }
            Err(err) => {
                eprintln!("Error reading the file {}", err);
            }
        }
    }
}

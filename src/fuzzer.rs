use std::{fs, io};
use std::fs::File;
use std::process::{Command, Stdio};
use std::io::{Read, Write, Error};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashSet;
use rand::Rng;

use crate::Coverage;
use crate::c_api::{shmget, shmat};

const BIN_PATH: &str = "targets/exif_coverage";
const ASAN_PATH: &str = "targets/exifsan";
const CORPUS_DIR: &str = "corpus/";
const TARGET_JPG_PATH: &str = "targets/mutated.jpg";
const CRASH_DIR: &str = "crashes/";

const COVERAGE_STRUCT_SIZE: usize = 0x68;

#[derive(Clone, Debug)]
pub struct Fuzzer {
    // Path to Binary
    bin_path: String,

    // Path to Asan Binary (for reporting crashes)
    asan_path: String,

    // Path to corpus
    corpus_dir: String,
    
    // Path to target jpg file
    target_jpg_path: String,

    // Command-line arguments
    cmdline_args: Vec<String>,

    // Path to crash directory
    crash_dir: String,

    // Initial corpus
    corpus: Vec<Vec<u8>>,

    // Initial file data
    file_data: Vec<u8>
}


impl Fuzzer {

    pub fn new() -> Self {
        Fuzzer {
            // Path to binary
            bin_path: BIN_PATH.to_string(),
            // Asan bin path
            asan_path: ASAN_PATH.to_string(),
            // Path of source file
            corpus_dir: CORPUS_DIR.to_string(),
            // Path of target jpg
            target_jpg_path: TARGET_JPG_PATH.to_string(),
            // Commandline args for binary
            cmdline_args: vec![TARGET_JPG_PATH.to_string()],
            // Path to store crash files
            crash_dir: CRASH_DIR.to_string(),

            corpus: vec![Vec::new()],

            file_data: Vec::new()
        }
    }

    pub fn harness(&mut self, total_coverage_ref: Arc<RwLock<Coverage>>, crash_count_ref: Arc<Mutex<u32>>, corpus_ref: Arc<RwLock<Vec<Vec<u8>>>>) {

        // Pick file from corpus to mutate
        self.pick_from_corpus();

        // Mutate file data
        self.mutator();

        // Update mutated file with mutated data
        self.update_file();

        // Run file
        let mut child = Command::new(&self.bin_path)
            .args(self.cmdline_args.clone())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to execute!");
        
        let pid: u32 = 1234 + child.id() % 0x100;
        let status = child.wait().expect("Couldn't execute!");

        self.coverage_handler(total_coverage_ref, corpus_ref, pid);

        match status.code() {
            // Some(code) => println!("Exited with status code: {}", code),
            Some(_code) => (),
            None => {
                // println!("Got a crash!");
                self.report_crash().expect("Couldn't report the crash!");
                *crash_count_ref.lock().unwrap() += 1;
            },
        }
    }

    pub fn init_corpus(&mut self, corpus_ref: Arc<RwLock<Vec<Vec<u8>>>>) {
        // Update local corpus
        let corpus = corpus_ref.read().unwrap();
        self.corpus = corpus.clone();
    }

    //* Update total_coverage for files that we already have in our corpus 
    //* (dont create duplicate files in corpus)

    pub fn init_coverage(&mut self, total_coverage: &mut Coverage) -> Vec<Vec<u8>> {

        let entries = fs::read_dir(self.corpus_dir.clone()).unwrap()
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, io::Error>>().unwrap();

        println!("[*] Initializing coverage!");

        let mut corpus_set = HashSet::new();

        for existing_file in entries {
            let path: PathBuf = existing_file.clone();

            let mut file = match File::open(&path) {
                Err(err) => panic!("File {:?} could not be opened: {}", path, err),
                Ok(file) => file,
            };

            let metadata = match fs::metadata(&path) {
                Err(err) => panic!("Unable to read metadata from file {:?}: {}", path, err),
                Ok(metadata) => metadata,
            };

            let mut file_data = vec![0; metadata.len() as usize];

            file.read(&mut file_data).unwrap();

            // println!("Adding file {:?} to corpus -> length {}!", path, file_data.len());

            // Write data to target file
            let path_new = Path::new(&self.target_jpg_path);
            let mut file = match File::create(&path_new) {
                Err(err) => panic!("File {} could not be created: {}", self.target_jpg_path, err),
                Ok(file) => file,
            };
            match file.write_all(&file_data) {
                Err(err) => panic!("File {} could not be written: {}", self.target_jpg_path, err),
                _ => (),
            }

            // Run file
            let mut child = Command::new(&self.bin_path)
                .args(self.cmdline_args.clone())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to execute!");

            let pid: u32 = 1234 + child.id() % 0x100;

            child.wait().expect("Couldn't execute!");

            // println!("PID: {}", pid);

            // Update covered blocks without saving to corpus
            let obtained_coverage = self.get_coverage(pid);

            total_coverage.update_coverage(obtained_coverage);

            // Add file data to local corpus
            if file_data.len() != 0 {
                corpus_set.insert(file_data);
            }
        }

        let corpus = Vec::from_iter(corpus_set);

        // Print debug data -> total coverage so far
        let coverage: (u32, u32) = total_coverage.get_total_coverage();
        println!("[!] Initialized coverage -> {}/{} blocks", coverage.0, coverage.1);

        println!("Corpus size: {}", corpus.len());

        corpus

    }

    //* Mutate the input
    fn mutator(&mut self) {

        // Number of times to mutate input
        let mutation_count: usize = self.gen_rand() % 5 + 1;

        for _ in 0..mutation_count {
            let rand_num: usize = self.gen_rand() % 3;

            match rand_num {
                0 => self.bit_flipper(),
                1 => self.change_byte(),
                2 => self.insert_magic_numbers(),
                _ => (),
            };
        }

    }

    //* Find if the input produced any previously unseen coverage
    fn coverage_handler(&mut self, total_coverage_ref: Arc<RwLock<Coverage>>, corpus_ref: Arc<RwLock<Vec<Vec<u8>>>>, pid: u32) {

        let obtained_coverage: Coverage = self.get_coverage(pid);

        let new_coverage: bool;
        let mut coverage_copy: Coverage;

        // Scope out borrow
        {
            let total_coverage = total_coverage_ref.read().unwrap();
            coverage_copy = total_coverage.clone();
        }

        new_coverage = coverage_copy.update_coverage(obtained_coverage);

        if new_coverage {
            println!("Got new coverage!");
            println!("New coverage: {}/{} blocks!", coverage_copy.coverage_count, coverage_copy.total_blocks);

            // Update global coverage
            {
                let mut total_coverage = total_coverage_ref.write().unwrap();
                total_coverage.update_coverage(obtained_coverage);
            }

            // Update global corpus
            {
                let mut corpus = corpus_ref.write().unwrap();
                corpus.push(self.file_data.clone());
            }

            // Save new coverage to corpus
            self.save_to_corpus();

            // Print debug data -> total coverage so far
            // let coverage: (i32, i32) = total_coverage.get_total_coverage();
            // println!("[!] Updated coverage -> {}/{} blocks", coverage.0, coverage.1);
        }
    }

    //* Use shared memory to get coverage
    fn get_coverage(&self, pid: u32) -> Coverage {

        unsafe {
            let key: u32 = pid;

            let id = shmget(key, COVERAGE_STRUCT_SIZE, 0o666);
            assert!(id >= 0, "Something went wrong!");

            let shmem: *mut Coverage;
            shmem = shmat(id, core::ptr::null_mut(), 0);

            let covered: Coverage = *shmem;
            
            // println!("{:?}", covered.blocks);

            covered
        }
    }

    //* Pick either a random file from corpus or previous file and read it
    fn pick_from_corpus(&mut self) {

        let selected_idx: usize = self.gen_rand() % self.corpus.len();

        self.file_data = self.corpus[selected_idx].clone();

        assert!(self.file_data.len() != 0, "Issue with opened file!");
    }

    //* Save input with new coverage to corpus
    fn save_to_corpus(&mut self) {

        let mut path: PathBuf = PathBuf::from(self.corpus_dir.clone());
        path.push(&self.gen_random_filename());
        path.set_extension("jpg");

        while path.exists() {
            path = PathBuf::from(self.corpus_dir.clone());
            path.push(&self.gen_random_filename());
            path.set_extension("jpg");
        }

        let mut file = match File::create(&path) {
            Err(err) => panic!("File {:?} could not be created: {}", path, err),
            Ok(file) => file,
        };

        match file.write_all(&self.file_data) {
            Err(err) => panic!("File {:?} could not be written: {}", path, err),
            _ => (),
        };

        self.corpus.push(self.file_data.clone());

    }

    fn bit_flipper(&mut self) { 
        
        let byte_idx: usize = self.gen_rand() % self.file_data.len();
        let bit_idx: usize = self.gen_rand() % 8;

        self.file_data[byte_idx] ^= 1 << bit_idx;

        // println!("Bit flipped -> {}:{}", byte_idx, bit_idx);
    }

    fn change_byte(&mut self) {

        let byte_idx: usize = self.gen_rand() % self.file_data.len();
        let new_byte: u8 = self.gen_rand() as u8;

        self.file_data[byte_idx] = new_byte;

        // println!("Byte changed -> {}:{}", byte_idx, new_byte);
    }

    fn insert_magic_numbers(&mut self) {

        let interesting_numbers: Vec<(usize, u32)> = vec![
            (1, 0x0),
            (1, 0x7f),
            (1, 0x80),
            (1, 0xff),
            (2, 0x0),
            (2, 0x7fff),
            (2, 0x8000),
            (2, 0xffff),
            (4, 0x0),
            (4, 0x7fffffff),
            (4, 0x80000000),
            (4, 0xffffffff),
        ];

        let interesting_idx: usize = self.gen_rand() % interesting_numbers.len();
        let byte_len: usize = interesting_numbers[interesting_idx].0;

        let byte_idx: usize = self.gen_rand() % (self.file_data.len() - byte_len);

        for i in 0..byte_len {
            self.file_data[byte_idx + i] = (interesting_numbers[interesting_idx].1 >> i*8) as u8;
        }

        // println!("Bytes changed -> {}:{}", byte_idx, interesting_numbers[interesting_idx].1);
    }

    fn update_file(&self) {

        let path = Path::new(&self.target_jpg_path);

        let mut file = match File::create(&path) {
            Err(err) => panic!("File {} could not be created: {}", self.target_jpg_path, err),
            Ok(file) => file,
        };

        match file.write_all(&self.file_data) {
            Err(err) => panic!("File {} could not be written: {}", self.target_jpg_path, err),
            _ => (),
        }
    }

    //* Save file that produces a crash
    fn report_crash(&self) -> Result<(), Error> {

        let mut path: PathBuf = PathBuf::from(self.crash_dir.clone());
        path.push(&self.gen_random_filename());
        path.set_extension("jpg");

        while path.exists() {
            path = PathBuf::from(self.crash_dir.clone());
            path.push(&self.gen_random_filename());
            path.set_extension("jpg");
        }

        let mut file = match File::create(&path) {
            Err(err) => panic!("File {:?} could not be created: {}", path, err),
            Ok(file) => file,
        };

        match file.write_all(&self.file_data) {
            Err(err) => panic!("File {:?} could not be written: {}", path, err),
            _ => (),
        };

        path.set_extension("dmp");

        let output = Command::new(&self.asan_path)
            .args(self.cmdline_args.clone())
            .stdout(Stdio::null())
            .output()
            .expect("Failed to generate dump!");

        let crash_data: Vec<u8> = output.stderr;

        file = match File::create(&path) {
            Err(err) => panic!("File {:?} could not be created: {}", path, err),
            Ok(file) => file,
        };

        match file.write_all(&crash_data) {
            Err(err) => panic!("File {:?} could not be written: {}", path, err),
            _ => (),
        }

        // println!("Crash dump saved to {}", crash_dump_loc);

        Ok(())
    }

    //* Generates a new random filename
    fn gen_random_filename(&self) -> String {
        
        let mut bytes = Vec::new();
        let mut alpha = Vec::new();
        alpha.extend_from_slice(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

        for _ in 0..10 {
            bytes.push(alpha[self.gen_rand() % (alpha.len() as usize)]);
        }

        String::from_utf8(bytes).unwrap()
    }

    fn gen_rand(&self) -> usize {
        
        let randval: usize = rand::thread_rng().gen();
        randval
    }

}
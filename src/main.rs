mod fuzzer;
mod coverage;
mod c_api;

use std::process::Command;
use std::io::Error;
use std::time::SystemTime;
use std::thread;
use std::sync::{Arc, Mutex, RwLock};

use fuzzer::Fuzzer;
use coverage::Coverage;

fn display_stats(time_millis: u128, total_coverage_ref: Arc<RwLock<Coverage>>, crash_count_ref: Arc<Mutex<u32>>, 
    iterations: u32, max_iter: u32, thread_count: u32) {

    let crash_count = crash_count_ref.lock().unwrap();
    let coverage = total_coverage_ref.read().unwrap();

    let completed: u32 = iterations / thread_count;
    let incomplete: u32 = (max_iter - iterations) / thread_count;

    Command::new("clear").status().unwrap();

    print!("Progress: [");

    for _ in 0..completed {
        print!("+");
    }
    
    for _ in 0..incomplete {
        print!("-");
    }

    println!("]");

    println!("[*] After {} iterations:", iterations);
    println!("[*] Time elapsed: {:.2} seconds", (time_millis as f64)/100.0);
    println!("[*] Current coverage: {}/{}", coverage.coverage_count, coverage.total_blocks);
    println!("[*] Crashes obtained: {}", *crash_count);
    println!("[*] Speed -> {:.2} iter/sec", ((iterations as f64) / ((time_millis as f64)/100.0)) as f64);

}


fn thread_handler(total_coverage_ref: Arc<RwLock<Coverage>>, crash_count_ref: Arc<Mutex<u32>>, 
    corpus_ref: Arc<RwLock<Vec<Vec<u8>>>>, execs_per_thread: u32, thread_no: u32) {

    let mut fuzz = Fuzzer::new();

    fuzz.init_corpus(corpus_ref.clone());

    for i in 0..execs_per_thread {
        fuzz.harness(total_coverage_ref.clone(), crash_count_ref.clone(), corpus_ref.clone());
    }
}

fn runner(iter_count: u32, thread_count: u32, execs_per_thread: u32) {

    let crash_count = Arc::new(Mutex::new(0));

    let mut init_coverage = Coverage::new();

    let mut fuzz = Fuzzer::new();
    
    // Initialize coverage and save corpus into memory
    let corpus = Arc::new(RwLock::new(fuzz.init_coverage(&mut init_coverage)));

    let total_coverage = Arc::new(RwLock::new(init_coverage));

    let start_time = SystemTime::now();

    for iter_id in 0..iter_count {
        let mut threads = Vec::new();
        
        for thread_no in 1..=thread_count {

            let crash_count_ref = crash_count.clone();
            let total_coverage_ref = total_coverage.clone();
            let corpus_ref = corpus.clone();

            threads.push(thread::spawn(move ||
                thread_handler(total_coverage_ref, crash_count_ref, corpus_ref, execs_per_thread, thread_no)
            ));
        }
        
        for t in threads {
            t.join().unwrap();
        }
        
        let time_elapsed = start_time.elapsed().unwrap().as_millis();

        display_stats(time_elapsed, total_coverage.clone(), 
            crash_count.clone(), (iter_id + 1) * thread_count * execs_per_thread, 
            iter_count*thread_count*execs_per_thread, thread_count * execs_per_thread);
    }
    
}


fn main() -> Result<(), Error> {

    runner(10, 30, 100);

    Ok(())
}
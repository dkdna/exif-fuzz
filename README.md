# exif-fuzz
A simple coverage-guided fuzzer to fuzz exif data in images, written in Rust. The fuzz target was inspired by [Fuzzing like a Caveman](https://h0mbre.github.io/Fuzzing-Like-A-Caveman/#)

The fuzzer is multithreaded, and performs simple mutations, which are :
+ Random bit flips
+ Random byte flips
+ Replacing random bytes with magic numbers (0, INT_MAX, etc.).

The code coverage used for this fuzzer is basic block coverage, and coverage data is shared between the fuzz target and the fuzzer using shared memory.

The fuzzer is coverage-guided, meaning that every file which produces new coverage is added to the corpus.

The fuzzer also runs an asan build of the target for files that produce crashes, to generate proper crash dumps.

### Features to be added:

+ Create snapshots of coverage, making it easier to load.
+ Add a way to load a snapshot instead of manually loading the whole corpus to initialize coverage.
+ Add command-line options (to load snapshot from disk, specify fuzz target, etc.).
+ ctrl-c handler (save snapshot)

use crate::Coverage;

extern "C" {

    pub fn shmget(key: u32, size: usize, flags: i32) -> i32;

    pub fn shmat(id: i32, ptr: *mut u8 , flags: i32) -> *mut Coverage;
    
}
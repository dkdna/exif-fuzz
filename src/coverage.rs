
const BITMAP_SIZE: usize = 0x60;
const BLOCK_COUNT: u32 = 651;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Coverage{
    pub total_blocks: u32,
    pub coverage_count: u32,
    pub blocks: [u8; BITMAP_SIZE],
}

impl Coverage {

    pub fn new() -> Self {

        Coverage { 
            total_blocks: BLOCK_COUNT, coverage_count: 0, blocks: [0; BITMAP_SIZE] 
        }

    }

    pub fn update_coverage(&mut self, new_coverage: Coverage) -> bool {

        let mut updated_coverage: bool = false;

        let new_blocks = new_coverage.blocks;

        for i in 0..self.total_blocks as usize {
            
            // If block has not been previously covered
            if (((new_blocks[i / 8] >> (i % 8)) & 1) != 0) && (((self.blocks[i / 8] >> (i % 8)) & 1) == 0) {
                self.blocks[i / 8] |= 1 << (i % 8);
                self.coverage_count += 1;
                updated_coverage = true;
            }
        }

        updated_coverage
    }

    pub fn get_total_coverage(&self) -> (u32, u32) {

        (self.coverage_count, self.total_blocks)

    }
}

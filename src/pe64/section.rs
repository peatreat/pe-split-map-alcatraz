use std::slice;

use crate::pe64::headers::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};

pub struct Section<'a> {
    pub _raw: &'a [u8],
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub characteristics: u32,
}

impl Section<'_> {
    pub fn is_executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
    }

    pub fn contains_rva(&self, rva: usize) -> bool {
        rva >= self.virtual_address && rva < (self.virtual_address + self.virtual_size)
    }
}

impl<'a> From<(&'a [u8], &'a IMAGE_SECTION_HEADER)> for Section<'a> {
    fn from((raw, header): (&[u8], &'a IMAGE_SECTION_HEADER)) -> Self {
        let section_raw = unsafe { slice::from_raw_parts::<'a, u8>(raw.as_ptr().add(header.PointerToRawData as usize) as *const u8, header.SizeOfRawData as usize) };
        
        let name = header.Name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect::<String>();
        
        Self {
            _raw: section_raw,
            name,
            virtual_address: header.VirtualAddress as usize,
            virtual_size: header.VirtualSize as usize,
            characteristics: header.Characteristics
        }
    }
}
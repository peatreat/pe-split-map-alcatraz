use std::slice;

use crate::pe64::headers::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};

pub struct Section<'a> {
    pub _raw: &'a [u8],
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub size_of_raw_data: usize,
    pub section_alignment: usize,
    pub characteristics: u32,
}

impl Section<'_> {
    pub fn is_executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
    }

    pub fn size(&self) -> usize {
        let size = self.virtual_size.max(self.size_of_raw_data);

        if self.section_alignment == 0 {
            return size;
        }

        size.next_multiple_of(self.section_alignment)
    }

    pub fn contains_rva(&self, rva: usize) -> bool {
        rva >= self.virtual_address && rva < (self.virtual_address + self.size())
    }
}

impl<'a> From<(&'a [u8], &'a IMAGE_SECTION_HEADER, usize)> for Section<'a> {
    fn from((raw, header, section_alignment): (&[u8], &'a IMAGE_SECTION_HEADER, usize)) -> Self {
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
            size_of_raw_data: header.SizeOfRawData as usize,
            section_alignment,
            characteristics: header.Characteristics
        }
    }
}
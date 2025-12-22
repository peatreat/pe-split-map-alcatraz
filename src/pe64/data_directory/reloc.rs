use core::num;
use std::mem;

pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

use crate::pe64::PE64;
use crate::psm_error::PSMError;

pub struct RelocDirectory;

#[derive(Copy, Clone)]
pub struct RelocSymbol {
    pub rva: usize,
    pub size: Option<usize>,
}

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}

impl RelocDirectory {
    pub fn get_reloc_symbols(pe64: &PE64) -> Result<Option<Vec<RelocSymbol>>, PSMError> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let reloc_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

        if reloc_data_directory.VirtualAddress == 0 || reloc_data_directory.Size == 0 {
            return Ok(None);
        }

        let mut base_reloc_va = reloc_data_directory.VirtualAddress as usize;
        let mut base_reloc_entry = pe64.get_ref_from_rva::<IMAGE_BASE_RELOCATION>(base_reloc_va).ok();

        let mut symbols = Vec::new();

        while let Some(entry) = base_reloc_entry {
            if entry.VirtualAddress == 0 || entry.SizeOfBlock == 0 {
                break;
            }

            let reloc_entry_va = base_reloc_va + mem::size_of::<IMAGE_BASE_RELOCATION>();
            let num_relocs = (entry.SizeOfBlock as usize - mem::size_of::<IMAGE_BASE_RELOCATION>()) / mem::size_of::<u16>();

            for i in 0..num_relocs {
                let reloc_data_offset = reloc_entry_va + i * mem::size_of::<u16>();
                let reloc_data = *(pe64.get_ref_from_rva(reloc_data_offset)? as &u16) as u32;

                let reloc_type = reloc_data >> 12;
                let reloc_offset = reloc_data & 0xFFF;

                let target_rva = entry.VirtualAddress as usize + reloc_offset as usize;

                if reloc_type == IMAGE_REL_BASED_DIR64 as u32 {
                    symbols.push(RelocSymbol {
                        rva: target_rva,
                        size: Some(mem::size_of::<u64>()),
                    });

                    let mut relocated_rva: u64 = *pe64.get_ref_from_rva::<u64>(target_rva)?;

                    relocated_rva = relocated_rva.wrapping_sub(pe64.nt64().OptionalHeader.ImageBase);

                    symbols.push(RelocSymbol {
                        rva: relocated_rva as usize,
                        size: None,
                    });
                }
            }

            base_reloc_va += entry.SizeOfBlock as usize;
            base_reloc_entry = pe64.get_ref_from_rva::<IMAGE_BASE_RELOCATION>(base_reloc_va).ok();
        }

        Ok(Some(symbols))
    }
}

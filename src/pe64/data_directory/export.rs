use std::collections::HashMap;

use crate::{pe64::{PE64, headers::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY}}};
use crate::psm_error::PSMError;

pub struct ExportDirectory {
    pub rva: usize,
    pub size: usize,
    pub ordinal_base: u32,
    pub name_ordinals: Vec<(u16, String)>,
    pub functions: Vec<u32>,
}

impl ExportDirectory {
    pub fn get_export_offset_from_name(&self, name: &str) -> Option<u32> {
        self.name_ordinals.iter().find_map(|(ordinal, n)| {
            if n == name {
                Some(self.functions[*ordinal as usize])
            } else {
                None
            }
        })
    }
    pub fn get_export_offset_from_ordinal(&self, ordinal: u16) -> Option<u32> {
        let offset = (ordinal as u32 - self.ordinal_base) as usize;

        if offset < self.functions.len() {
            return Some(self.functions[offset]);
        }

        None
    }

    pub fn get_export_directory(pe64: &PE64) -> Result<Option<Self>, PSMError> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let export_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_directory.VirtualAddress == 0 || export_data_directory.Size == 0 {
            return Ok(None);
        }

        let entry: Option<&IMAGE_EXPORT_DIRECTORY> = pe64.get_ref_from_rva(export_data_directory.VirtualAddress as usize).ok();

        if let Some(entry) = entry {
            let mut export_dir = ExportDirectory {
                rva: export_data_directory.VirtualAddress as usize,
                size: export_data_directory.Size as usize,
                ordinal_base: entry.Base,
                name_ordinals: Vec::new(),
                functions: Vec::new(),
            };

            for i in 0..entry.NumberOfNames {
                let name_rva = pe64.get_ref_from_rva::<u32>((entry.AddressOfNames as usize) + (i * 4) as usize)?;

                let size = pe64.get_string_size(*name_rva as usize)?.saturating_sub(1);

                let name = String::from_utf8(pe64.get_data_from_rva(*name_rva as usize, size)?.to_vec())?;
                let ordinal = pe64.get_ref_from_rva::<u16>((entry.AddressOfNameOrdinals as usize) + (i * 2) as usize)?;

                export_dir.name_ordinals.push((*ordinal, name));
            }

            export_dir.functions = unsafe { std::slice::from_raw_parts(pe64.get_ref_from_rva(entry.AddressOfFunctions as usize)? as *const u32, entry.NumberOfFunctions as usize).to_vec()};

            return Ok(Some(export_dir));
        }

        Ok(None)
    }
}
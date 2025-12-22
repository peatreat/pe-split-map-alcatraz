use std::mem;

use crate::pe64::{PE64, headers::{IMAGE_DEBUG_DIRECTORY, IMAGE_DIRECTORY_ENTRY_DEBUG}};

pub struct DebugDirectory {
    pub dir_rva: usize,
    pub dir_size: usize,
    pub data_rva: usize,
    pub data_size: usize,
}

impl DebugDirectory {
    pub fn get_debug_directories(pe64: &PE64) -> Vec<Self> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let debug_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG as usize];

        if debug_data_directory.VirtualAddress == 0 || debug_data_directory.Size == 0 {
            return Vec::new();
        }

        let debug_rva = debug_data_directory.VirtualAddress as usize;
        let debug_size = debug_data_directory.Size as usize;

        let mut debug_directories = Vec::new();

        let number_of_entries = debug_size / mem::size_of::<IMAGE_DEBUG_DIRECTORY>();

        for i in 0..number_of_entries {
            let entry: Option<&IMAGE_DEBUG_DIRECTORY> = pe64.get_ref_from_rva(debug_rva + i * mem::size_of::<IMAGE_DEBUG_DIRECTORY>()).ok();

            if let Some(entry) = entry {
                debug_directories.push(Self {
                    dir_rva: debug_rva + i * mem::size_of::<IMAGE_DEBUG_DIRECTORY>(),
                    dir_size: mem::size_of::<IMAGE_DEBUG_DIRECTORY>(),
                    data_rva: entry.AddressOfRawData as usize,
                    data_size: entry.SizeOfData as usize,
                });
            }
        }

        debug_directories
    }
}
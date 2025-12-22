use std::mem::{self, offset_of};

use crate::psm_error::PSMError;
use crate::{pe64::{PE64, headers::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64, IMAGE_THUNK_DATA64}}};

pub struct Imports {
    pub dir_rva: usize,
    pub dir_size: usize,
    pub directories: Vec<ImportDirectory>,
}

pub struct DllImport {
    pub base: usize,
    pub name: String,
    pub path: String,
}

pub struct ImportDirectory {
    pub dll_name_rva_and_size: Option<(usize, usize)>, // (rva, size)
    pub thunks: Vec<ThunkData>,
}

pub struct ThunkData {
    pub rva: usize,
    pub size: usize,
    pub rva_of_data: usize,
    pub ordinal: Option<u16>,
    pub name_rva_and_size: Option<(usize, usize)>, // (rva, size)
}

impl ImportDirectory {
    pub fn get_imports(pe64: &PE64) -> Result<Option<Imports>, PSMError> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let import_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        if import_directory.VirtualAddress == 0 || import_directory.Size == 0 {
            return Ok(None);
        }

        let import_dir_rva = import_directory.VirtualAddress as usize;
        let import_dir_size = import_directory.Size as usize;

        let mut imports = Imports {
            dir_rva: import_dir_rva,
            dir_size: import_dir_size,
            directories: Vec::new(),
        };

        let number_of_entries = import_dir_size / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        for i in 0..number_of_entries {
            let mut import_directory = ImportDirectory {
                dll_name_rva_and_size: None,
                thunks: Vec::new(),
            };

            let entry: Option<&IMAGE_IMPORT_DESCRIPTOR> = pe64.get_ref_from_rva(import_dir_rva + i * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()).ok();

            if let Some(entry) = entry {
                if entry.Name != 0 {
                    let size = pe64.get_string_size(entry.Name as usize)?;
                    import_directory.dll_name_rva_and_size = Some((entry.Name as usize, size));
                }

                let mut original_thunk_rva = entry.OriginalFirstThunk as usize;
                let original_thunk: Option<&IMAGE_THUNK_DATA64> = pe64.get_ref_from_rva(original_thunk_rva).ok();
                let mut count = 0;

                if let Some(mut original_thunk) = original_thunk {
                    unsafe {
                        while *original_thunk != 0 {
                            let mut thunk_data = ThunkData {
                                rva: original_thunk_rva,
                                size: mem::size_of::<IMAGE_THUNK_DATA64>(),
                                rva_of_data: entry.FirstThunk as usize + count * mem::size_of::<IMAGE_THUNK_DATA64>(),
                                ordinal: None,
                                name_rva_and_size: None,
                            };

                            if *original_thunk & IMAGE_ORDINAL_FLAG64 == 0 { // import by name
                                let import_by_name_rva = *original_thunk as usize;
                                let mut import_size = mem::size_of::<u16>(); // Hint is u16

                                let mut size = pe64.get_string_size(import_by_name_rva + offset_of!(IMAGE_IMPORT_BY_NAME, Name))?;
                                size = size.max(2); // at least 2 bytes for the name for alignment
                                import_size += size; // add size of name

                                thunk_data.name_rva_and_size = Some((import_by_name_rva, import_size));
                            } else {
                                thunk_data.ordinal = Some(*(original_thunk as *const u64 as *const u16));
                            }

                            import_directory.thunks.push(thunk_data);

                            original_thunk = &*(original_thunk as *const IMAGE_THUNK_DATA64).add(1);
                            original_thunk_rva += mem::size_of::<IMAGE_THUNK_DATA64>();
                            count += 1;
                        }
                    }
                }
            }

            imports.directories.push(import_directory);
        }

        Ok(Some(imports))
    }
}

impl DllImport {
    pub fn new(base: usize, path: &str) -> Option<Self> {
        Some (
            Self {
                base,
                name: std::path::Path::new(path).file_name()?.to_str()?.to_string(),
                path: path.to_owned(),
            }
        )
    }
}
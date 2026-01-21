use iced_x86::{code_asm::bl, Decoder};
use rand::seq::SliceRandom;

use crate::{
    heap::{self, Heap},
    pe64::{
        data_directory::{DllImport, ExportDirectory, ImportDirectory, RelocDirectory},
        symbols::Symbol,
        translation::{block::TranslationBlock, Translation},
        PE64,
    },
    psm_error::{PSMError, Result},
};

pub struct Mapper;

pub struct Mapped {
    pub entrypoint: u64,
    pub blocks: Vec<MappedBlock>,
}

#[derive(Default)]
pub struct MappedBlock {
    pub address: u64,
    pub data: Vec<u8>,
}

pub enum TranslationBlockSize {
    MaxByteSize(u64),
    MaxNumberInstructions(u64),
}

impl Mapper {
    pub fn find_symbol_by_rva(
        symbols: &[(std::ops::Range<usize>, MappedBlock)],
        rva: usize,
    ) -> Option<&(std::ops::Range<usize>, MappedBlock)> {
        let mut first = 0isize;
        let mut last = symbols.len() as isize - 1;

        while first <= last {
            let mid_index = (first + last) / 2;
            let mid = &symbols[mid_index as usize];

            if (mid.0.contains(&rva)) {
                return Some(mid);
            } else if rva < mid.0.start {
                last = mid_index - 1;
            } else {
                first = mid_index + 1;
            }
        }

        None
    }
    pub fn find_symbol_by_rva_mut(
        symbols: &mut [(std::ops::Range<usize>, MappedBlock)],
        rva: usize,
    ) -> Option<&mut (std::ops::Range<usize>, MappedBlock)> {
        let mut first = 0isize;
        let mut last = symbols.len() as isize - 1;

        while first <= last {
            let mid_index = (first + last) / 2;

            if symbols[mid_index as usize].0.contains(&rva) {
                return Some(&mut symbols[mid_index as usize]);
            } else if rva < symbols[mid_index as usize].0.start {
                last = mid_index - 1;
            } else {
                first = mid_index + 1;
            }
        }

        None
    }

    fn map_symbols(
        pe: &PE64,
        heap: &mut Heap,
        symbols: &[(usize, Symbol)],
    ) -> Result<Vec<(std::ops::Range<usize>, MappedBlock)>> {
        // filter out ignored symbols
        let mut symbols = symbols
            .iter()
            .filter(|(rva, symbol)| !symbol.should_ignore && symbol.max_operation_size > 0)
            .map(|(rva, symbol)| {
                (
                    *rva..(*rva + symbol.max_operation_size as usize),
                    MappedBlock::default(),
                )
            })
            .collect::<Vec<_>>();

        // allocate in random order
        let mut symbols_shuffled = symbols.iter_mut().collect::<Vec<_>>();
        let mut rng = rand::rng();
        symbols_shuffled.shuffle(&mut rng);

        for (rva_range, mapped_block) in &mut symbols_shuffled {
            let symbol_size = (rva_range.end - rva_range.start) as usize;

            mapped_block.address = heap.reserve_with_same_alignment(
                rva_range.start as u64,
                (rva_range.end - rva_range.start) as u64,
                32,
            )?;

            mapped_block.data = pe
                .get_data_from_rva(rva_range.start, symbol_size)
                .and_then(|slice| Ok(slice.to_vec()))
                .unwrap_or(vec![0u8; symbol_size]);
        }

        Ok(symbols)
    }

    pub fn map(
        pe: &PE64,
        dll_imports: &[DllImport],
        code_heap: &mut Heap,
        symbol_heap: &mut Heap,
        translations: &mut [Translation],
        symbols: &[(usize, Symbol)],
        block_size: TranslationBlockSize,
        assume_jumps_are_near: bool,
    ) -> Result<Mapped> {
        // map symbols
        let mut symbols = Mapper::map_symbols(pe, symbol_heap, symbols)?;

        // create our blocks
        let mut blocks: Vec<TranslationBlock> = Vec::new();

        let mut current_block = TranslationBlock::new();

        for index in 0..translations.len() {
            current_block.add_translation(index);

            match block_size {
                TranslationBlockSize::MaxByteSize(size) => {
                    if current_block.byte_size(translations, assume_jumps_are_near)? >= size {
                        blocks.push(current_block);
                        current_block = TranslationBlock::new();
                    }
                }
                TranslationBlockSize::MaxNumberInstructions(size) => {
                    if current_block.len() >= size {
                        blocks.push(current_block);
                        current_block = TranslationBlock::new();
                    }
                }
            }
        }

        if !current_block.is_empty() {
            blocks.push(current_block);
        }

        // allocate blocks in a random order
        let mut blocks_shuffled = blocks.iter_mut().collect::<Vec<_>>();
        let mut rng = rand::rng();
        blocks_shuffled.shuffle(&mut rng);

        for block in &mut blocks_shuffled {
            block.reserve(translations, code_heap, 0x10, assume_jumps_are_near)?;
        }

        // resolve blocks
        for block in blocks.iter_mut() {
            block.resolve(&pe, translations, &symbols)?;
        }

        // resolve base relocations
        if let Some(reloc_symbols) = RelocDirectory::get_reloc_symbols(pe)? {
            for reloc_symbol in reloc_symbols {
                if let Some(8) = reloc_symbol.size {
                    let mut relocated_rva: u64 = *pe.get_ref_from_rva::<u64>(reloc_symbol.rva)?;

                    relocated_rva = relocated_rva.wrapping_sub(pe.nt64().OptionalHeader.ImageBase);

                    let relocated_symbol_address = Translation::translate_rva_to_mapped(
                        &pe,
                        &translations,
                        &symbols,
                        relocated_rva,
                    )?;

                    if let Some((rva_range, symbol)) =
                        Mapper::find_symbol_by_rva_mut(&mut symbols, reloc_symbol.rva)
                    {
                        let symbol_offset = reloc_symbol.rva - rva_range.start;
                        symbol.data[symbol_offset..(symbol_offset + 8)]
                            .copy_from_slice(&relocated_symbol_address.to_le_bytes());
                    }
                }
            }
        }

        // resolve imports
        if let Some(imports) = ImportDirectory::get_imports(pe)? {
            for import_dir in imports.directories {
                if let Some(dll_name) = import_dir
                    .dll_name_rva_and_size
                    .and_then(|(name_rva, size)| pe.get_data_from_rva(name_rva, size).ok())
                    .and_then(|dll_name_slice| {
                        String::from_utf8(dll_name_slice[..dll_name_slice.len() - 1].to_vec()).ok()
                    })
                {
                    println!("dll: {}", dll_name);

                    let dll_import = dll_imports
                        .iter()
                        .find(|dll_import| dll_import.name.eq_ignore_ascii_case(&dll_name))
                        .ok_or(PSMError::ImportDLLNotFound(dll_name.to_owned()))?;

                    let exports = ExportDirectory::get_export_directory(&PE64::new(
                        &dll_import.path,
                        false,
                        false,
                    )?)?
                    .ok_or(PSMError::ImportHasNoExports(dll_name.to_owned()))?;

                    for thunk in import_dir.thunks {
                        let export_offset = if let Some(import_name) = thunk
                            .name_rva_and_size
                            .and_then(|(name_rva, size)| {
                                pe.get_data_from_rva(
                                    name_rva + std::mem::size_of::<u16>(),
                                    size - std::mem::size_of::<u16>(),
                                )
                                .ok()
                            })
                            .and_then(|import_name_slice| {
                                String::from_utf8(
                                    import_name_slice[..import_name_slice.len() - 1].to_vec(),
                                )
                                .ok()
                            }) {
                            exports.get_export_offset_from_name(&import_name).ok_or(
                                PSMError::ImportNotFound(
                                    dll_name.to_owned(),
                                    None,
                                    Some(import_name),
                                ),
                            )
                        } else if let Some(ordinal) = thunk.ordinal {
                            exports.get_export_offset_from_ordinal(ordinal).ok_or(
                                PSMError::ImportNotFound(dll_name.to_owned(), Some(ordinal), None),
                            )
                        } else {
                            Err(PSMError::BadImportFunctionName(
                                dll_name.to_owned(),
                                thunk
                                    .name_rva_and_size
                                    .and_then(|(name_rva, _)| Some(name_rva)),
                            ))
                        }?;

                        let import_address = dll_import.base + export_offset as usize;

                        if let Some((rva_range, symbol)) =
                            Mapper::find_symbol_by_rva_mut(&mut symbols, thunk.rva_of_data)
                        {
                            let symbol_offset = thunk.rva_of_data - rva_range.start;
                            symbol.data[symbol_offset..(symbol_offset + 8)]
                                .copy_from_slice(&import_address.to_le_bytes());
                        }
                    }
                }
            }
        }

        // get entrypoint address
        let entrypoint = Translation::translate_rva_to_mapped(
            &pe,
            translations,
            &symbols,
            pe.nt64().OptionalHeader.AddressOfEntryPoint as u64,
        )?;

        // create mapped blocks
        let mut mapped_blocks: Vec<MappedBlock> = Vec::new();

        for (index, block) in blocks.iter().enumerate() {
            mapped_blocks.push(MappedBlock {
                address: block.address(translations)?,
                data: block.buffer(translations, assume_jumps_are_near, blocks.get(index + 1))?,
            });
        }

        mapped_blocks.reserve(symbols.len());

        mapped_blocks.append(
            &mut symbols
                .into_iter()
                .map(|(_, mapped_block)| mapped_block)
                .collect(),
        );

        // shuffle to mix up the order of writes being transmitted
        mapped_blocks.shuffle(&mut rng);

        Ok(Mapped {
            entrypoint,
            blocks: mapped_blocks,
        })
    }
}

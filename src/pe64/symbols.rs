use std::collections::HashMap;

use iced_x86::{Decoder, Mnemonic};

use crate::psm_error::PSMError;

use super::PE64;
use super::data_directory::{DebugDirectory, ExceptionDirectory, ExportDirectory, ImportDirectory, RelocDirectory, reloc};

#[derive(Copy, Clone)]
pub struct Symbol {
    pub max_operation_size: u32,
    pub is_ptr_reference: bool,
    pub is_directory_symbol: bool,
    pub should_ignore: bool,
}

pub fn get_symbol(symbol: &[(usize, Symbol)], rva: usize) -> Option<&(usize, Symbol)> {
    symbol.iter().find(|s| (s.0..(s.0+s.1.max_operation_size as usize)).contains(&rva))
}

impl Symbol {
    pub fn update_or_insert(
        symbols: &mut HashMap<usize, Symbol>,
        rva: usize,
        operation_size: u32,
        is_ptr_reference: bool,
        is_directory_symbol: bool,
        should_ignore: bool,
    ) {
        symbols.entry(rva)
            .and_modify(|symbol| {
                if operation_size > symbol.max_operation_size {
                    symbol.max_operation_size = operation_size;
                }

                if is_ptr_reference {
                    symbol.is_ptr_reference = true;
                }

                if is_directory_symbol {
                    symbol.is_directory_symbol = true;
                }
            })
            .or_insert_with(|| Symbol {
                max_operation_size: operation_size,
                is_ptr_reference,
                is_directory_symbol,
                should_ignore,
            });
    }
}

pub fn split_symbols(pe: &PE64, obfuscated: bool) -> Result<Vec<(usize, Symbol)>, PSMError> {
    let mut symbols: HashMap<usize, Symbol> = HashMap::new();

    pe.iter_find_section(|section| {
        println!("section: {}, raw size: {:p}, virt size: {:p}", section.name, section._raw.len() as *const usize, section.virtual_size as *const usize);

        if section.is_executable() && !(obfuscated && section.name == ".text") {
            let mut decoder = Decoder::new(64, section._raw, iced_x86::DecoderOptions::NONE);

            decoder.set_ip(section.virtual_address as u64);

            let mut prev_lea_ref: Option<u64> = None;

            while decoder.can_decode() {
                let instruction = decoder.decode();

                if instruction.mnemonic() == Mnemonic::Sub {
                    if let Some(prev_ref) = prev_lea_ref {
                        let obfuscation_offset = instruction.immediate32();

                        let operand_rva = prev_ref.wrapping_sub(obfuscation_offset as u64);
                        let operand_section = pe.iter_find_section(|s| s.contains_rva(operand_rva as usize));
                        
                        if let Some(operand_section) = operand_section {
                            if !operand_section.is_executable() {
                                let operand_size = 0;
                                let is_lea_instruction = true;

                                // update if already exists with larger size else insert new
                                Symbol::update_or_insert(
                                    &mut symbols,
                                    operand_rva as usize,
                                    operand_size as u32,
                                    is_lea_instruction,
                                    false,
                                    false,
                                );
                            }
                        }

                        prev_lea_ref = None;
                    }
                }

                if instruction.is_ip_rel_memory_operand() {
                    if obfuscated && instruction.mnemonic() == Mnemonic::Lea {
                        prev_lea_ref = Some(instruction.ip_rel_memory_address());
                        continue;
                    }

                    println!("{:p} | {:p}", instruction.ip() as *const usize, instruction.ip_rel_memory_address() as *const usize);
                    let operand_section = pe.iter_find_section(|s| s.contains_rva(instruction.ip_rel_memory_address() as usize));
                    
                    if let Some(operand_section) = operand_section {
                        if operand_section.is_executable() {
                            // if operand referenced is in an executable section, skip symbol storage
                            continue;
                        }

                        let operand_size = instruction.memory_size().size();
                        let is_lea_instruction = instruction.mnemonic() == iced_x86::Mnemonic::Lea;

                        // update if already exists with larger size else insert new
                        Symbol::update_or_insert(
                            &mut symbols,
                            instruction.ip_rel_memory_address() as usize,
                            operand_size as u32,
                            is_lea_instruction,
                            false,
                            false,
                        );
                    }
                    //println!("instruction: {} | rva: {:p} | symbol rva: {:p} | size: {:?}", instruction, (section.virtual_address as u64 + instruction.ip()) as *const usize, (section.virtual_address as u64 + instruction.ip_rel_memory_address()) as *const usize, instruction.memory_size().size());
                }
            }

            return true;
        }

        false
    });

    DebugDirectory::get_debug_directories(&pe).iter().for_each(|debug_dir| {
        Symbol::update_or_insert(
            &mut symbols,
            debug_dir.dir_rva,
            debug_dir.dir_size as u32,
            false,
            true,
            true,
        );

        Symbol::update_or_insert(
            &mut symbols,
            debug_dir.data_rva,
            debug_dir.data_size as u32,
            false,
            true,
            true,
        );

        //println!("debug dir rva: {:p} | size: 0x{:X} ", (debug_dir.dir_rva as *const usize), debug_dir.dir_size);
        //println!("debug data rva: {:p} | size: 0x{:X} ", (debug_dir.data_rva as *const usize), debug_dir.data_size);
    });

    ExceptionDirectory::get_unwind_blocks(&pe).iter().for_each(|unwind_block| {
        Symbol::update_or_insert(
            &mut symbols,
            unwind_block.rva,
            unwind_block.size as u32,
            false,
            true,
            true,
        );

        //println!("unwind block rva: {:p} | size: 0x{:X} ", (unwind_block.rva as *const usize), unwind_block.size);
    });

    if let Some(export_dir) = ExportDirectory::get_export_directory(&pe)? {
        Symbol::update_or_insert(
            &mut symbols,
            export_dir.rva,
            export_dir.size as u32,
            false,
            true,
            true,
        );

        println!("export dir rva: {:p} | size: 0x{:X} ", (export_dir.rva as *const usize), export_dir.size);
    };

    if let Some(imports) = ImportDirectory::get_imports(&pe)? {
        Symbol::update_or_insert(
            &mut symbols,
            imports.dir_rva,
            imports.dir_size as u32,
            false,
            true,
            true,
        );

        println!("import dir rva: {:p} | size: 0x{:X} ", (imports.dir_rva as *const usize), imports.dir_size);

        for import_dir in imports.directories {
            if let Some((dll_name_rva, dll_name_size)) = import_dir.dll_name_rva_and_size {
                Symbol::update_or_insert(
                    &mut symbols,
                    dll_name_rva,
                    dll_name_size as u32,
                    false,
                    true,
                    true,
                );

                println!("import dll name rva: {:p} | size: 0x{:X} ", (dll_name_rva as *const usize), dll_name_size);
            }

            import_dir.thunks.iter().for_each(|thunk| {
                Symbol::update_or_insert(
                    &mut symbols,
                    thunk.rva,
                    thunk.size as u32,
                    false,
                    true,
                    false,
                );
                
                println!("import thunk rva: {:p} | size: 0x{:X} ", (thunk.rva as *const usize), thunk.size);

                if let Some((name_rva, name_size)) = thunk.name_rva_and_size {
                    Symbol::update_or_insert(
                        &mut symbols,
                        name_rva,
                        name_size as u32,
                        false,
                        true,
                        true,
                    );

                    println!("import thunk name rva: {:p} | size: 0x{:X} ", (name_rva as *const usize), name_size);
                }
            });
        }
    }

    if let Some(reloc_symbols) = RelocDirectory::get_reloc_symbols(&pe)? {
        // for relocation symbols, merge symbols that are <= 0x10 bytes apart into one symbol so vtables don't get split up

        if !reloc_symbols.is_empty() {
            let mut reloc_symbols = reloc_symbols.into_iter().collect::<Vec<_>>();
            reloc_symbols.sort_by_key(|s| s.rva);

            let mut merged_reloc_symbols = Vec::new();

            merged_reloc_symbols.push(reloc_symbols[0].clone());

            for i in 1..reloc_symbols.len() {
                let last_symbol = merged_reloc_symbols.last_mut().unwrap();
                let current_symbol = &reloc_symbols[i];

                if current_symbol.size.is_none() || last_symbol.size.is_none() {
                    merged_reloc_symbols.push(current_symbol.clone());
                    continue;
                }

                if current_symbol.rva <= last_symbol.rva + last_symbol.size.unwrap_or(0) + 0x10 {
                    // merge symbols by updating size
                    let new_size = (current_symbol.rva + current_symbol.size.unwrap_or(0)) - last_symbol.rva;
                    last_symbol.size = Some(new_size);
                } else {
                    merged_reloc_symbols.push(current_symbol.clone());
                }
            }

            for reloc_symbol in merged_reloc_symbols {
                let symbol_section = pe.iter_find_section(|s| s.contains_rva(reloc_symbol.rva)).unwrap();

                if symbol_section.is_executable() {
                    // if relocation is in an executable section, skip symbol storage
                    continue;
                }

                Symbol::update_or_insert(
                    &mut symbols,
                    reloc_symbol.rva,
                    reloc_symbol.size.unwrap_or(0) as u32,
                    reloc_symbol.size.is_none(),
                    true,
                    false,
                );

                println!("reloc symbol rva: {:p} | size: {:?}", (reloc_symbol.rva as *const usize), reloc_symbol.size);
            }
        }
    }

    let mut sorted_symbols = symbols.iter().map(|(key, value)| (*key, *value)).collect::<Vec<_>>();
    sorted_symbols.sort_by_key(| (k, _) | *k);

    // update ptr reference symbols to have size = next_symbol_rva - current_symbol_rva if larger than current size, but clamp to section size
    for i in 0..sorted_symbols.len() - 1 {
        let next_rva = sorted_symbols[i + 1].0;
        let (current_rva, current_symbol) = &mut sorted_symbols[i];

        if current_symbol.is_ptr_reference {
            let symbol_section = pe.iter_find_section(|s| s.contains_rva(*current_rva)).unwrap();
            let section_end_rva = symbol_section.virtual_address + symbol_section.virtual_size;

            let calculated_size = next_rva.saturating_sub(*current_rva);
            let new_size = calculated_size.min(section_end_rva.saturating_sub(*current_rva));

            if new_size as u32 > current_symbol.max_operation_size {
                sorted_symbols[i].1.max_operation_size = new_size as u32;
            }
        }
    }

    // update last if is ptr reference to section end
    if let Some((last_rva, last_symbol)) = sorted_symbols.last_mut() {
        if last_symbol.is_ptr_reference {
            let symbol_section = pe.iter_find_section(|s| s.contains_rva(*last_rva)).unwrap();
            let section_end_rva = symbol_section.virtual_address + symbol_section.virtual_size;

            let calculated_size = section_end_rva.saturating_sub(*last_rva);

            last_symbol.max_operation_size = calculated_size as u32;
        }
    }

    // merge overlapping symbols
    // if cur rva is between last rva and last rva + size, update last size to max(last size, cur rva + cur size - last rva), else add new symbol to merged list
    let mut merged_symbols: Vec<(usize, Symbol)> = Vec::new();

    for (rva, symbol) in sorted_symbols {
        if let Some((last_rva, last_symbol)) = merged_symbols.last_mut() {
            if rva >= *last_rva && rva < (*last_rva + last_symbol.max_operation_size as usize) {
                // overlapping, update size
                let new_size = (rva + symbol.max_operation_size as usize).saturating_sub(*last_rva);
                if new_size as u32 > last_symbol.max_operation_size {
                    last_symbol.max_operation_size = new_size as u32;
                }

                last_symbol.is_ptr_reference |= symbol.is_ptr_reference;
            } else {
                // non-overlapping, add new symbol
                merged_symbols.push((rva, symbol));
            }
        } else {
            // first symbol, add directly
            merged_symbols.push((rva, symbol));
        }
    }

    // for all contiguous symbols after a ptr ref symbol, merge the ptr ref symbol to cover all contiguous symbols that are not ptr ref symbols
    let mut final_symbols: Vec<(usize, Symbol)> = Vec::new();
    let mut i = 0;
    while i < merged_symbols.len() {
        let (rva, symbol) = merged_symbols[i];

        if symbol.is_ptr_reference {
            let mut combined_size = symbol.max_operation_size as usize;
            let mut j = i + 1;
            let mut should_ignore = symbol.should_ignore;
            let symbol_section = pe.iter_find_section(|s| s.contains_rva(rva)).unwrap();

            while j < merged_symbols.len() {
                let (next_rva, next_symbol) = merged_symbols[j];
                let next_sym_section = pe.iter_find_section(|s| s.contains_rva(next_rva)).unwrap();

                if !next_symbol.is_ptr_reference && !next_symbol.is_directory_symbol && symbol_section.virtual_address == next_sym_section.virtual_address /* && next_rva == rva + combined_size*/ {
                    //combined_size = next_symbol.max_operation_size as usize;
                    if (!next_symbol.should_ignore) {
                        should_ignore = false;
                    }

                    j += 1;
                }
                /*else if next_symbol.is_ptr_reference {
                    combined_size += next_rva - (rva + combined_size);
                    break;
                }*/
                else {
                    combined_size = (next_rva - rva).min(symbol_section.virtual_address + symbol_section.virtual_size - rva);
                    break;
                }
            }

            if j == merged_symbols.len() {
                // reached end, extend to last symbol
                let (last_rva, last_symbol) = merged_symbols[j - 1];
                combined_size = (last_rva + last_symbol.max_operation_size as usize) - rva;
            }

            final_symbols.push((rva, Symbol {
                max_operation_size: combined_size as u32,
                is_ptr_reference: true,
                is_directory_symbol: symbol.is_directory_symbol,
                should_ignore: should_ignore,
            }));

            i = j;
        } else {
            final_symbols.push((rva, symbol));
            i += 1;
        }
    }

    //for (rva, symbol) in final_symbols {
    //    //println!("symbol rva: {:p} | end rva: {:p}", (rva as *const usize), (rva + symbol.max_operation_size as usize) as *const usize);
    //}

    Ok(final_symbols)
}
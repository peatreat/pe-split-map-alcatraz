#![allow(warnings)]

mod pe64;
mod heap;
mod psm_error;

use std::{cell::RefCell, collections::HashMap};

use pe64::PE64;
use iced_x86::{self, Decoder, Mnemonic, OpKind};
use rand::{seq::SliceRandom, thread_rng};

use crate::{heap::HeapPage, pe64::{data_directory::{DllImport, ExportDirectory, ImportDirectory}, mapper::{Mapper, TranslationBlockSize}, symbols::{get_symbol, split_symbols}, translation::{self, Translation}}};

fn main() {
    /*
        todo smap:
         - add instruction splitting up to certain max size (like 16 bytes)
         - create our own heap allocator to avoid fragmentation from many small allocations
         - if symbol is in a section that contains initialized data and the symbol rva < section va + SizeOfRawData, write bytes from in the raw section data, else write null bytes

        todo:
         - support base relocations
         - for base relocations that are 8 bytes apart, have them treated as 1 block of 8 * count bytes in size
         - set all ptr reference symbols to max(symbol_size, next_symbol_rva - current_symbol_rva)
         - do the same thing as overlapping intervals on leetcode for merging overlapping symbols (sort by rva, store first symbol rva and size in new vector, then for each next symbol in sorted vector we will check if the rva is between last item in new list's rva and rva + size, if it is then we update max of last entry in new list but if not then we add current symbol to new list)
    
        updates:
            - right now it works pretty good at getting the bounds right but some things it splits up incorrectly
            0x2E26D gets split up
            0x2eeae gets split up (the obfstr after this 1 doesnt have a lea and there is a byte ref in this array also, this tells us that there can be instructions that ref different offsets of an array that aren't contiguous but the symbol still needs to be together because the array also gets accessed at runtime by a register offset)
            // we need to fix our merging logic to handle these cases better
            - what i think we can do is after we do the overlapping merge, we can do another pass where for each ptr ref symbol, we extend its size to cover all contiguous non ptr ref symbols after it until we hit another ptr ref symbol

            i think the issue is with the end tags that get referenced in the obfuscated strings/bytes that mess up the symbol size calculation
            what i did should have merged symbols while they were contiguous and not ptr refs that were after a ptr ref symbol, but i think the merging logic was flawed

            i think it's better now, still need to take another scan through and see with the eye check
            .data symbols are just completely messed up idk why. i think maybe with the section segregation stuff
            at the end it just includes all the directory based symbols into 1 big symbol, idk if it's because those are missing or because of the new stuff i added for merging

            maybe for merging non-ptr refs between ptr refs we should add another check
            if it's a non-ptr ref that came from a regular instruction like mov ... then we do what we normally do by merging it to prev ptr ref symbol
            but if it's a non-ptr ref that we are 100% sure of the size (reloc ref sym, or data directory symbols), then split symbol there
    */

    let pe = PE64::new("test.dll", true).unwrap();

    let assume_near = true;

    let sym = split_symbols(&pe, true).unwrap();

    let mut translations = pe.get_translations(assume_near);

    let mut code_pages = Vec::new();
    let mut symbol_pages = Vec::new();

    for i in 0..200 {
        code_pages.push(HeapPage::new(0x300000 + i * 0x1000, 0x300000 + i * 0x1000 + 0x1000));
        symbol_pages.push(HeapPage::new(0x200000 + i * 0x1000, 0x200000 + i * 0x1000 + 0x1000));
    }

    symbol_pages.push(HeapPage::new(0x500000, 0x600000));

    let mut code_heap = heap::Heap::new(code_pages);
    let mut symbol_heap = heap::Heap::new(symbol_pages);

    let dll_imports = [
        DllImport::new(0x7f000000, "C:/Windows/System32/kernel32.dll").unwrap(),
    ];

    let mapped = Mapper::map(&pe, &dll_imports, &mut code_heap, &mut symbol_heap, &mut translations, &sym, TranslationBlockSize::MaxByteSize(32), true).unwrap();

    for block in mapped.blocks {
        println!("address: {:p}, data: {:02X?}", block.address as *const usize, block.data);
        let mut decoder = Decoder::new(64, &block.data, 0);
        
        decoder.set_ip(block.address as u64);

        while decoder.can_decode() {
            let instruction = decoder.decode();
            println!("{}", instruction);
        }
    }

    panic!();

    //for i in 0..32 {
    //    println!("{:?}", translations[i].buffer().unwrap());
    //    println!("{}", translations[i].instruction());
    //}
    let mut raw_allocations = Vec::new();

    pub struct Allocation<'a> {
        pub address: u64,
        pub size: u32,
        pub buffer: Vec<u8>,
        pub reservations: Vec<Reservation<'a>>,
    }

    impl Allocation<'_> {
        pub fn free_space(&mut self, size: u64) -> Option<(&mut Self, u64)> {
            let free_address = self.reservations.last().map_or(self.address, |x| x.address + x.buffer_size as u64);

            if free_address + size >= self.address + self.size as u64 {
                None
            }
            else {
                Some((self, free_address))
            }
        }
    }

    pub struct Reservation<'a> {
        pub rva: u64,
        pub buffer_index: usize,
        pub buffer_size: usize,
        //pub ip: u64,
        pub address: u64,
        pub size: u64,
        pub translation: Vec<(u64, &'a mut Translation)>,
        pub translation_size: u32,
    }

    // allocate memory segments, create reservation table
    for i in 0..4 {
        let mut alloc = Vec::new();
        const ALLOC_SIZE: usize = 0x1000;
        alloc.reserve(ALLOC_SIZE);
        raw_allocations.push( Allocation {
            address: i * ALLOC_SIZE as u64,
            size: ALLOC_SIZE as _,
            buffer: alloc,
            reservations: Vec::<Reservation>::new(),
        });
    }

    // sort by address
    raw_allocations.sort_by_key(|x| x.address);

    const MAX_BLOCK_SIZE: usize = 18;

    //translations.shuffle(&mut thread_rng());

    // allocate space for translations
    let mut i = 0;
    let translations_len = translations.len();
    while i < translations_len {
        let mut total_size = 0;
        let mut j = 0;

        let mut total_bytes = Vec::new();
        let mut total_translations: Vec<(u64, &mut Translation)> = Vec::new();
        let mut ip = 0;

        while total_size < MAX_BLOCK_SIZE && i + j < translations_len {
            let translation = &mut translations[i + j];

            if ip == 0 && j == 0 {
                ip = translation.rva();
            }

            total_translations.push((translation.rva(), unsafe { (translation as *mut Translation).as_mut().unwrap() }));
            
            let mut bytes = translation.buffer(assume_near).expect("Failed to get translation buffer");

            if total_size + bytes.len() > MAX_BLOCK_SIZE {
                break;
            }

            total_size += bytes.len();
            total_bytes.append(&mut bytes);
            j += 1;
        }

        const JMP_RIP: [u8; 14] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];

        let total_size_with_jmp_rip = ((total_size as u64 + JMP_RIP.len() as u64) + 0xF) & !0xF;

        let mut free_space = None;
        for alloc in &mut raw_allocations {
            let maybe_free_space = alloc.free_space((total_size  + JMP_RIP.len()) as _);
            if maybe_free_space.is_some() {
                free_space = maybe_free_space;
                break;
            }
        }

        let (free_base, free_space) = free_space.expect("Failed to allocate space");
        let offset_from_base = free_space - free_base.address;

        //println!("{:X} {free_space:X} {offset_from_base:X}", free_base.address);

        let mut bytes = unsafe { Box::<[u8]>::new_zeroed_slice(total_size_with_jmp_rip as _).assume_init() };
        bytes[..total_bytes.len()].copy_from_slice(&total_bytes);
        
        bytes[total_size..(total_size + JMP_RIP.len())].copy_from_slice(&JMP_RIP);
        //unsafe { (bytes.as_mut_ptr().add(total_size + 6) as *mut u64).write_unaligned(free_space + JMP_RIP.len() as u64 + total_size as u64); };

        let buffer_index = free_base.buffer.len();
        free_base.buffer.extend_from_slice(&bytes);
        free_base.reservations.push(Reservation {
            rva: ip,
            buffer_index,
            buffer_size: total_size_with_jmp_rip as _,
            address: free_space,
            size: total_size as _,
            translation: total_translations,
            translation_size: total_size as _,
        });
        
        i += j;
    }

    for alloc_i in 0..raw_allocations.len() {
        let alloc = &raw_allocations[alloc_i];
///
        for reservation_i in 0..alloc.reservations.len() {
            let reservation = &alloc.reservations[reservation_i];

            for translation_i in 0..reservation.translation.len() {
                let (rva, translation) = &reservation.translation[translation_i];
                //println!("{rva:X}");

                match translation {
                    Translation::Default(default_translation) => {},
                    Translation::Jcc(jcc_translation) => {
                        //jcc_translation.resolve(ip);
                        let reservation_at_address = alloc.reservations.iter().find(|r| (r.rva..(r.rva + r.size)).contains(&rva)).unwrap();
                        let reservation_offset = rva - reservation_at_address.rva;
                        //let translation = pe.find_first_translation_rva(&translations, jcc_translation.branch_target as _).unwrap();
                        let (translation_alloc, reservation_for_translation, (res_rva, reservation_with_translation)) = raw_allocations.iter().find_map(|alloc| alloc.reservations.iter().find_map(|r| 
                            if let Some(translation) = r.translation.iter().find(|x| {
                                //println!("{:X}", x.0);
                                x.0 == jcc_translation.branch_target as _
                            }) {
                                Some((alloc, r, translation))
                            }
                            else {
                                None
                            }
                        )).unwrap();
                        //let translation = translations.iter().find(|t| t as *const _ as usize == *reservation_with_translation  as *const _ as usize);
    
                        //
                        //if let Some((reservation_for_translation, (res_rva, reservation_with_translation))) = reservation_with_translation {
                        let mut jcc_translation = jcc_translation.clone();
                        let new_ip = reservation_for_translation.address + reservation_for_translation.buffer_index as u64;
                        let offset_from_reservation = res_rva - reservation_for_translation.rva;
                        let new_address = translation_alloc.address + reservation_for_translation.buffer_index as u64 + reservation_offset as u64;
                        jcc_translation.resolve(new_address);
                        let buffer = jcc_translation.buffer(assume_near).unwrap();
                        let alloc = unsafe { (alloc as *const Allocation as *mut Allocation).as_mut().unwrap() };
                        //alloc.buffer[(reservation.buffer_index)..(reservation.buffer_index +buffer.len())].copy_from_slice(&buffer);
                        //let x = reservation_for_translation.rva + reservation_for_translation.;
                    //
                        //println!("{reservation_offset:X} {offset_from_reservation:X} {new_address:X} {:X} {:X} {:X}", res_rva, reservation_for_translation.buffer_index, reservation_for_translation.rva);
                    },
                    Translation::Control(control_translation) => {},
                    Translation::Relative(relative_translation) => {},
                    Translation::Near(near_translation) => todo!(),
                }
            }
        }
    }

    let mut total_bytes = Vec::new();
    for alloc in &mut raw_allocations {
        //println!("{:X}", alloc.buffer.len());
        total_bytes.append(&mut alloc.buffer);
    }

    std::fs::write("out.bin", total_bytes).expect("Failed to write output to file!");
}

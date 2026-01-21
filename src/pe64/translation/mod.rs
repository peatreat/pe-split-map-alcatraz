pub mod block;
pub mod control;
pub mod jcc;
pub mod near;
pub mod raw;
pub mod relative;

pub use control::ControlTranslation;
use iced_x86::{Decoder, Encoder, Instruction};
pub use jcc::JCCTranslation;
use rand::RngCore;
pub use relative::RelativeTranslation;

use crate::{
    pe64::{
        mapper::{MappedBlock, Mapper},
        translation::near::NearTranslation,
    },
    psm_error::PSMError,
    PE64,
};

pub enum Translation {
    Default(DefaultTranslation),
    Embed(EmbedTranslation),
    Jcc(JCCTranslation),
    Control(ControlTranslation),
    Relative(RelativeTranslation),
    Near(NearTranslation),
}

impl Translation {
    pub fn rva(&self) -> u64 {
        self.instruction().ip()
    }

    pub fn buffer(&self, assume_jumps_are_near: bool) -> Result<Vec<u8>, iced_x86::IcedError> {
        match self {
            Translation::Default(default_translation) => default_translation.buffer(),
            Translation::Embed(embed_translation) => embed_translation.buffer(),
            Translation::Jcc(jcc_translation) => jcc_translation.buffer(assume_jumps_are_near),
            Translation::Control(control_translation) => {
                control_translation.buffer(assume_jumps_are_near)
            }
            Translation::Relative(relative_translation) => relative_translation.buffer(),
            Translation::Near(near_translation) => near_translation.buffer(),
        }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        match self {
            Translation::Default(default_translation) => default_translation.resolve(rel_op_ip),
            Translation::Embed(embed_translation) => embed_translation.resolve(rel_op_ip),
            Translation::Jcc(jcc_translation) => jcc_translation.resolve(rel_op_ip),
            Translation::Control(control_translation) => control_translation.resolve(rel_op_ip),
            Translation::Relative(relative_translation) => relative_translation.resolve(rel_op_ip),
            Translation::Near(near_translation) => near_translation.resolve(rel_op_ip),
        }
    }

    pub fn instruction(&self) -> Instruction {
        match self {
            Translation::Default(default_translation) => default_translation.instruction(),
            Translation::Embed(embed_translation) => embed_translation.instruction(),
            Translation::Jcc(jcc_translation) => jcc_translation.instruction(),
            Translation::Control(control_translation) => control_translation.instruction(),
            Translation::Relative(relative_translation) => relative_translation.instruction(),
            Translation::Near(near_translation) => near_translation.instruction(),
        }
    }

    pub fn mapped(&self) -> u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped(),
            Translation::Embed(embed_translation) => embed_translation.mapped(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped(),
            Translation::Control(control_translation) => control_translation.mapped(),
            Translation::Relative(relative_translation) => relative_translation.mapped(),
            Translation::Near(near_translation) => near_translation.mapped(),
        }
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped_mut(),
            Translation::Embed(embed_translation) => embed_translation.mapped_mut(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped_mut(),
            Translation::Control(control_translation) => control_translation.mapped_mut(),
            Translation::Relative(relative_translation) => relative_translation.mapped_mut(),
            Translation::Near(near_translation) => near_translation.mapped_mut(),
        }
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        match self {
            Translation::Default(default_translation) => default_translation.rel_op_rva(),
            Translation::Embed(embed_translation) => embed_translation.rel_op_rva(),
            Translation::Jcc(jcc_translation) => jcc_translation.rel_op_rva(),
            Translation::Control(control_translation) => control_translation.rel_op_rva(),
            Translation::Relative(relative_translation) => relative_translation.rel_op_rva(),
            Translation::Near(near_translation) => near_translation.rel_op_rva(),
        }
    }

    pub fn set_obfuscation_offset(&mut self, obfuscation_offset: u32) {
        match self {
            Translation::Relative(relative_translation) => {
                relative_translation.set_obfuscation_offset(obfuscation_offset)
            }
            Translation::Near(near_translation) => {
                near_translation.set_obfuscation_offset(obfuscation_offset)
            }
            _ => {}
        }
    }

    pub fn buffer_size(
        &mut self,
        assume_jumps_are_near: bool,
    ) -> Result<usize, iced_x86::IcedError> {
        match self {
            Translation::Near(near_translation) => near_translation.buffer_size(),
            _ => self
                .buffer(assume_jumps_are_near)
                .and_then(|buffer| Ok(buffer.len())),
        }
    }

    pub fn find_first_translation_rva<'a>(
        translations: &'a [Self],
        rva_to_find: u64,
    ) -> Option<&'a Self> {
        let mut first = 0isize;
        let mut last = translations.len() as isize - 1;
        let mut first_occurrence = None;

        while first <= last {
            let mid_index = (first + last) / 2;
            let cur_rva = translations[mid_index as usize].rva();

            if cur_rva == rva_to_find {
                first_occurrence = Some(&translations[mid_index as usize]);
                last = mid_index - 1;
            } else if cur_rva < rva_to_find {
                first = mid_index + 1;
            } else {
                last = mid_index - 1;
            }
        }

        return first_occurrence;
    }

    pub fn get_rel_offset_near(target_address: u64, next_ip: u64) -> Result<i32, PSMError> {
        let rel_offset = target_address.wrapping_sub(next_ip);
        let is_valid =
            (rel_offset as i64) >= (i32::MIN as i64) && (rel_offset as i64) <= (i32::MAX as i64);

        is_valid
            .then_some(rel_offset as i32)
            .ok_or(PSMError::BadRelativeOffset(
                next_ip,
                target_address,
                rel_offset,
            ))
    }

    pub fn translate_rva_to_mapped(
        pe: &PE64,
        translations: &[Self],
        symbols: &[(std::ops::Range<usize>, MappedBlock)],
        mut rva_to_find: u64,
    ) -> Result<u64, PSMError> {
        if pe.is_obfuscated() {
            let target_section = pe
                .iter_find_section(|section| section.contains_rva(rva_to_find as usize))
                .ok_or(PSMError::RVANotFound(rva_to_find))?;

            if target_section.name == ".text" {
                let mut decoder = Decoder::new(
                    64,
                    pe.get_data_from_rva(rva_to_find as usize, 5 /*size of jump*/)?,
                    0,
                );
                decoder.set_ip(rva_to_find);

                let jmp_instr = decoder.decode();

                if jmp_instr.mnemonic() == iced_x86::Mnemonic::Ret {
                    let ret_translations = translations
                        .iter()
                        .filter(|translation| {
                            translation.instruction().mnemonic() == iced_x86::Mnemonic::Ret
                        })
                        .collect::<Vec<_>>();

                    if ret_translations.is_empty() {
                        return Err(PSMError::ExpectedJump(rva_to_find));
                    }

                    return Ok(ret_translations
                        [rand::rng().next_u64() as usize % ret_translations.len()]
                    .mapped());
                } else if jmp_instr.mnemonic() != iced_x86::Mnemonic::Jmp {
                    return Err(PSMError::ExpectedJump(rva_to_find));
                }

                rva_to_find = jmp_instr.ip_rel_memory_address();
            }
        }

        Translation::find_first_translation_rva(translations, rva_to_find)
            .and_then(|translation| Some(translation.mapped()))
            .or(
                Mapper::find_symbol_by_rva(symbols, rva_to_find as usize).map(
                    |(rva_range, mapped_block)| {
                        mapped_block.address + (rva_to_find as usize - rva_range.start) as u64
                    },
                ),
            )
            .ok_or_else(|| PSMError::TranslationFail(rva_to_find))
        //.ok_or(PSMError::TranslationFail(rva_to_find))
    }
}

#[derive(Clone)]
pub struct DefaultTranslation {
    mapped_va: u64,
    pub instruction: iced_x86::Instruction,
}

impl DefaultTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self {
            mapped_va: 0,
            instruction,
        }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {}

    pub fn rel_op_rva(&self) -> Option<u64> {
        None
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.instruction
    }

    pub fn mapped(&self) -> u64 {
        self.mapped_va
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        &mut self.mapped_va
    }

    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        //println!("{}", &self.instruction);
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}

#[derive(Clone)]
pub struct EmbedTranslation {
    mapped_va: u64,
    pub instruction: iced_x86::Instruction,
}

impl EmbedTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self {
            mapped_va: 0,
            instruction,
        }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {}

    pub fn rel_op_rva(&self) -> Option<u64> {
        None
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.instruction
    }

    pub fn mapped(&self) -> u64 {
        self.mapped_va
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        &mut self.mapped_va
    }

    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let ip = self.instruction.ip();
        let len = self.instruction.len();

        if len <= 4 {
            let mut encoder = Encoder::new(64);
            encoder.encode(&self.instruction, ip).unwrap();
            let bytes_remaining = 4 - self.instruction.len() as u8;
            let mut embed = vec![
                0xEB,
                0x01 + bytes_remaining,
                0xB8 + (ip % (0xBF - 0xB8)) as u8,
                0x00,
                0x00,
                0x00,
                0x00,
            ];
            let buffer = encoder.take_buffer();
            embed
                [(0x3 + bytes_remaining as usize)..(0x3 + bytes_remaining as usize + buffer.len())]
                .copy_from_slice(&buffer);
            Ok(embed)
        } else {
            let mut encoder = Encoder::new(64);
            encoder.encode(&self.instruction, ip).unwrap();
            let bytes_remaining = 8 - self.instruction.len() as u8;
            let mut embed = vec![
                0xEB,
                0x02 + bytes_remaining,
                0x48,
                0xB8 + (ip % (0xBF - 0xB8)) as u8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ];
            let buffer = encoder.take_buffer();
            embed
                [(0x4 + bytes_remaining as usize)..(0x4 + bytes_remaining as usize + buffer.len())]
                .copy_from_slice(&buffer);
            Ok(embed)
        }
    }
}

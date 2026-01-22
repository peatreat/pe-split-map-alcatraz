use core::panic;
use std::{
    f32::consts::E,
    fs, io,
    mem::{self, offset_of},
};

use iced_x86::{
    code_asm::{
        get_gpr16, get_gpr32, get_gpr64, get_gpr8, qword_ptr, rax, rdx, rsp, AsmRegister64,
        CodeAssembler,
    },
    Code, Decoder, Encoder, Instruction,
};
use rand::{rng, rngs::ReseedingRng, Rng};

use crate::{
    pe64::{
        headers::{
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_SECTION_HEADER,
        },
        section::Section,
        translation::{
            near::NearTranslation, ControlTranslation, DefaultTranslation, JCCTranslation,
            RelativeTranslation, Translation,
        },
    },
    psm_error::PSMError,
    translation::EmbedTranslation,
};

pub mod data_directory;
mod headers;
pub mod mapper;
mod section;
pub mod symbols;
pub mod translation;

use iced_x86::*;

pub struct PE64 {
    _raw: Vec<u8>,
    obfuscated: bool,
    embed_instructions: bool,
    lea: bool,
    mov: bool,
    xor: bool,
    shx: bool,
}

impl PE64 {
    pub fn new(
        path: &str,
        obfuscated: bool,
        embed_instructions: bool,
        lea: bool,
        mov: bool,
        xor: bool,
        shx: bool,
    ) -> Result<Self, PSMError> {
        let bytes = fs::read(path)?;

        PE64::new_from_bytes(bytes, obfuscated, embed_instructions, lea, mov, xor, shx)
    }

    pub fn new_from_bytes(
        bytes: Vec<u8>,
        obfuscated: bool,
        embed_instructions: bool,
        lea: bool,
        mov: bool,
        xor: bool,
        shx: bool,
    ) -> Result<Self, PSMError> {
        // check if valid pe by checking e_magic in DOS header
        if bytes.len() < mem::size_of::<IMAGE_DOS_HEADER>() || bytes[0] != 0x4D || bytes[1] != 0x5A
        {
            return Err(PSMError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                "File is not a valid PE",
            )));
        }

        let pe = PE64 {
            _raw: bytes,
            obfuscated,
            embed_instructions,
            lea,
            mov,
            xor,
            shx,
        };

        // check if 64-bit
        if !pe.is_64() {
            return Err(PSMError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                "File is not a valid PE64",
            )));
        }

        Ok(pe)
    }

    pub fn is_obfuscated(&self) -> bool {
        self.obfuscated
    }

    pub fn dos<'a>(&self) -> &'a IMAGE_DOS_HEADER {
        // parse dos
        unsafe { &*(self._raw.as_ptr() as *const IMAGE_DOS_HEADER) }
    }

    pub fn nt64<'a>(&self) -> &'a IMAGE_NT_HEADERS64 {
        // parse nt 64-bit
        unsafe {
            &*(self._raw.as_ptr().add(self.dos().e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
        }
    }

    fn is_64(&self) -> bool {
        self.nt64().OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    pub fn image_base(&self) -> u64 {
        self.nt64().OptionalHeader.ImageBase
    }

    pub fn rva_to_offset(&self, rva: usize) -> Result<usize, PSMError> {
        self.iter_find_section(|section| section.contains_rva(rva))
            .map(|section| {
                let offset_within_section = rva - section.virtual_address;
                let section_raw_offset =
                    section._raw.as_ptr() as usize - self._raw.as_ptr() as usize;
                section_raw_offset + offset_within_section
            })
            .ok_or(PSMError::RVANotFound(rva as u64))
    }

    pub fn get_ref_from_rva<'a, T>(&'a self, rva: usize) -> Result<&'a T, PSMError> {
        let offset = self.rva_to_offset(rva)?;

        if offset + mem::size_of::<T>() > self._raw.len() {
            return Err(PSMError::InvalidRVA(rva as u64));
        }

        Ok(unsafe { &*(self._raw.as_ptr().add(offset) as *const T) })
    }

    pub fn get_data_from_rva(&self, rva: usize, size: usize) -> Result<&[u8], PSMError> {
        let offset = self
            .iter_find_section(|section| {
                section.contains_rva(rva)
                    && rva + size <= section.virtual_address + section._raw.len()
            })
            .map(|section| {
                let offset_within_section = rva - section.virtual_address;
                let section_raw_offset =
                    section._raw.as_ptr() as usize - self._raw.as_ptr() as usize;
                section_raw_offset + offset_within_section
            })
            .ok_or(PSMError::RVANotFound(rva as u64))?;

        Ok(&self._raw[offset..offset + size])
    }

    pub fn get_string_size(&self, rva: usize) -> Result<usize, PSMError> {
        let mut offset = self.rva_to_offset(rva)?;

        let mut size = 1; // start with 1 to account for null terminator

        while offset < self._raw.len() {
            let byte = self
                ._raw
                .get(offset)
                .ok_or(PSMError::InvalidRVA(rva as u64 + offset as u64))?;

            if *byte == 0 {
                break;
            }

            size += 1;
            offset += 1;
        }

        Ok(size)
    }

    pub fn iter_find_section<F>(&self, mut closure: F) -> Option<Section<'_>>
    where
        F: FnMut(&Section) -> bool,
    {
        let number_of_sections = self.nt64().FileHeader.NumberOfSections;

        let first_section_offset = self.dos().e_lfanew as usize
            + offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) as usize
            + self.nt64().FileHeader.SizeOfOptionalHeader as usize;

        let section_size = mem::size_of::<IMAGE_SECTION_HEADER>();

        for i in 0..number_of_sections {
            let section_offset = first_section_offset + (i as usize * section_size);
            let section = unsafe {
                &*(self._raw.as_ptr().add(section_offset) as *const IMAGE_SECTION_HEADER)
            };

            let section = Section::from((self._raw.as_slice(), section));

            if closure(&section) {
                return Some(section);
            }
        }

        None
    }

    fn get_unused_gpr64(&self, instruction: &iced_x86::Instruction) -> Option<iced_x86::Register> {
        let mut unused = [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RSP,
            Register::RBP,
            Register::RSI,
            Register::RDI,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ];

        for i in 0..instruction.op_count() {
            if instruction.op_kind(i) == OpKind::Register {
                let mut op_reg = instruction.op_register(i);

                if op_reg.is_gpr() {
                    op_reg = op_reg.full_register();
                    unused[op_reg.number() as usize] = Register::None;
                }
            }
        }

        unused.iter().find(|reg| **reg != Register::None).copied()
    }

    fn find_code_for_operands(
        &self,
        mnemonic: &iced_x86::Mnemonic,
        operands: &[OpCodeOperandKind],
    ) -> Option<Code> {
        for code in Code::values() {
            let op_kinds = code.op_code().op_kinds();

            if code.mnemonic() == *mnemonic && op_kinds.len() == operands.len() {
                let op_kinds_equal = op_kinds.iter().eq(operands.iter());

                if op_kinds_equal {
                    return Some(code);
                }
            }
        }

        None
    }

    fn obf_xor(a: &mut CodeAssembler, inst: &mut Instruction) -> Option<Instruction> {
        let mut was_obfuscated = false;

        let op_kind0 = inst.op_kind(0);
        let op_kind1 = inst.op_kind(1);

        if op_kind0 == OpKind::Register && op_kind1 == OpKind::Register {
            let op_reg0 = inst.op_register(0);
            let op_reg1 = inst.op_register(1);

            if op_reg0.is_gpr() && op_reg0 == op_reg1 {
                was_obfuscated = true;

                if let Some(r) = get_gpr8(op_reg0) {
                    a.mov(r, 0).unwrap();
                } else if let Some(r) = get_gpr16(op_reg0) {
                    a.mov(r, 0).unwrap();
                } else if let Some(r) = get_gpr32(op_reg0) {
                    a.mov(r, 0).unwrap();
                } else if let Some(r) = get_gpr64(op_reg0) {
                    a.mov(r, 0u64).unwrap();
                }
            }
        }

        if was_obfuscated {
            Some(a.instructions()[0])
        } else {
            None
        }
    }

    fn obf_mov(
        a: &mut CodeAssembler,
        inst: &mut Instruction,
        preserve_flags: bool,
    ) -> Vec<Instruction> {
        let mut was_obfuscated = false;
        let mut added_mov_instr = false;

        let op_kind0 = inst.op_kind(0);

        if op_kind0 == OpKind::Register {
            let op_kind1 = inst.op_kind(1);
            let reg = inst.op0_register();

            if reg.is_gpr() {
                was_obfuscated = true;

                // let rounds = rng().random_range(1..=1);
                let rounds = 1;

                for _ in 0..rounds {
                    let mut vals: Vec<[usize; 7]> = Vec::new();

                    match op_kind1 {
                        OpKind::Immediate8 => {
                            let x = [
                                rng().random_range(0..=u8::MAX as usize / 2),
                                rng().random_range(1..=u8::MAX as usize),
                                rng().random_range(1..=64),
                                rng().random_range(0..=2),
                                rng().random_range(0..=2),
                                rng().random_range(0..=1),
                                rng().random_range(0..=1),
                            ];

                            let mut v = inst.immediate8();
                            if x[4] == 0 {
                                v = v.rotate_left(x[2] as u32);
                            } else if x[4] == 1 {
                                v = v.rotate_right(x[2] as u32);
                            }
                            if x[5] == 1 {
                                v ^= x[1] as u8;
                            }
                            if x[3] == 0 {
                                v = v.wrapping_sub(x[0] as u8);
                            } else if x[3] == 1 {
                                v = v.wrapping_add(x[0] as u8);
                            }
                            if x[6] == 1 {
                                v = !v;
                            }

                            inst.set_immediate8(v);

                            vals.push(x);
                        }
                        OpKind::Immediate16 => {
                            let x = [
                                rng().random_range(0..=i16::MAX as usize / 2),
                                rng().random_range(i16::MAX as usize / 2..=i16::MAX as usize),
                                rng().random_range(1..=64),
                                rng().random_range(0..=2),
                                rng().random_range(0..=2),
                                rng().random_range(0..=1),
                                rng().random_range(0..=1),
                            ];

                            let mut v = inst.immediate16();
                            if x[4] == 0 {
                                v = v.rotate_left(x[2] as u32);
                            } else if x[4] == 1 {
                                v = v.rotate_right(x[2] as u32);
                            }
                            if x[5] == 1 {
                                v ^= x[1] as u16;
                            }
                            if x[3] == 0 {
                                v = v.wrapping_sub(x[0] as u16);
                            } else if x[3] == 1 {
                                v = v.wrapping_add(x[0] as u16);
                            }
                            if x[6] == 1 {
                                v = !v;
                            }

                            inst.set_immediate16(v);

                            vals.push(x);
                        }
                        OpKind::Immediate32 => {
                            let x = [
                                rng().random_range(0..=u32::MAX as usize / 2),
                                rng().random_range(u32::MAX as usize / 2..=u32::MAX as usize),
                                rng().random_range(1..=64),
                                rng().random_range(0..=2),
                                rng().random_range(0..=2),
                                rng().random_range(0..=1),
                                rng().random_range(0..=1),
                            ];

                            let mut v = inst.immediate32();
                            if x[4] == 0 {
                                v = v.rotate_left(x[2] as u32);
                            } else if x[4] == 1 {
                                v = v.rotate_right(x[2] as u32);
                            }
                            if x[5] == 1 {
                                v ^= x[1] as u32;
                            }
                            if x[3] == 0 {
                                v = v.wrapping_sub(x[0] as u32);
                            } else if x[3] == 1 {
                                v = v.wrapping_add(x[0] as u32);
                            }
                            if x[6] == 1 {
                                v = !v;
                            }

                            inst.set_immediate32(v);

                            vals.push(x);
                        }
                        OpKind::Immediate64 => {
                            let x = [
                                rng().random_range(0..=i32::MAX as usize / 2),
                                rng().random_range(i32::MAX as usize / 2..=i32::MAX as usize),
                                rng().random_range(1..=64),
                                rng().random_range(0..=2),
                                rng().random_range(0..=2),
                                rng().random_range(0..=1),
                                rng().random_range(0..=1),
                            ];

                            let mut v = inst.immediate64();
                            if x[4] == 0 {
                                v = v.rotate_left(x[2] as u32);
                            } else if x[4] == 1 {
                                v = v.rotate_right(x[2] as u32);
                            }
                            if x[5] == 1 {
                                v ^= x[1] as u64;
                            }
                            if x[3] == 0 {
                                v = v.wrapping_sub(x[0] as u64);
                            } else if x[3] == 1 {
                                v = v.wrapping_add(x[0] as u64);
                            }
                            if x[6] == 1 {
                                v = !v;
                            }

                            inst.set_immediate64(v);

                            vals.push(x);
                        }
                        _ => {
                            was_obfuscated = false;
                            break;

                            // [0, 0, 0]
                        }
                    };

                    //

                    if was_obfuscated {
                        use iced_x86::code_asm::*;

                        if !added_mov_instr {
                            added_mov_instr = true;
                            a.add_instruction(*inst).unwrap();

                            if preserve_flags {
                                a.pushf().unwrap();
                            }
                        }

                        vals.reverse();

                        for [add_val, xor_val, rot_val, is_sub, is_rotl, should_xor_val, should_not_val] in
                            vals
                        {
                            if let Some(r) = get_gpr8(reg) {
                                if should_not_val != 0 {
                                    a.not(r).unwrap();
                                }
                                if is_sub == 1 {
                                    a.sub(r, add_val as u32).unwrap();
                                } else if is_sub == 0 {
                                    a.add(r, add_val as u32).unwrap();
                                }
                                if should_xor_val != 0 {
                                    a.xor(r, xor_val as u32).unwrap();
                                }
                                if is_rotl == 1 {
                                    a.rol(r, rot_val as u32).unwrap();
                                } else if is_rotl == 0 {
                                    a.ror(r, rot_val as u32).unwrap();
                                }
                            } else if let Some(r) = get_gpr16(reg) {
                                if should_not_val != 0 {
                                    a.not(r).unwrap();
                                }
                                if is_sub == 1 {
                                    a.sub(r, add_val as u32).unwrap();
                                } else if is_sub == 0 {
                                    a.add(r, add_val as u32).unwrap();
                                }
                                if should_xor_val != 0 {
                                    a.xor(r, xor_val as u32).unwrap();
                                }
                                if is_rotl == 1 {
                                    a.rol(r, rot_val as u32).unwrap();
                                } else if is_rotl == 0 {
                                    a.ror(r, rot_val as u32).unwrap();
                                }
                            } else if let Some(r) = get_gpr32(reg) {
                                if should_not_val != 0 {
                                    a.not(r).unwrap();
                                }
                                if is_sub == 1 {
                                    a.sub(r, add_val as u32).unwrap();
                                } else if is_sub == 0 {
                                    a.add(r, add_val as u32).unwrap();
                                }
                                if should_xor_val != 0 {
                                    a.xor(r, xor_val as u32).unwrap();
                                }
                                if is_rotl == 1 {
                                    a.rol(r, rot_val as u32).unwrap();
                                } else if is_rotl == 0 {
                                    a.ror(r, rot_val as u32).unwrap();
                                }
                            } else if let Some(r) = get_gpr64(reg) {
                                if should_not_val != 0 {
                                    a.not(r).unwrap();
                                }
                                if is_sub == 1 {
                                    a.sub(r, add_val as i32).unwrap();
                                } else if is_sub == 0 {
                                    a.add(r, add_val as i32).unwrap();
                                }
                                if should_xor_val != 0 {
                                    a.xor(r, xor_val as i32).unwrap();
                                }
                                if is_rotl == 1 {
                                    a.rol(r, rot_val as u32).unwrap();
                                } else if is_rotl == 0 {
                                    a.ror(r, rot_val as u32).unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }

        if preserve_flags {
            a.popf().unwrap();
        }

        if was_obfuscated {
            let mut instructions = a.take_instructions();
            let new_instruction = &mut instructions[0];

            match new_instruction.op_kind(1) {
                OpKind::Immediate8 => {
                    new_instruction.set_immediate8(inst.immediate8());
                }
                OpKind::Immediate16 => {
                    new_instruction.set_immediate16(inst.immediate16());
                }
                OpKind::Immediate32 => {
                    new_instruction.set_immediate32(inst.immediate32());
                }
                OpKind::Immediate64 => {
                    new_instruction.set_immediate64(inst.immediate64());
                }
                OpKind::Immediate32to64 => {
                    new_instruction.set_immediate32to64(inst.immediate32to64());
                }
                OpKind::Immediate8to64 => {
                    new_instruction.set_immediate8to64(inst.immediate8to64());
                }
                _ => panic!("Invalid opkind for mov {:?}", new_instruction.op1_kind()),
            }

            instructions
        } else {
            Vec::new()
        }
    }

    fn obf_shl(
        a: &mut CodeAssembler,
        inst: &mut Instruction,
        preserve_flags: bool,
    ) -> Vec<Instruction> {
        let mut was_obfuscated = false;

        let op_kind0 = inst.op_kind(0);
        let op_kind1 = inst.op_kind(1);
        let divisor = 2u64.pow(inst.immediate8() as u32);

        if op_kind0 == OpKind::Register
            && op_kind1 == OpKind::Immediate8
            && divisor <= u32::MAX as u64
        {
            let reg = inst.op0_register();

            if let Some(r) = get_gpr64(reg) {
                was_obfuscated = true;

                a.sub(rsp, 0x8).unwrap();
                if preserve_flags {
                    a.pushf().unwrap();
                }
                a.push(rax).unwrap();
                a.push(rdx).unwrap();
                if r != rax {
                    if rng().random_range(0..=1) == 0 {
                        a.xchg(r, rax).unwrap();
                    } else {
                        a.xchg(rax, r).unwrap();
                    }
                }
                let mut tmp_a = CodeAssembler::new(64).unwrap();
                tmp_a.mov(r, 2u64.pow(inst.immediate8() as u32)).unwrap();
                let mut tmp_a = tmp_a.take_instructions();
                for i in Self::obf_mov(a, &mut tmp_a[0], false) {
                    a.add_instruction(i).unwrap();
                }
                a.mul(r).unwrap();
                if r != rax {
                    if rng().random_range(0..=1) == 0 {
                        a.xchg(r, rax).unwrap();
                    } else {
                        a.xchg(rax, r).unwrap();
                    }
                }
                if preserve_flags {
                    a.mov(qword_ptr(rsp + 0x8 * 3), r).unwrap();
                } else {
                    a.mov(qword_ptr(rsp + 0x8 * 2), r).unwrap();
                }
                a.pop(rdx).unwrap();
                a.pop(rax).unwrap();
                if preserve_flags {
                    a.popf().unwrap();
                }
                if rng().random_range(0..=1) == 0 {
                    a.mov(r, qword_ptr(rsp)).unwrap();
                    a.add(rsp, 0x8).unwrap();
                } else {
                    a.add(rsp, 0x8).unwrap();
                    a.mov(r, qword_ptr(rsp - 0x8)).unwrap();
                }
            }
        }

        if was_obfuscated {
            a.take_instructions()
        } else {
            Vec::new()
        }
    }

    fn obf_shr(
        a: &mut CodeAssembler,
        inst: &mut Instruction,
        preserve_flags: bool,
    ) -> Vec<Instruction> {
        let mut was_obfuscated = false;

        let op_kind0 = inst.op_kind(0);
        let op_kind1 = inst.op_kind(1);
        let divisor = 2u64.pow(inst.immediate8() as u32);

        if op_kind0 == OpKind::Register
            && op_kind1 == OpKind::Immediate8
            && divisor <= u32::MAX as u64
            && divisor != 0
        {
            let reg = inst.op0_register();

            if let Some(r) = get_gpr64(reg) {
                was_obfuscated = true;

                a.sub(rsp, 0x8).unwrap();
                if preserve_flags {
                    a.pushf().unwrap();
                }
                a.push(rax).unwrap();
                a.push(rdx).unwrap();
                if r != rax {
                    if rng().random_range(0..=1) == 0 {
                        a.xchg(r, rax).unwrap();
                    } else {
                        a.xchg(rax, r).unwrap();
                    }
                }
                let mut tmp_a = CodeAssembler::new(64).unwrap();
                tmp_a.mov(r, divisor).unwrap();
                let mut tmp_a = tmp_a.take_instructions();
                for i in Self::obf_mov(a, &mut tmp_a[0], false) {
                    a.add_instruction(i).unwrap();
                }
                a.div(r).unwrap();
                if r != rax {
                    if rng().random_range(0..=1) == 0 {
                        a.xchg(r, rax).unwrap();
                    } else {
                        a.xchg(rax, r).unwrap();
                    }
                }
                if preserve_flags {
                    a.mov(qword_ptr(rsp + 0x8 * 3), r).unwrap();
                } else {
                    a.mov(qword_ptr(rsp + 0x8 * 2), r).unwrap();
                }
                a.pop(rdx).unwrap();
                a.pop(rax).unwrap();
                // a.sub(rsp, 0x8 * 2);
                if preserve_flags {
                    a.popf().unwrap();
                }
                if rng().random_range(0..=1) == 0 {
                    a.mov(r, qword_ptr(rsp)).unwrap();
                    a.add(rsp, 0x8).unwrap();
                } else {
                    a.add(rsp, 0x8).unwrap();
                    a.mov(r, qword_ptr(rsp - 0x8)).unwrap();
                }
            }
        }

        if was_obfuscated {
            a.take_instructions()
        } else {
            Vec::new()
        }
    }

    fn add_default_translation(
        &self,
        decoder: &mut Decoder,
        mut instruction: iced_x86::Instruction,
        translations: &mut Vec<Translation>,
    ) -> Result<(), iced_x86::IcedError> {
        if self.embed_instructions && instruction.len() <= rng().random_range(0..=8) {
            translations.push(Translation::Embed(EmbedTranslation::new(instruction)));
        } else {
            let mnemonic = instruction.mnemonic();

            let flags_modified = instruction.rflags_modified();
            let mut cummulative_flags_modified = 0;
            let mut preserve_flags = true;

            let mut scan_forward = 0;
            while decoder.can_decode() && scan_forward < 10 {
                let next_inst = decoder.decode();
                scan_forward += 1;

                // instruction reads rflags (like cmp), our flags must be backed up
                if next_inst.rflags_read() != 0 {
                    break;
                }

                let op_kind = next_inst.op_kind(0);

                if op_kind == OpKind::FarBranch16
                    || op_kind == OpKind::FarBranch32
                    || op_kind == OpKind::NearBranch16
                    || op_kind == OpKind::NearBranch32
                    || op_kind == OpKind::NearBranch64
                {
                    break;
                }

                if next_inst.mnemonic() == Mnemonic::Call {
                    decoder.set_ip(next_inst.near_branch_target());

                    continue;
                }

                cummulative_flags_modified |= next_inst.rflags_modified();

                // flags get completely overwritten before rflags read, flags can be discarded
                if flags_modified & cummulative_flags_modified == flags_modified {
                    preserve_flags = false;
                    break;
                }
            }

            if self.mov && mnemonic == Mnemonic::Mov {
                let mut a = CodeAssembler::new(64).unwrap();
                let instructions = Self::obf_mov(&mut a, &mut instruction, preserve_flags);

                if instructions.is_empty() {
                    translations.push(Translation::Default(DefaultTranslation::new(instruction)));
                } else {
                    for mut new_instruction in instructions {
                        new_instruction.set_ip(instruction.ip());

                        translations.push(Translation::Default(DefaultTranslation::new(
                            new_instruction,
                        )));
                    }
                }
            } else if self.xor && mnemonic == Mnemonic::Xor {
                let mut a = CodeAssembler::new(64).unwrap();
                let instructions = Self::obf_xor(&mut a, &mut instruction);

                if let Some(mut new_instruction) = instructions {
                    new_instruction.set_ip(instruction.ip());
                    translations.push(Translation::Default(DefaultTranslation::new(
                        new_instruction,
                    )));
                } else {
                    translations.push(Translation::Default(DefaultTranslation::new(instruction)));
                }
            } else if self.shx && mnemonic == Mnemonic::Shl {
                let mut a = CodeAssembler::new(64).unwrap();
                let mut instr = instruction;
                let instructions = Self::obf_shl(&mut a, &mut instr, preserve_flags);

                if instructions.is_empty() {
                    translations.push(Translation::Default(DefaultTranslation::new(instruction)));
                } else {
                    for mut new_instruction in instructions {
                        new_instruction.set_ip(instruction.ip());

                        translations.push(Translation::Default(DefaultTranslation::new(
                            new_instruction,
                        )));
                    }
                }
            }
            // else if self.shx && mnemonic == Mnemonic::Shr {
            //     let mut a = CodeAssembler::new(64).unwrap();
            //     let mut instr = instruction;
            //     let instructions = Self::obf_shr(&mut a, &mut instr, preserve_flags);

            //     if instructions.is_empty() {
            //         translations.push(Translation::Default(DefaultTranslation::new(instruction)));
            //     } else {
            //         for mut new_instruction in instructions {
            //             new_instruction.set_ip(instruction.ip());

            //             translations.push(Translation::Default(DefaultTranslation::new(
            //                 new_instruction,
            //             )));
            //         }
            //     }
            // }
            else if self.lea && mnemonic == Mnemonic::Lea {
                let offset32 = rng().random_range((i32::MIN / 2)..=(i32::MAX / 2));
                let disp = instruction.memory_displacement64();
                let new_disp = disp.wrapping_add_signed(offset32 as i64);

                instruction.set_memory_displ_size(8);
                instruction.set_memory_displacement64(new_disp);

                // instruction
                translations.push(Translation::Default(DefaultTranslation::new(instruction)));

                if preserve_flags {
                    let mut i = Instruction::with(Code::Pushfq);
                    i.set_ip(instruction.ip());
                    translations.push(Translation::Default(DefaultTranslation::new(i)));
                }

                if (new_disp as i32) < 0 {
                    let mut i = Instruction::with2(
                        Code::Add_rm64_imm32,
                        instruction.op0_register().full_register(),
                        -offset32,
                    )?;
                    i.set_ip(instruction.ip());
                    // println!("{i}");

                    translations.push(Translation::Default(DefaultTranslation::new(i)));
                } else {
                    let mut i = Instruction::with2(
                        Code::Sub_rm64_imm32,
                        instruction.op0_register().full_register(),
                        offset32,
                    )?;
                    i.set_ip(instruction.ip());
                    // println!("{i}");

                    translations.push(Translation::Default(DefaultTranslation::new(i)));
                }

                if preserve_flags {
                    let mut i = Instruction::with(Code::Popfq);
                    i.set_ip(instruction.ip());
                    translations.push(Translation::Default(DefaultTranslation::new(i)));
                }
            } else {
                translations.push(Translation::Default(DefaultTranslation::new(instruction)));
            }
        }

        Ok(())
    }

    /*
    reserve for all translations (for executable translations we reserve buffer size + far jump size) (for symbol translations we reserve buffer size)

    all reservations will be done in random order so first we create a vector of references to the translations, shuffle that vector, and iterate through it and call the reserve() method

    now all translations will be in random locations. thing is this is poor for speed of executable translations

    for executable translations lets put them in blocks of n instructions where a block holds the references of those translations but the blocks are in a vector that gets shuffled

    that way we can reserve in blocks

    block batching can either be None, NumberOfInstructions, or TotalSizeOfInstructions
    */

    fn add_relative_translation(
        &self,
        mut instruction: iced_x86::Instruction,
        translations: &mut Vec<Translation>,
        assume_near: bool,
        prev_obfuscated_lea: &mut Option<usize>,
    ) -> Result<(), iced_x86::IcedError> {
        match instruction.mnemonic() {
            iced_x86::Mnemonic::Lea => {
                if self.obfuscated {
                    *prev_obfuscated_lea = Some(translations.len());
                }

                if assume_near {
                    translations.push(Translation::Near(NearTranslation::new(instruction)));
                    return Ok(());
                }

                instruction.set_code(Code::Mov_r64_imm64); // change it to: mov r64, imm64
                instruction.set_op1_kind(OpKind::Immediate64);
                instruction.set_immediate64(instruction.ip_rel_memory_address());

                translations.push(Translation::Relative(RelativeTranslation::new(instruction)));
            }
            iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Call => {
                if assume_near {
                    translations.push(Translation::Near(NearTranslation::new(instruction)));
                    return Ok(());
                }

                //println!(" {:X} jmp kind: {:?}, instr: {}", instruction.ip(), instruction.op0_kind(), instruction);
                let mut mov_instruction = Instruction::with2(
                    Code::Mov_r64_imm64,
                    Register::R11,
                    instruction.ip_rel_memory_address(),
                )?;
                mov_instruction.set_ip(instruction.ip());

                let mnemonic = if instruction.mnemonic() == iced_x86::Mnemonic::Jmp {
                    Code::Jmp_rm64
                } else {
                    Code::Call_rm64
                };

                let mut control_instruction = if instruction.op0_kind() == OpKind::NearBranch64 {
                    Instruction::with1(mnemonic, Register::R11)?
                } else {
                    Instruction::with1(
                        mnemonic,
                        MemoryOperand::new(
                            Register::R11,
                            Register::None,
                            1,
                            0,
                            0,
                            false,
                            Register::None,
                        ),
                    )?
                };

                control_instruction.set_ip(instruction.ip());

                translations.push(Translation::Control(ControlTranslation::new(
                    mov_instruction,
                    control_instruction,
                )));
            }
            iced_x86::Mnemonic::Jb
            | iced_x86::Mnemonic::Jbe
            | iced_x86::Mnemonic::Jcxz
            | iced_x86::Mnemonic::Jecxz
            | iced_x86::Mnemonic::Jknzd
            | iced_x86::Mnemonic::Jkzd
            | iced_x86::Mnemonic::Jl
            | iced_x86::Mnemonic::Jle
            | iced_x86::Mnemonic::Jae
            | iced_x86::Mnemonic::Ja
            | iced_x86::Mnemonic::Jge
            | iced_x86::Mnemonic::Jg
            | iced_x86::Mnemonic::Jno
            | iced_x86::Mnemonic::Jnp
            | iced_x86::Mnemonic::Jns
            | iced_x86::Mnemonic::Jo
            | iced_x86::Mnemonic::Jp
            | iced_x86::Mnemonic::Js
            | iced_x86::Mnemonic::Je
            | iced_x86::Mnemonic::Jne => {
                // right now the big problem here is we are creating new instructions that have branches to other new instructions and those new instructions don't have a proper IP
                // we should make a new translation type that holds these branches to these new instructions and when resolving we can set the proper IPs for them
                //let target = instruction.near_branch64();
                //println!("short branch before: {}, kind: {:?}", instruction, instruction.op0_kind());

                translations.push(Translation::Jcc(JCCTranslation::new(instruction)?));

                /*let encoded = jcc_translation.buffer()?;
                println!("encoded jcc bytes: {:x?}", encoded);
                let mut decoder = Decoder::new(64, &encoded, iced_x86::DecoderOptions::NONE);
                decoder.set_ip(0);
                while decoder.can_decode() {
                    let instruction = decoder.decode();
                    println!("[{:p}] decoded jcc instr: {}, kind: {:?}", instruction.ip() as *const usize, instruction, instruction.op0_kind());
                }*/

                //panic!();
                //println!("short branch after: {}, kind: {:?}", instruction, instruction.op0_kind());
            }
            _ => {
                if assume_near {
                    translations.push(Translation::Near(NearTranslation::new(instruction)));
                    return Ok(());
                }

                let unused_gpr64 = self.get_unused_gpr64(&instruction).unwrap();

                let mut push_instruction = Instruction::with1(Code::Push_r64, unused_gpr64)?;
                let mut mov_instruction = Instruction::with2(
                    Code::Mov_r64_imm64,
                    unused_gpr64,
                    instruction.ip_rel_memory_address(),
                )?;
                let mut pop_instruction = Instruction::with1(Code::Pop_r64, unused_gpr64)?;

                push_instruction.set_ip(instruction.ip());
                mov_instruction.set_ip(instruction.ip());
                pop_instruction.set_ip(instruction.ip());

                translations.push(Translation::Default(DefaultTranslation::new(
                    push_instruction,
                )));

                translations.push(Translation::Relative(RelativeTranslation::new(
                    mov_instruction,
                )));

                //println!("old instr: {}", instruction);

                instruction.set_memory_base(unused_gpr64);
                instruction.set_memory_displ_size(0);
                instruction.set_memory_displacement64(0);
                instruction.set_memory_index(Register::None);
                instruction.set_memory_index_scale(1);

                translations.push(Translation::Default(DefaultTranslation::new(instruction)));

                translations.push(Translation::Default(DefaultTranslation::new(
                    pop_instruction,
                )));

                /*for i in (translations.len() - 4)..translations.len() {
                    let encoded = translations[i].buffer()?;
                    let mut decoder = Decoder::new(64, &encoded, iced_x86::DecoderOptions::NONE);
                    decoder.set_ip(0);
                    while decoder.can_decode() {
                        let instruction = decoder.decode();
                        println!("[{:p}] decoded default instr: {}, kind: {:?}", instruction.ip() as *const usize, instruction, instruction.op1_kind());
                    }
                }

                panic!();*/
            }
        };

        Ok(())
    }

    fn add_switch_translation(
        &self,
        mut instruction: iced_x86::Instruction,
        translations: &mut Vec<Translation>,
    ) -> Result<(), iced_x86::IcedError> {
        if instruction.op_count() != 1 {
            panic!("unexpected number of operands");
        }

        /*
            obfuscator.exe jmp table instructions at 140027AAA

            jmp table at 140027C24
        */

        match instruction.op0_kind() {
            OpKind::Register => {
                for (i, translation) in translations.iter().enumerate().rev() {
                    if translation.instruction().op_count() != 2
                        || translation.instruction().op0_kind() != OpKind::Register
                        || translation.instruction().op0_register() != instruction.op0_register()
                    {
                        continue;
                    }

                    if translation.instruction().mnemonic() != Mnemonic::Add {
                        // we found a 2 operand instruction where dst operand is current register but it isn't ADD so it can't be a jump table
                        break;
                    }

                    // if prev instruction is not: add cur_reg, reg then it's not a jump table
                    if translation.instruction().op1_kind() != OpKind::Register {
                        break;
                        //panic!("unexpected instruction that uses jmp's register at {:p}", translation.instruction().ip() as *const usize);
                    }

                    // from here on out we can assume we are in a jump table

                    let index_register = translation.instruction().op1_register();
                    let movsxd = translations[i - 1].instruction();

                    if movsxd.mnemonic() != Mnemonic::Movsxd {
                        panic!(
                            "unexpected instruction that uses jmp's register at {:p}",
                            translation.instruction().ip() as *const usize
                        );
                    }

                    println!("{:?}", movsxd.memory_index());

                    //let mut mov_instruction = Instruction::with2(Code::Mov_r64_imm64, index_register, instruction.near_branch64())?;
                    //mov_instruction.set_ip(instruction.ip());
                    //
                    //let mut control_instruction = Instruction::with1(Code::Jmp_rm64, index_register)?;
                    //
                    //control_instruction.set_ip(instruction.ip());
                    //
                    //translations.push(Box::new(translation::ControlTranslation {
                    //    mov_instruction,
                    //    control_instruction,
                    //}));

                    todo!("implement jump table support by getting index register from ADD instruction");
                }

                translations.push(Translation::Default(DefaultTranslation::new(instruction)));

                Ok(())
            }
            OpKind::NearBranch64 => {
                if self
                    .iter_find_section(|section| {
                        section.contains_rva(instruction.near_branch64() as usize)
                    })
                    .is_none()
                {
                    panic!("bad near branch");
                }

                let mut mov_instruction = Instruction::with2(
                    Code::Mov_r64_imm64,
                    Register::R11,
                    instruction.near_branch64(),
                )?;
                mov_instruction.set_ip(instruction.ip());

                let mut control_instruction = Instruction::with1(Code::Jmp_rm64, Register::R11)?;

                control_instruction.set_ip(instruction.ip());

                translations.push(Translation::Control(ControlTranslation::new(
                    mov_instruction,
                    control_instruction,
                )));

                Ok(())
            }
            _ => panic!("unsupported jmp instruction"),
        }
    }

    pub fn is_rel_instruction(&self, instruction: &iced_x86::Instruction) -> bool {
        instruction.is_ip_rel_memory_operand() || instruction.is_jcc_short_or_near()
    }

    fn is_bad_instruction(&self, instruction: &iced_x86::Instruction) -> bool {
        (instruction.code() == Code::Add_rm8_r8
            && instruction.memory_base() == Register::RAX
            && instruction.op1_register() == Register::AL)
            || instruction.is_invalid()
            || instruction.code() == Code::Int3
            || instruction.code() == Code::Nop_rm16
            || instruction.code() == Code::Nop_rm32
            || instruction.code() == Code::Nop_rm64
    }

    pub fn get_translations(&self, assume_near: bool) -> Vec<Translation> {
        let mut translations: Vec<Translation> = Vec::new();

        self.iter_find_section(|section| {
            if !section.is_executable() || (self.is_obfuscated() && section.name == ".text") {
                return false;
            }

            let mut decoder = Decoder::new(64, section._raw, iced_x86::DecoderOptions::NONE);

            decoder.set_ip(section.virtual_address as u64);

            //let mut prev_instr: [Option<Instruction>; 3] = [None; 3];

            let mut prev_obfuscated_lea: Option<usize> = None;

            while decoder.can_decode() {
                let position = decoder.position();
                let instruction = decoder.decode();

                if instruction.code() == Code::Add_rm8_r8
                    && instruction.memory_base() == Register::RAX
                    && instruction.op1_register() == Register::AL
                {
                    let next_pos = section._raw[position..]
                        .iter()
                        .enumerate()
                        .find(|(_, byte)| **byte != 0)
                        .map(|(index, _)| position + index);

                    if let Some(next_pos) = next_pos {
                        decoder.set_ip(instruction.ip() + next_pos.saturating_sub(position) as u64);
                        let _ = decoder.set_position(next_pos);
                        continue;
                    } else {
                        break;
                    }
                }

                if self.is_bad_instruction(&instruction) {
                    continue;
                }

                // jump tables appear in this fashion in binaries compiled with llvm:
                // lea
                // movsxd
                // add
                // jmp REG
                /*let mut found_jumptable = false;
                if instruction.mnemonic() == iced_x86::Mnemonic::Jmp
                    && let Some(maybe_lea) = prev_instr[2]
                    && let Some(maybe_movsxd) = prev_instr[1]
                    && let Some(maybe_add) = prev_instr[0] {
                    if maybe_lea.mnemonic() == iced_x86::Mnemonic::Lea
                        && maybe_movsxd.mnemonic() == iced_x86::Mnemonic::Movsxd
                        && maybe_add.mnemonic() == iced_x86::Mnemonic::Add {
                        found_jumptable = true;
                    }
                }*/

                //if instruction.ip() == 0x128C {
                //    //for instr in prev_instr {
                //    //    if let Some(instr) = instr {
                //    //        println!("{instr}");
                //    //    }
                //    //}
                //    println!("{}, op kind: {:?}, is rel: {}, segment reg: {:?}", instruction, instruction.op0_kind(), instruction.is_ip_rel_memory_operand(), instruction.memory_segment());
                //}

                if instruction.mnemonic() == Mnemonic::Sub {
                    if let Some(prev_lea_index) = prev_obfuscated_lea {
                        let obfuscation_offset = instruction.immediate32();

                        translations[prev_lea_index].set_obfuscation_offset(obfuscation_offset);

                        prev_obfuscated_lea = None;
                    }
                }

                if self.is_rel_instruction(&instruction)
                    || instruction.op0_kind() == OpKind::NearBranch64
                {
                    self.add_relative_translation(
                        instruction,
                        &mut translations,
                        assume_near,
                        &mut prev_obfuscated_lea,
                    )
                    .unwrap();
                } else if instruction.mnemonic() == iced_x86::Mnemonic::Jmp {
                    self.add_switch_translation(instruction, &mut translations)
                        .unwrap();
                } else {
                    let mut new_decoder =
                        Decoder::new(64, section._raw, iced_x86::DecoderOptions::NONE);

                    new_decoder.set_ip(decoder.ip());
                    let _ = new_decoder.set_position(decoder.position());

                    self.add_default_translation(&mut new_decoder, instruction, &mut translations)
                        .unwrap();
                }

                //prev_instr.rotate_right(1);
                //prev_instr[0] = Some(instruction);
            }

            false
        });

        translations
    }
}

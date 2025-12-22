use iced_x86::Encoder;

use super::Translation;

pub struct RelativeTranslation {
    mapped_va: u64,
    obfuscation_offset: Option<u32>,
    pub instruction: iced_x86::Instruction,
}

impl RelativeTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self { instruction, mapped_va: 0, obfuscation_offset: None }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        // 2nd operand should be immediate that contains the original ip_rel_operand() value and in here that immediate gets replaced with the reserved memory address
        self.instruction.set_immediate64(rel_op_ip + self.obfuscation_offset.unwrap_or(0) as u64);
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.instruction.immediate64().wrapping_sub(self.obfuscation_offset.unwrap_or(0) as u64))
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

    pub fn set_obfuscation_offset(&mut self, obfuscation_offset: u32) {
        self.obfuscation_offset = Some(obfuscation_offset);
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        //println!("{}", &self.instruction);
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}

// for when a translation is created, we immediately reserve memory but don't resolve it yet
// once we create all translations, we will then iterate all translations and resolve their relative operand addresses

// we will reserve memory in chunks, so we need to create blocks of translations, shuffle the blocks for randomness, then reserve memory addresses for each block, then resolve all translations
// for the jump instruction at the end of a chunk, we will assume it has a size of 14 for the maximum absolute jump instruction size
// memory reservation will be done by allocating at the end of allocation page cursor, and we will align the reserved size to where the next chunk that gets reserved starts at a 16-byte aligned address

// we will reserve memory for all symbols, but we will mark some symbols to not be reserved (like data directory symbols, except relocations and imports)
// add warning messages when there are large symbols so the user is aware of possible memory signatures, large .rdata symbols are critical warnings while large .data symbols are regular warnings
// i think it might be possible for symbols to be stored in .text section, so we need to check for that as well

// when resolving we will check if the rva of the operand is a symbol rva and if it is then we resolve using the symbol mapped address and offseting from it
// if not then we look for the translation block that contains the rva and use the base address of that block plus the offset within the block to resolve the address
use iced_x86::Instruction;

use super::Translation;

#[derive(Clone)]
pub struct RawTranslation {
    pub buffer: Vec<u8>,
}

impl RawTranslation {
    pub fn resolve(&mut self, ip: u64) {
        // Implementation for resolving the relative translation
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        Instruction::new()
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        Ok(self.buffer.clone())
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
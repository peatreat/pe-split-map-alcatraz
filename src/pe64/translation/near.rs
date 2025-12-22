use iced_x86::Encoder;

use super::Translation;

pub struct NearTranslation {
    mapped_va: u64,
    obfuscation_offset: Option<u32>,
    pub instruction: iced_x86::Instruction,
}

impl NearTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self { instruction, mapped_va: 0, obfuscation_offset: None }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        self.instruction.set_memory_displacement64(rel_op_ip + self.obfuscation_offset.unwrap_or(0) as u64);
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.instruction.ip_rel_memory_address().wrapping_sub(self.obfuscation_offset.unwrap_or(0) as u64))
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
        let mut instr = self.instruction.clone();
        
        instr.as_near_branch();
        encoder.encode(&instr, self.mapped())?;

        Ok(encoder.take_buffer())
    }

    pub fn buffer_size(&self) -> Result<usize, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        let mut instr = self.instruction.clone();
        
        instr.as_near_branch();
        instr.set_memory_displacement64(i32::MAX as u64);
        encoder.encode(&instr, 0)?;

        Ok(encoder.take_buffer().len())
    }
}
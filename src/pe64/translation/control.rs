use iced_x86::Encoder;

use super::Translation;

#[derive(Clone)]
pub struct ControlTranslation {
    mapped_va: u64,
    pub mov_instruction: iced_x86::Instruction,
    pub control_instruction: iced_x86::Instruction,
}

impl ControlTranslation {
    pub fn new(mov_instruction: iced_x86::Instruction, control_instruction: iced_x86::Instruction) -> Self {
        Self { mov_instruction, control_instruction, mapped_va: 0 }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        // Implementation for resolving the relative translation
        self.mov_instruction.set_immediate64(rel_op_ip);
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.mov_instruction.immediate64())
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.mov_instruction
    }

    pub fn mapped(&self) -> u64 {
        self.mapped_va
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        &mut self.mapped_va
    }
    
    pub fn buffer(&self, assume_jumps_are_near: bool) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);

        encoder.encode(&self.mov_instruction, self.mov_instruction.ip())?;
        encoder.encode(&self.control_instruction, self.control_instruction.ip())?;
        
        //println!("{}", &self.mov_instruction);
        //println!("{}", &self.control_instruction);

        Ok(encoder.take_buffer())
    }
}
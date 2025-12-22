use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

use super::Translation;

#[derive(Clone)]
pub struct JCCTranslation {
    pub mapped_va: u64,
    pub jcc_instruction: iced_x86::Instruction,
    pub branch_target: u64,
}

impl JCCTranslation {
    pub fn new(mut jcc_instruction: iced_x86::Instruction) -> Result<Self, iced_x86::IcedError> {
        let branch_target = jcc_instruction.near_branch64();

        Ok (
            JCCTranslation {
                mapped_va: 0,
                jcc_instruction,
                branch_target,
            }
        )
    }

    fn get_instruction_size(&self, instruction: &Instruction) -> Result<u64, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        encoder.encode(instruction, instruction.ip()).and_then(|size| Ok(size as u64))
    }
}

impl JCCTranslation {
    pub fn resolve(&mut self, rel_ip: u64) {
        // take rva stored in branch target and then replace branch target with absolute address of the reserved memory for that rva's translation
        self.branch_target = rel_ip;
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.branch_target)
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.jcc_instruction
    }

    pub fn mapped(&self) -> u64 {
        self.mapped_va
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        &mut self.mapped_va
    }
    
    pub fn buffer(&self, assume_jumps_are_near: bool) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);

        let mut jcc_instr = self.jcc_instruction.clone();

        if assume_jumps_are_near {
            jcc_instr.as_near_branch();
            jcc_instr.set_near_branch64(self.branch_target);
            encoder.encode(&jcc_instr, self.mapped())?;

            return Ok(encoder.take_buffer());
        }
        else {
            jcc_instr.as_short_branch();
            jcc_instr.set_near_branch64(0);
            jcc_instr.set_ip(0);

            let mut skip_instruction = Instruction::with_branch(Code::Jmp_rel8_64, 0)?;
            skip_instruction.set_ip(jcc_instr.ip() + self.get_instruction_size(&jcc_instr)?);

            let mut branch_instruction = Instruction::with1(Code::Jmp_rm64, MemoryOperand::new(Register::RIP, Register::None, 1, 0, 4, false, Register::None))?;
            branch_instruction.set_ip(skip_instruction.ip() + self.get_instruction_size(&skip_instruction)?);

            let branch_instruction_size = self.get_instruction_size(&branch_instruction)?;

            branch_instruction.set_memory_displacement32((branch_instruction.ip() + branch_instruction_size) as u32);

            skip_instruction.set_near_branch64(branch_instruction.ip() + branch_instruction_size + std::mem::size_of_val(&self.branch_target) as u64);

            jcc_instr.set_near_branch64(branch_instruction.ip());

            encoder.encode(&jcc_instr, jcc_instr.ip())?;
            encoder.encode(&skip_instruction, skip_instruction.ip())?;
            encoder.encode(&branch_instruction, branch_instruction.ip())?;
        }

        //println!("{}", &jcc_instr);
        //println!("{}", &skip_instruction);
        //println!("{}", &branch_instruction);
        
        Ok (
            [ encoder.take_buffer(), self.branch_target.to_le_bytes().to_vec() ].concat()
        )
    }
}
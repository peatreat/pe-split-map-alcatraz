use std::string::FromUtf8Error;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PSMError {
    #[error("IO Error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error("FromUTF8 Error: {0:?}")]
    FromUTF8Error(#[from] FromUtf8Error),
    #[error("{0:?}")]
    IcedError(#[from] iced_x86::IcedError),
    #[error("Reserve Error: size={0}, alignment={1}")]
    ReserveError(u64, u64),
    #[error("Empty Translation Block")]
    EmptyTranslationBlock,
    #[error("Bad Relative Offset: rip={0}, target_rva={1}, offset={2}")]
    BadRelativeOffset(u64, u64, u64),
    #[error("Failed to translate RVA to mapped address: rva={0}")]
    TranslationFail(u64),
    #[error("Expected jump instruction: rva={0}")]
    ExpectedJump(u64),
    #[error("RVA Out of Bounds: rva={0}")]
    InvalidRVA(u64),
    #[error("RVA not found in sections: rva={0}")]
    RVANotFound(u64),
    #[error("Import DLL not found: module={0}")]
    ImportDLLNotFound(String),
    #[error("Failed to get exports from import: module={0}")]
    ImportHasNoExports(String),
    #[error("Import not found: module={0}, ordinal={1:?}, function={2:?}")]
    ImportNotFound(String, Option<u16>, Option<String>),
    #[error("Import function name was malformed: module={0}, name_rva={1:?}")]
    BadImportFunctionName(String, Option<usize>),
}

pub type Result<T> = std::result::Result<T, PSMError>;
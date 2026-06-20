//! Library facade so the headless crypto/vault logic can be unit/integration
//! tested without pulling in the Win32 GUI.

pub mod crypto;
pub mod vault;

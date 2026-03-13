//! # CLI Commands
//!
//! Each subcommand of the LooMed CLI is implemented in its own module.
//! Modules parse their arguments and delegate to `loomed-core` and
//! `loomed-store`. No business logic lives here.

pub mod add;
pub mod commit;
pub mod init;
pub mod log;
pub mod show;
pub mod status;
pub mod verify;
//! # CLI Commands
//!
//! Each subcommand of the LooMed CLI is implemented in its own module.
//! Modules parse their arguments and delegate to `loomed-core` and
//! `loomed-store`. No business logic lives here.

pub mod init;
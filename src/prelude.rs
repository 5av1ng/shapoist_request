//! all possible things you may use when using this crate

#[cfg(feature = "client")]
pub use crate::client::prelude::*;

#[cfg(feature = "server")]
pub use crate::server::*;

pub use crate::public::command::*;
pub use crate::public::resource::*;
pub use crate::public::server_handle_info::*;
pub use crate::public::*;
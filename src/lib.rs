/*! used by shapoist 
 * 
 * Normally, start with [`crate::public::Request`]
 * */

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
pub mod public;
pub mod prelude;

pub use crate::prelude::*;

#[cfg(feature = "server")]
mod io_functions;
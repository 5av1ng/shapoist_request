/*! used by shapoist 
 * 
 * Normally, start with [`crate::public::Request`]
 * */

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod client;
pub mod public;
pub mod prelude;
//! saves structs for client

use std::thread::JoinHandle;
use std::thread;
use crate::prelude::*;

pub mod prelude;

impl Request {
	/// send request to server
	pub fn send(&mut self, _command: &RequestCommand) -> JoinHandle<Result<(), ClientError>> {
		thread::spawn(|| -> Result<(), ClientError> {
			Ok(())
		})
	}
}
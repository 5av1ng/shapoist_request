/*! saves common part between server and client
 */
use crate::RequestCommand;

pub mod command;
pub mod resource;
pub mod server_handle_info;

/// the main struct of a single request.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq, Default)]
pub struct Request {
	/// command will only be [`Option::None`] when creating.
	pub command: Option<RequestCommand>,
	/// [`Option::None`] will only be found when user is not login or during registration.
	/// only [`InfoCommand`] would not need to use this.
	/// otherwise server will block this request.
	pub uid: Option<u64>,
	/// only when user login this would be exactly password, otherwise this will be a random string.
	/// [`Option::None`] will only be found when user is not login or during registration.
	/// only [`InfoCommand`] would not need to use this.
	/// otherwise server will block this request
	pub token: Option<String>
}
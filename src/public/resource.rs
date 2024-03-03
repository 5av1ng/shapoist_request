use time::OffsetDateTime;
use thiserror::Error;
use std::collections::HashMap;

/// type of a resource
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceType {
	Music,
	Chart,
	Plugin,
	Other(String)
}

/// just what name tolds
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum UpdateType {
	Nightly,
	Stable,
}

/// a struct repensent mail, omited @ symbol
///
/// # Example 
/// ```
/// # use shapoist_request::{ Mail, BadEmail };
/// # fn mail_example() -> Result<(), BadEmail> { 
/// let mail = Mail::from("name@domain.com")?;
/// assert_eq!(mail, Mail { name: String::from("name"), domain: String::from("domain.com") });
///	# Ok(())
/// # }
/// ```
/// ```should_panic
/// # use shapoist_request::Mail;
/// Mail::from("name@domain").unwrap();
/// ```
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Mail {
	pub name: String,
	pub domain: String,
}

/// possilble errors while prasing [`Mail`]
#[derive(Error, Debug, serde::Serialize, serde::Deserialize)]
pub enum BadEmail {
	/// mail misses @ symbol
	#[error("mail misses \"@\" symbol")]
	MissingAt,
	/// mail has more than one symbol
	#[error("mail has more than one \"@\" symbol, expected 1, found {0}")]
	MoreAt(usize),
	/// mail misses name field
	#[error("mail misses name field")]
	MissingName,
	/// mail misses domain field
	#[error("mail misses domain field")]
	MissingDomain,
	/// mail has invailed domain
	#[error("mail has invaild domain")]
	InvaildDomain,
}

impl Mail {
	pub fn from(input: impl Into<String>) -> Result<Self, BadEmail> {
		let input = input.into();
		let input_split: Vec<&str> = input.split("@").collect();
		if input_split.len() == 0 {
			return Err(BadEmail::MissingAt)
		}else if input_split.len() == 1 {
			if &input[0..1] == "@" {
				return Err(BadEmail::MissingName)
			}else {
				return Err(BadEmail::MissingDomain)
			}
		}else if input_split.len() > 2 {
			return Err(BadEmail::MoreAt(input_split.len()))
		}else {
			let domain_split: Vec<&str> = input_split[1].split(".").collect();
			if domain_split.len() != 2 {
				return Err(BadEmail::InvaildDomain)
			}
			return Ok(Self {
				name: input_split[0].into(),
				domain: input_split[1].into()
			})
		}
	}
}


/// a user saved in server
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct User {
	pub uid: u64,
	pub username: String,
	/// r g b a r g b a ...
	pub avator: Vec<u8>,
	pub self_introduction: String,
	pub recent_play: Option<Vec<u64>>,
	pub links: Vec<String>,
	pub upload: HashMap<ResourceType, Vec<u64>>,
	pub mail: Mail
}

/// TODO
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Replay {}

/// confirmation code and when the code create.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfirmationCode {
	pub code: usize,
	pub time: OffsetDateTime
}
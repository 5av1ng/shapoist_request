use crate::public::resource::User;
use crate::public::resource::Mail;
use crate::public::resource::UpdateType;
use crate::public::resource::ResourceType;

/// possible requests to server
///
/// sorted by classes
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum RequestCommand {
	/// Detailed info check [`UserCommand`]
	UserCommand(UserCommand),
	/// Detailed info check [`SourceCommand`]
	SourceCommand(SourceCommand),
	/// Detailed info check [`InfoCommand`]
	Info(InfoCommand),
	/// report something
	Report {
		reason: String,
		ty: ReportType
	},
	/// normally user would not have permission to access these command
	Admin(AdminCommand),
}

/// normally user would not have permission to access these command
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum AdminCommand {
}

/// possible user commands
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum UserCommand {
	/// login with given uid and token
	Login,
	/// registrate with given infomation, password is saved in token
	Registrate {
		mail: Mail,
		username: String,
		confirmation_code: String,
	},
	/// get detailed userinfo
	GetUserInfo,
	/// logoff
	Logoff,
	/// user will use given email to get a password-change email.
	ForgetPass(Mail),
	/// contains new Info.
	ChangeInfo(User),
	/// contains uid
	Ban(u64),
	/// contains uid
	Pardon(u64),
	/// contains uid,
	Blacklist(u64),
	/// contains uid,
	BlacklistRemove(u64),
	/// delete a user
	Delete,
	/// contains replay file
	Replay(Vec<u8>)
}

/// possible infomation-get commands
///
/// Only this command doesn't require uid and token
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum InfoCommand {
	/// Get the newest update from given option
	GetUpdate(UpdateType),
	/// Get the newest n notices
	GetNotice(u64),
}

/// Report type
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum ReportType {
	Resource {
		ty: ResourceType,
		id: u64
	},
	Comment {
		ty: ResourceType,
		id: u64,
		comment_id: u64
	},
	/// contains uid
	User(u64),
	Bug
}

/// possible source-get commands
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum SourceCommand {
	/// get shop info
	GetShopInfo {
		/// requested resource type, [`Option::None`] for main page 
		ty : Option<ResourceType>,
		/// requested resource type
		module: String,
		/// requested resource page
		page: usize,
	},
	/// comment to a resource
	Comment {
		/// what user comments
		comment: String,
		/// contains id of a comment, [`Option::None`] for not reply to any comment
		reply: Option<u64>,
		/// resource id
		resource: (u64, ResourceType)
	},
	/// rate a resource
	Rate {
		/// resource id
		resource: (u64, ResourceType),
		/// 0-100, but will div 10 when display
		rate: u64
	},
	/// search a resource
	Search {
		/// keyword
		key: String,
		/// [`Option::None`] for not to limit resource type
		ty: Option<ResourceType>
	},
	/// upload a new resource
	Upload{
		file: Vec<u8>,
		/// [`Option::None`] for not a update request
		update: Option<u64>,
		ty: ResourceType
	},
	/// download a resource, contains resource id and resource type
	Download(u64, ResourceType),
	/// delete a resource or comment
	Delete {
		resource_id: u64,
		ty: ResourceType,
		/// [`Option::None`] for delete a resource, otherwise delete a reply
		comment: Option<u64>
	},
	ChangeCondition{
		id: u64, 
		ty: ResourceType,
		condition: String,
	},
}
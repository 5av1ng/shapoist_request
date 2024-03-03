use std::path::PathBuf;
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
	/// normally user would not have permission to access these command
	Admin(AdminCommand),
}

/// normally user would not have permission to access these command
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum AdminCommand {
	/// publish a new update, contains binary file.
	PublishUpdate(Vec<u8>),
	/// publish a new notice, contains notice itself, using markdown
	PublishNotice(String),
	/// contains uid
	UserBan(u64),
	/// contains uid
	UserPardon(u64),
	/// contains ip
	BanIp(String),
	/// contains ip
	PardonIp(String),
	/// every document was written in markdown, contains what document should change
	DocumentChange(PathBuf, String),
	/// contains what document should create
	DocumentCrate(PathBuf),
	/// get all reports
	GetReport {
		page: usize,
		ty: ReportType
	},
	/// to manager server data more precisely.
	GetFile(PathBuf),
	/// to manager server data more precisely.
	GetFileList,
}

/// possible user commands
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum UserCommand {
	/// login with given uid and token
	Login(LoginType),
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
	/// user will use given email to get a confirmation email.
	ConfirmationCode(Mail),
	/// contains new Info.
	ChangeInfo(User),
	/// contains uid,
	Blacklist(u64),
	/// contains uid,
	BlacklistRemove(u64),
	/// delete a user
	Delete,
	/// contains replay file
	Replay(Vec<u8>)
}

/// the way user login
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum LoginType {
	Mail(Mail),
	Uid(u64)
}

/// possible infomation-get commands
///
/// Only this command doesn't require uid and token
#[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub enum InfoCommand {
	/// report something
	Report {
		reason: String,
		ty: ReportType
	},
	/// Get the newest update from given option
	GetUpdate(UpdateType),
	/// Get the notices by id, None for newest
	GetNotice(Option<u64>),
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
		resource_type: ResourceType,
		resource_id: u64,
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
		ty: Option<ResourceType>,
		/// requested resource page, start from zero
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
	UploadBegin {
		total: u64,
		/// [`Option::None`] for not a update request
		update: Option<u64>,
		ty: ResourceType
	},
	/// we'll update separately
	UploadProcess {
		id: u64,
		file: Vec<u8>,
		/// temportary solution
		is_config: bool
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
	/// user can partly access this function
	ChangeCondition{
		id: u64, 
		ty: ResourceType,
		/// represent config.toml
		condition: String,
	},
}
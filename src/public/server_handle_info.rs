use crate::User;

/// represents what server send to client
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ServerReturn {
	pub inner: Result<ServerReturnInner, String>
}

#[derive(serde::Serialize, serde::Deserialize)]
/// process info
pub enum ServerReturnInner {
	/// see more in [`crate::UserReturn`]
	User(UserReturn),
	/// see more in [`crate::InfoReturn`]
	Info(InfoReturn),
	/// see more in [`crate::SourceReturn`]
	Source(SourceReturn),
}

#[derive(serde::Serialize, serde::Deserialize)]
/// responses [`crate::SourceCommand`]
pub enum SourceReturn {
	ShopInfo {
		/// represent ChartInfo in core project.
		info: Vec<String>,
	},
	/// contains current upload task's id.
	UploadTaskAccept(u64),
	UploadChunkAccept,
	DownloadPath(String),
	ResourceDeleted,
	ConditionChanged
}

#[derive(serde::Serialize, serde::Deserialize)]
/// responses [`crate::UserCommand`]
pub enum UserReturn {
	/// user logined successfully
	Logined {
		uid: u64,
		token: String,
	},
	/// user registrated successfully
	Registrated {
		uid: u64,
		token: String,
	},
	UserInfo(User),
	Logoffed,
	Deleted,
	Changed
}

#[derive(serde::Serialize, serde::Deserialize)]
/// responses [`crate::InfoCommand`]
pub enum InfoReturn {
	/// report something successfully
	ReportSuccess,
	/// Vec<u8> for file
	Update(Vec<u8>),
	/// notice message in markdown
	Notice(String)
}

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
	#[error("Serialize or deserializing error, info: {0}")]
	ConvertError(#[from] serde_json::Error),
	#[error("io failed, info: {0}")]
	IoError(#[from] std::io::Error),
	#[error("the function requested is not available")]
	NotAvailable,
	#[error("unknown command")]
	UnknownCommand,
	#[error("invaild request")]
	InvaildRequest,
	#[error("token de/encrypt error, info: {0}")]
	TokenError(#[from] TokenError),
	#[error("parsing user command error, info: {0}")]
	UserError(#[from] UserError),
	#[error("parsing source command error, info: {0}")]
	SourceError(#[from] SourceError),
}

#[derive(thiserror::Error, Debug)]
pub enum TokenError {
	#[error("failed to match token")]
	TokenUnmatch,
	#[error("length is not enough to decrypt")]
	InvalidLength,
	// #[error("error during using rsa, info: {0}")]
	// RsaError(#[from] rsa::errors::Error),
	#[error("error during decoding utf8 string, info: {0}")]
	Utf8DecodeError(#[from] std::string::FromUtf8Error),
	#[error("error during decoding base64 string, info: {0}")]
	Base64DecodeError(#[from] base64::DecodeError)
}

#[derive(thiserror::Error, Debug)]
pub enum UserError {
	#[error("invaild user")]
	InvaildUser,
	#[error("permission denied")]
	PermissionDenied,
	#[error("user is not login")]
	NotLogin,
	#[error("user not found")]
	UserNotFound,
	#[error("the given password didnt match current user")]
	PasswordUnmatch,
	#[error("confirmation code didnt exist")]
	ConfirmationCodeUnexist,
	#[error("confirmation code overdue")]
	ConfirmationCodeOverdue,
	#[error("confirmation code unmatch")]
	ConfirmationCodeUnmatch
}

#[derive(thiserror::Error, Debug)]
pub enum SourceError {
	#[error("upload task not found")]
	UploadTaskNotFound,
}
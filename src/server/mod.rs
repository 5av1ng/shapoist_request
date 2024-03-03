// #![warn(missing_docs)]

use std::io::Write;
use std::fs::OpenOptions;
use std::fs;
use time::OffsetDateTime;
use time::Duration;
use std::io::Read;
use rand::distributions::Alphanumeric;
use rand::distributions::Standard;
use rand::prelude::*;
use base64::prelude::*;
// use rsa::RsaPublicKey;
// use rsa::RsaPrivateKey;
// use rsa::Pkcs1v15Encrypt;
use crate::io_functions::*;
use std::collections::HashMap;
use crate::*;
use log::*;

const PAGE: usize = 20;

/// core part of server
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Server {
	pub user_inner: UserInner,
	pub settings: Settings,
	pub upload_id: HashMap<u64, UploadProcess>,
}

/// saves upload file info
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct UploadProcess {
	/// uploaded bytes.
	pub process: u64,
	/// total bytes.
	pub total: u64,
	pub resource_type: ResourceType,
	pub resource_id: u64,
}

/// user storge
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct UserInner {
	/// uid and hashed password
	pub logined_users: HashMap<u64, User>,
	pub user_pass_map: HashMap<u64, String>,
	pub mail_confirmation: HashMap<Mail, ConfirmationCode>,
	pub mail_to_uid: HashMap<Mail, u64>,
}

impl UserInner {
	pub fn init() -> Result<Self, ServerError> {
		let user_pass_map: HashMap<u64, String> = from_json(&read_file_to_string("./data/user/user_pass_map.json")?).unwrap_or_default();
		let logined_users: HashMap<u64, User> = from_json(&read_file_to_string("./data/user/logined_user_map.json")?).unwrap_or_default();
		let mail_confirmation: HashMap<Mail, ConfirmationCode> = from_json(&read_file_to_string("./data/user/mail_confirmation.json")?).unwrap_or_default();
		let mail_to_uid: HashMap<Mail, u64> = from_json(&read_file_to_string("./data/user/mail_to_uid.json")?).unwrap_or_default();
		Ok(Self {
			user_pass_map,
			logined_users,
			mail_confirmation,
			mail_to_uid,
		})
	}

	pub fn sync(&mut self) -> Result<(), ServerError> {
		self.mail_confirmation.retain(|_, code| (OffsetDateTime::now_utc() - code.time) < Duration::minutes(15));
		write_file("./data/user/user_pass_map.json", to_json(&self.user_pass_map)?.as_bytes())?;
		write_file("./data/user/logined_user_map.json", to_json(&self.logined_users)?.as_bytes())?;
		write_file("./data/user/mail_confirmation.json", to_json(&self.mail_confirmation)?.as_bytes())?;
		write_file("./data/user/mail_to_uid.json", to_json(&self.mail_to_uid)?.as_bytes())?;
		Ok(())
	}
}

impl Server {
	pub fn init() -> Result<Self, ServerError> {
		info!("init server");
		let user_inner = UserInner::init()?;
		let settings: Settings = from_json(&read_file_to_string("./data/settings.json")?).unwrap_or_else(|_| {
			let token_generater: TokenGenerator = rand::random();
			let token_generater_2: TokenGenerator = rand::random();
			Settings {
				hash_rules: token_generater_2.hash_rules,
				token_generater
			}
		});
		Ok(Self {
			user_inner,
			settings,
			upload_id: HashMap::new()
		})
	}

	pub fn handle_request_json(&mut self, request: String) -> ServerReturn {
		info!("getting new request");
		let request: Request = match from_json(&request) {
			Ok(t) => t,
			Err(e) => {
				error!("request parsing failed, info: {}", e);
				return ServerReturn {
					inner: Err(format!("{}", e))
				};
			}
		};
		self.handle_request(request)
	}

	pub fn handle_request(&mut self, request: Request) -> ServerReturn {
		if let Some(command) = request.command {
			command.prase(request.uid, request.token, &mut self.settings, &mut self.user_inner, &mut self.upload_id)
		}else {
			ServerReturn {
				inner: Err(format!("{}", ServerError::InvaildRequest))
			}
		}
	}

	pub fn sync(&mut self) -> Result<(), ServerError> {
		self.user_inner.sync()?;
		write_file("./data/settings.json", to_json(&self.settings)?.as_bytes())?;
		Ok(())
	}
}

/// settings of current server
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Settings {
	/// what way do we hash user's password, will in the vec's order
	pub hash_rules: Vec<HashRule>,
	/// defines how to generate token and authorizate it.
	pub token_generater: TokenGenerator
}

impl Settings {
	/// as name suggests
	pub fn check_password(&self, uid: u64, pass: &String, user_inner: &UserInner) -> Result<bool, ServerError> {
		let pass = self.hash_password(pass);
		if let Some(t) = user_inner.user_pass_map.get(&uid) {
			Ok(*t == pass)
		}else {
			Err(UserError::UserNotFound.into())
		}
	}

	/// as name suggests
	pub fn hash_password(&self, pass: &String) -> String {
		let mut pass = pass.clone();
		for hash_rule in &self.hash_rules {
			pass = hash_rule.hash(&pass);
		}
		pass
	}
}

/// decided the way we hash
/// this struct can be generate by `rand` crate
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum HashRule {
	/// md5 hash, though it's cryptographically broken, but i think we can still use this combine with other hash functions to get safe results.
	Md5,
	/// sha256 hash
	Sha256,
	/// where we add what salt, will add '0' if desired size is larger than string
	Salt(usize, String)
}

impl HashRule {
	/// using current hash rule to hash it.
	pub fn hash(&self, input: &String) -> String {
		match &self {
			Self::Md5 => format!("{:x}", md5::compute(input)),
			Self::Sha256 => sha256::digest(input),
			Self::Salt(position, salt) => {
				let mut after = input.clone();
				if position >= &input.len() {
					for _ in input.len()..= *position {
						after.push('0')
					}
				}
				after.insert_str(*position, salt);
				after
			}
		}
	}
}

impl Distribution<HashRule> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> HashRule {
		match rng.gen_range(0..=2) {
		0 => HashRule::Md5,
		1 => {
			let random = rng.gen_range(5..15);
			let salt =  rng.sample_iter(&Alphanumeric).take(random).map(char::from).collect();
			HashRule::Salt(rng.gen_range(0..15), salt)
		},
		2 => HashRule::Sha256,
		_ => unreachable!()
		}
	}
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
/// the struct to generate token, token generate process should be unpredicable and varies after each calling.
/// this struct can be generate by `rand` crate
pub struct TokenGenerator {
	/// 1. we'll pre hash user's hashed passwords
	pub hash_rules: Vec<HashRule>,
	/// we'll add random and fixed size salt between every hashes
	pub salt_positions: Vec<usize>,
	// /// 2. then we will using rsa to encrypt current token
	// pub rsa_public: RsaPublicKey,
	// /// of course we will need to decrypt it
	// pub rsa_private: RsaPrivateKey,
	/// last we'll encrypto tokens
	pub cryptos: Vec<CryptoRule>,
}

impl TokenGenerator {
	/// the way we generate token
	pub fn generate_token(&self, uid: u64, user_inner: &UserInner) -> Result<String, ServerError> {
		if let Some(hashed_pass) = user_inner.user_pass_map.get(&uid) {
			Ok(self.generate_token_with_pass(hashed_pass)?)
		}else {
			Err(UserError::UserNotFound.into())
		}
	}

	fn generate_token_with_pass(&self, pass: &String) -> Result<String, TokenError> {
		let mut res: String = pass.as_bytes().iter().map(|inner| char::from(*inner)).collect();

		let salt: Vec<char> = rand::thread_rng().sample_iter(&Alphanumeric).take(self.salt_positions.len()).map(char::from).collect();
		self.hash(&mut res, &salt);

		// let mut rng = rand::thread_rng();
		// let enc_data = self.rsa_public.encrypt(&mut rng, Pkcs1v15Encrypt, &res.as_bytes())?;
		// res = enc_data.iter().map(|inner| char::from(*inner)).collect();

		self.encrypt(&mut res)?;


		Ok(res)
	}

	fn hash(&self, input: &mut String, salt: &Vec<char>) {
		let salt_adder = |input: &mut String| {
			for (i, salt_position) in self.salt_positions.iter().enumerate() {
				if salt_position >= &input.len() {
					for _ in input.len()..= *salt_position {
						input.push('0')
					}
				}

				input.insert(*salt_position, salt[i]);
			}
		};

		for hash_rule in &self.hash_rules {
			*input = hash_rule.hash(input);
			salt_adder(input);
		}

		*input = HashRule::Sha256.hash(input);
		salt_adder(input);
	}

	fn encrypt(&self, input: &mut String) -> Result<(), TokenError> {
		for crypto in &self.cryptos {
			*input = crypto.encrypt(input)?;
		}

		Ok(())
	}

	fn decrypt(&self, input: &mut String) -> Result<(), TokenError> {
		for crypto in self.cryptos.iter().rev() {
			*input = crypto.decrypt(input)?;
		}

		Ok(())
	}

	/// the way we authorizate token
	pub fn authorizate(&self, uid: u64, token: &String, user_inner: &UserInner) -> Result<User, ServerError> {
		if let Some(hashed_pass) = user_inner.user_pass_map.get(&uid) {
			if self.authorizate_with_pass(hashed_pass, token)? {
				if let Some(user) = user_inner.logined_users.get(&uid) {
					Ok(user.clone())
				}else {
					Err(UserError::NotLogin.into())
				}
			}else {
				Err(TokenError::TokenUnmatch.into())
			}
		}else {
			Err(UserError::UserNotFound.into())
		}
	}

	fn authorizate_with_pass(&self, pass: &String, token: &String) -> Result<bool, TokenError> {
		let pass: String = pass.as_bytes().iter().map(|inner| char::from(*inner)).collect();

		let mut backward = token.clone();
		self.decrypt(&mut backward)?;
		// backward = self.rsa_private.decrypt(Pkcs1v15Encrypt, &backward.as_bytes())?.iter().map(|inner| char::from(*inner)).collect();

		let mut salt = vec!();
		let mut salt_getter = backward.clone();
		for salt_position in self.salt_positions.iter().rev() {
			if salt_position >= &salt_getter.len() {
				return Err(TokenError::InvalidLength)
			}

			salt.insert(0, salt_getter.remove(*salt_position));
		}

		let mut forward = pass.clone();
		self.hash(&mut forward, &salt);

		Ok(forward == backward)
	}
}

impl Distribution<TokenGenerator> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TokenGenerator {
		let hash_rule_len = rng.gen_range(5..10);
		let crypto_len = rng.gen_range(5..10);
		let salt_len = rng.gen_range(10..15);
		let hash_rules = rng.sample_iter(&Standard).take(hash_rule_len).collect();
		let cryptos = rng.sample_iter(&Standard).take(crypto_len).collect();
		let salt_positions: Vec<usize> = (0..salt_len).map(|_| {
			rng.gen_range(0..30)
		}).collect();
		// let rsa_private = loop {
		// 	if let Ok(t) = RsaPrivateKey::new(&mut rand::thread_rng(), 2048) {
		// 		break t
		// 	}
		// };
		// let rsa_public = RsaPublicKey::from(&rsa_private);
		TokenGenerator {
			hash_rules,
			salt_positions,
			cryptos,
			// rsa_private,
			// rsa_public,
		}
	}
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
/// decides how we encrypt and decrypto
/// this struct can be generate by `rand` crate
pub enum CryptoRule {
	// Ecc {
	// 	a: u64,
	// 	b: u64,
	// 	public: u64,
	// 	privite: u64
	// },
	/// rsa crypto, maybe not a good idea
	// Rsa {
	// 	public: RsaPublicKey,
	// 	private: RsaPrivateKey
	// },
	/// where we add what salt, will add '0' if desired size is larger than string
	Salt(usize, String),
	/// base64 crypto
	Base64,
}

impl CryptoRule {
	pub fn encrypt(&self, input: &String) -> Result<String, TokenError> {
		Ok(match &self {
			Self::Salt(position, salt) => {
				let mut after = input.clone();
				if position >= &input.len() {
					for _ in input.len()..= *position {
						after.push('0')
					}
				}
				after.insert_str(*position, salt);
				after
			}
			Self::Base64 => {
				BASE64_STANDARD.encode(input)
			},
		})
	}

	pub fn decrypt(&self, input: &String) -> Result<String, TokenError> {
		Ok(match &self {
			Self::Salt(position, salt) => {
				let mut after = input.clone();
				if position + salt.len() >= input.len() {
					return Err(TokenError::InvalidLength);
				}
				after = after[0..*position].to_string() + &after[position + salt.len()..];
				after
			},
			Self::Base64 => {
				String::from_utf8(BASE64_STANDARD.decode(input)?)?
			},
		})

	}
}

impl Distribution<CryptoRule> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CryptoRule {
		match rng.gen_range(1..=2) {
			1 => {
				let random = rng.gen_range(5..15);
				let salt = rng.sample_iter(&Alphanumeric).take(random).map(char::from).collect();
				CryptoRule::Salt(rng.gen_range(0..15), salt)
			},
			2 => CryptoRule::Base64,
			_ => unreachable!()
		}
	}
}

/// stanard report file
#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct Report {
	pub content: String,
	pub reporter: u64,
	/// None for not handled
	pub return_info: Option<String>
}

impl RequestCommand {
	pub fn prase(self, uid: Option<u64>, token: Option<String>, settings: &mut Settings, user_inner: &mut UserInner, upload_id: &mut HashMap<u64, UploadProcess>) -> ServerReturn {
		ServerReturn {
			inner: 
			match match self {
				Self::UserCommand(inner) => { inner.prase(uid, token, settings, user_inner) },
				Self::SourceCommand(inner) => { inner.prase(uid, token, settings, user_inner, upload_id) },
				Self::Info(inner) => { inner.prase(uid, token, settings, user_inner ) },
				Self::Admin(inner) => { inner.prase(uid, token, settings, user_inner) },
			} {
				Ok(t) => Ok(t),
				Err(e) => Err(format!("{}", e)),
			}
		}
	}
}

fn check_user(uid: Option<u64>, token: Option<String>, settings: &Settings, user_inner: &UserInner) -> Result<User, ServerError> {
	if let (Some(uid), Some(token)) = (uid, token) {
		settings.token_generater.authorizate(uid, &token, user_inner)
	}else {
		Err(ServerError::InvaildRequest)
	}
}

impl UserCommand {
	fn prase(self, uid: Option<u64>, token: Option<String>, settings: &Settings, user_inner: &mut UserInner) -> Result<ServerReturnInner, ServerError> {
		if let Some(token) = &token {
			match &self {
				UserCommand::Login(inner) => {
					let uid = match inner {
						LoginType::Mail(mail) => {
							if let Some(t) = user_inner.mail_to_uid.get(&mail) {
								*t
							}else {
								return Err(UserError::UserNotFound.into())
							}
						},
						LoginType::Uid(id) => *id,
					};
					if settings.check_password(uid, &token, user_inner)? {
						let token = settings.token_generater.generate_token(uid, user_inner)?;
						let user: User = from_json(&read_file_to_string(format!("./data/user/{}/user.json", uid))?)?;
						user_inner.logined_users.insert(uid, user);
						return Ok(ServerReturnInner::User(UserReturn::Logined {
							uid,
							token,
						}))
					}else {
						return Err(UserError::PasswordUnmatch.into())
					}
				},
				UserCommand::Registrate { mail, username, confirmation_code } => {
					let inner = if let Some(t) = user_inner.mail_confirmation.get(&mail) {
						if (OffsetDateTime::now_utc() - t.time) > Duration::minutes(15) {
							Err(UserError::ConfirmationCodeOverdue)
						}else {
							if t.code.to_string() == *confirmation_code {
								let uid = user_inner.mail_to_uid.len() as u64 + 100001;
								Ok(User {
									uid,
									username: username.to_string(),
									mail: mail.clone(),
									..Default::default()
								})
							}else {
								Err(UserError::ConfirmationCodeUnmatch)
							}
						}
						
					}else {
						Err(UserError::ConfirmationCodeUnexist)
					};
					user_inner.mail_confirmation.retain(|_, code| (OffsetDateTime::now_utc() - code.time) < Duration::minutes(15));

					let inner = inner?;
					user_inner.logined_users.insert(inner.uid, inner.clone());
					user_inner.mail_to_uid.insert(mail.clone(), inner.uid);

					let pass = settings.hash_password(&token);
					user_inner.user_pass_map.insert(inner.uid, settings.hash_password(&token));

					let token = settings.token_generater.generate_token_with_pass(&pass)?;
					create_dir(format!("./data/user/{}", inner.uid))?;
					create_file(format!("./data/user/{}/user.json", inner.uid))?;
					write_file(format!("./data/user/{}/user.json", inner.uid), to_json(&inner)?.as_bytes())?;
					return Ok(ServerReturnInner::User(UserReturn::Registrated {
						uid: inner.uid,
						token
					}));

				},
				UserCommand::ForgetPass(_) => { return Err(ServerError::NotAvailable) },
				UserCommand::ConfirmationCode(_) => { return Err(ServerError::NotAvailable) },
				_ => {}
			}
		}else {
			return Err(ServerError::InvaildRequest)
		}
		let user = check_user(uid, token, settings, user_inner)?;
		match self {
			Self::GetUserInfo => {
				return Ok(ServerReturnInner::User(UserReturn::UserInfo(user)));
			},
			Self::Logoff => {
				user_inner.logined_users.remove(&user.uid);
				return Ok(ServerReturnInner::User(UserReturn::Logoffed));
			},
			Self::ChangeInfo(new_user) => {
				remove_file(format!("./data/user/{}/user.json", user.uid))?;
				create_file(format!("./data/user/{}/user.json", user.uid))?;
				write_file(format!("./data/user/{}/user.json", user.uid), to_json(&new_user)?.as_bytes())?;
				user_inner.logined_users.insert(user.uid, new_user);
				return Ok(ServerReturnInner::User(UserReturn::Changed));
			},
			Self::Blacklist(_) => { return Err(ServerError::NotAvailable) },
			Self::BlacklistRemove(_) => { return Err(ServerError::NotAvailable) },
			Self::Delete => {
				user_inner.user_pass_map.remove(&user.uid);
				user_inner.logined_users.remove(&user.uid);
				user_inner.mail_to_uid.remove(&user.mail);
				remove_path(format!("./data/user/{}", user.uid))?;
				return Ok(ServerReturnInner::User(UserReturn::Deleted));
			},
			Self::Replay(_) => { return Err(ServerError::NotAvailable) },
			Self::ForgetPass(_) | Self::ConfirmationCode(_) | Self::Registrate {..} | Self::Login(_) => unreachable!(),
		}
	}
}

impl SourceCommand {
	fn prase(self, uid: Option<u64>, token: Option<String>, settings: &Settings, user_inner: &mut UserInner, upload_id: &mut HashMap<u64, UploadProcess>) -> Result<ServerReturnInner, ServerError> {
		check_user(uid, token, settings, user_inner)?;
		match self {
			Self::GetShopInfo { ty, page } => {
				match ty {
					Some(ResourceType::Chart) | None => {
						let path_read = fs::read_dir("./data/source/chart")?;
						let start_position = page * PAGE;
						let end_position = start_position + PAGE;
						let mut current_position = 0;
						let mut output_dirs = vec!();

						for dir in path_read {
							let dir = dir?;
							let path = dir.path();

							if path.is_dir() { 
								if current_position >= start_position && current_position < end_position {
									output_dirs.push(path)
								}

								current_position = current_position + 1;
							}

							if current_position >= end_position {
								break;
							}
						}

						let mut info = vec!();
						for dir in output_dirs {
							info.push(read_file_to_string(format!("{}/config.toml", dir.display()))?);
						}

						Ok(ServerReturnInner::Source(SourceReturn::ShopInfo { info }))
					},
					_ => Err(ServerError::NotAvailable)
				}
			},
			Self::Comment { .. } => {
				return Err(ServerError::NotAvailable);
			},
			Self::Rate { .. } => {
				return Err(ServerError::NotAvailable);
			},
			Self::Search { .. } => {
				return Err(ServerError::NotAvailable);
			},
			Self::UploadBegin { update, ty, total } => {
				match ty {
					ResourceType::Chart => {
						if let Some(resource_id) = update {
							let mut file = OpenOptions::new().read(true).write(true).append(false).open(format!("./data/source/chart/{}/chart.scc", resource_id))?;
							write!(file, "")?;
							let id = loop {
								let id: u64 = rand::random();
								if !upload_id.contains_key(&id) {
									upload_id.insert(id, UploadProcess {
										resource_type: ResourceType::Chart,
										resource_id,
										total,
										process: 0,
									});
									break id;
								}
								
							};

							return Ok(ServerReturnInner::Source(SourceReturn::UploadTaskAccept(id)));
						}else {
							let resource_id: u64 = from_json(&read_file_to_string("./data/source/chart/id.json")?)?;
							create_dir(format!("./data/source/chart/{}", resource_id))?;
							create_file(format!("./data/source/chart/{}/chart.scc", resource_id))?;
							create_file(format!("./data/source/chart/{}/config.toml", resource_id))?;
							let mut file = OpenOptions::new().read(true).write(true).append(false).open("./data/source/chart/id.json")?;
							write!(file, "{}", resource_id + 1)?;
							let id = loop {
								let id: u64 = rand::random();
								if !upload_id.contains_key(&id) {
									upload_id.insert(id, UploadProcess {
										resource_type: ResourceType::Chart,
										resource_id,
										total,
										process: 0,
									});
									break id;
								}
								
							};

							return Ok(ServerReturnInner::Source(SourceReturn::UploadTaskAccept(id)));
						}
					},
					_ => return Err(ServerError::NotAvailable),
				}
			},
			Self::UploadProcess { id, file, is_config } => {
				if let Some(process) = upload_id.get_mut(&id) {
					match process.resource_type {
						ResourceType::Chart => {
							let mut chart = if is_config {
								OpenOptions::new().read(true).write(true).append(true).open(format!("./data/source/chart/{}/config.toml", process.resource_id))?
							}else {
								OpenOptions::new().read(true).write(true).append(true).open(format!("./data/source/chart/{}/chart.scc", process.resource_id))?
							};
							chart.write_all(&file)?;
							process.process = process.process + file.len() as u64;
							if process.process >= process.total {
								upload_id.remove(&id);
							}
							return Ok(ServerReturnInner::Source(SourceReturn::UploadChunkAccept))
						},
						_ => {
							upload_id.remove(&id);
							return Err(ServerError::NotAvailable)
						},
					}
				}else {
					return Err(SourceError::UploadTaskNotFound.into())
				}
			},
			Self::Download(id, ty) => {
				match ty {
					ResourceType::Chart => {
						return Ok(ServerReturnInner::Source(SourceReturn::DownloadPath(format!("/data/source/chart/{}/chart.scc", id))))
					},
					_ => return Err(ServerError::NotAvailable),
				}
			},
			Self::Delete { resource_id, ty, comment: _ } => {
				match ty {
					ResourceType::Chart => {
						remove_path(format!("/data/source/chart/{}", resource_id))?;
						return Ok(ServerReturnInner::Source(SourceReturn::ResourceDeleted));
					},
					_ => return Err(ServerError::NotAvailable),
				}
			},
			Self::ChangeCondition { id, ty, condition } => {
				match ty {
					ResourceType::Chart => {
						let mut config = OpenOptions::new().read(true).write(true).append(false).open(format!("./data/source/chart/{}/config.toml", id))?;
						write!(config, "{}", condition)?;
						return Ok(ServerReturnInner::Source(SourceReturn::ConditionChanged));
					},
					_ => return Err(ServerError::NotAvailable),
				}
			},
		}
	}
}

impl InfoCommand {
	fn prase(self, uid: Option<u64>, token: Option<String>, settings: &Settings, user_inner: &mut UserInner) -> Result<ServerReturnInner, ServerError> {
		match self {
			Self::Report { reason, ty } => {
				let user = check_user(uid, token, settings, user_inner)?;
				let report = Report {
					content: reason,
					reporter: user.uid,
					return_info: None
				};
				match ty {
					ReportType::Resource { ty, id } => {
						match ty {
							ResourceType::Music => return Err(ServerError::NotAvailable),
							ResourceType::Chart => {
								let path = format!("./data/info/report/resource/chart/{}-{}.json", id, user.uid);
								create_file(&path)?;
								write_file(&path, to_json(&report)?.as_bytes())?;
							},
							ResourceType::Plugin => return Err(ServerError::NotAvailable),
							ResourceType::Other(_) => return Err(ServerError::NotAvailable),
						}
					},
					ReportType::Comment { comment_id, resource_type, resource_id } => {
						match resource_type {
							ResourceType::Music => return Err(ServerError::NotAvailable),
							ResourceType::Chart => {
								let path = format!("./data/info/report/comment/chart/{}-{}-{}.json", resource_id, comment_id, user.uid);
								create_file(&path)?;
								write_file(&path, to_json(&report)?.as_bytes())?;
							},
							ResourceType::Plugin => return Err(ServerError::NotAvailable),
							ResourceType::Other(_) => return Err(ServerError::NotAvailable),
						}
					},
					ReportType::User(uid) => {
						let path = format!("./data/info/report/user/{}-{}.json", uid, user.uid);
						create_file(&path)?;
						write_file(&path, to_json(&report)?.as_bytes())?;
					},
					ReportType::Bug => {
						let len = read_every_file("./data/info/report/bug")?.len();
						let path = format!("./data/info/report/bug/{}-{}.json", len, user.uid);
						create_file(&path)?;
						write_file(&path, to_json(&report)?.as_bytes())?;
					},
				}
				Ok(ServerReturnInner::Info(InfoReturn::ReportSuccess))
			},
			Self::GetUpdate(ty) => {
				let mut file = match ty {
					UpdateType::Nightly => {
						read_file("./data/info/update/nightly/newest.apk")?
					},
					UpdateType::Stable => {
						read_file("./data/info/update/stable/newest.apk")?
					},
				};
				let mut inner = vec!(); 
				file.read_to_end(&mut inner)?;
				Ok(ServerReturnInner::Info(InfoReturn::Update(inner)))
			},
			Self::GetNotice(info) => {
				let inner = if let Some(t) = info {
					read_file_to_string(format!("./data/info/notice/{}.md", t))?
				}else {
					let len = read_every_file("./data/info/notice")?.len().checked_sub(0).unwrap_or(0);
					read_file_to_string(format!("./data/info/notice/{}.md", len))?
				};
				Ok(ServerReturnInner::Info(InfoReturn::Notice(inner)))
			},
		}
	}
}

impl AdminCommand {
	fn prase(self, uid: Option<u64>, token: Option<String>, settings: &mut Settings, user_inner: &mut UserInner) -> Result<ServerReturnInner, ServerError> {
		check_user(uid, token, settings, user_inner)?;
		Err(ServerError::NotAvailable)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_token() {
		let token_generater: TokenGenerator = rand::random();
		let pass = String::from("testPassWord");
		let token = token_generater.generate_token_with_pass(&pass).unwrap();
		assert!(token_generater.authorizate_with_pass(&pass, &token).unwrap());
	}
}
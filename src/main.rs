use std::io;
use std::io::Write;
use std::process::exit;
use clap::{arg, Command};
use password_auth::{generate_hash, VerifyError};

fn cli() -> Command {
    Command::new("cable_lock")
        .about("Local secret storage for linux")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("authorization_grant")
                .about("Grant authorization for a client requesting to access resources")
                .arg(arg!(<SCOPE> "The requested scope"))
                .arg_required_else_help(true),
        )
}

struct User {
    username: String,
    hash: String,
    salt: String,
}

fn verify_password(user: User, password: &str) -> Result<(), VerifyError> {
    let with_salt = format!("{}{}", password, user.salt);
    password_auth::verify_password(with_salt, &*user.hash)
}


trait InputReader {
    fn get_username_and_password(&self) -> (String, String);
}

struct InputReaderImpl;
impl InputReader for InputReaderImpl {
    fn get_username_and_password(&self) -> (String, String) {
        print!("Username: ");
        io::stdout().flush().expect("Couldn't flush stdout");

        let mut user_name = String::new();
        io::stdin().read_line(&mut user_name).expect("Failed to read line");

        let password = rpassword::prompt_password("Password: ").unwrap();

        (user_name.trim().to_string(), password)
    }
}

struct InputReaderFake {
    user_name: String,
    password: String,
}

impl InputReader for InputReaderFake {
    fn get_username_and_password(&self) -> (String, String) {
        let usn = self.user_name.to_string();
        let pwd = self.password.clone().to_string();
        (usn, pwd)
    }
}

trait UserStore {
    fn get_user_by_username(&self, username: &str) -> Result<User, String>;
}

struct UserStoreFake;
impl UserStore for UserStoreFake {
    fn get_user_by_username(&self, username: &str) -> Result<User, String> {
        if username != "test_user" {
            return Err("no such user".to_string());
        }

        let salt = "salt".to_string();
        let password = "password";
        let salted = format!("{}{}", password, salt);
        let hash = generate_hash(salted);

        let user = User {
            username: "test_user".to_string(),
            hash,
            salt,
        };

        Ok(user)
    }
}

fn main() {
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("authorization_grant", sub_matches)) => {
            let scope = sub_matches.get_one::<String>("SCOPE").expect("required");
            let input_reader = InputReaderImpl;
            let user_store = UserStoreFake;
            match authenticate(&input_reader, &user_store) {
                Ok(_) => {
                    println!("SUCCESS");
                    println!("requested {}", scope);
                }
                Err(err) => {
                    println!("{}", err);
                    exit(1)
                }
            }
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }
    };
}

fn authenticate<I: InputReader, U: UserStore>(input_reader: &I, user_store: &U) -> Result<(), String> {
    let (user_name, password) = input_reader.get_username_and_password();
    match user_store.get_user_by_username(&user_name) {
        Ok(user) => {
            match verify_password(user, &password) {
                Ok(_) => Ok(()),
                Err(_) => Err("incorrect username or password".to_string())
            }
        }
        Err(_) => Err("incorrect username or password".to_string())
    }
}

#[cfg(test)]
mod tests {
    use password_auth::generate_hash;
    use rand::distributions::{Alphanumeric, DistString};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_salt() {
        let salt = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let password = "password";
        let salted = format!("{}{}", password, salt);
        let hash = generate_hash(salted);

        let user = User {
            username: "test_user".to_string(),
            hash,
            salt,
        };

        let result = verify_password(user, password);
        assert!(result.is_ok())
    }

    #[test]
    fn test_authenticate__valid_credentials__return_ok() {
        let input_reader_fake = InputReaderFake {
            user_name: "test_user".to_string(),
            password: "password".to_string(),
        };
        let user_store = UserStoreFake;

        let result = authenticate(&input_reader_fake, &user_store);
        assert!(result.is_ok())
    }

    #[test]
    fn test_authenticate__invalid_password__return_err() {
        let input_reader_fake = InputReaderFake {
            user_name: "test_user".to_string(),
            password: "wrong_password".to_string(),
        };
        let user_store = UserStoreFake;

        let result = authenticate(&input_reader_fake, &user_store);
        assert!(result.is_err())
    }

    #[test]
    fn test_authenticate__unknown_user__returns_err() {
        let input_reader_fake = InputReaderFake {
            user_name: "another_user".to_string(),
            password: "password".to_string(),
        };
        let user_store = UserStoreFake;

        let result = authenticate(&input_reader_fake, &user_store);
        assert!(result.is_err())
    }

    #[test]
    fn test_authenticate__both_wrong_returns_err() {
        let input_reader_fake = InputReaderFake {
            user_name: "another_user".to_string(),
            password: "incorrect_password".to_string(),
        };
        let user_store = UserStoreFake;

        let result = authenticate(&input_reader_fake, &user_store);
        assert!(result.is_err())
    }
}

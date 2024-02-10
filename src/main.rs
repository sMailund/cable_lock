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

struct Authenticator {
    user_store: dyn UserStore,
}

impl Authenticator {
    fn authenticate() -> Result<(), String> {
        Err("".to_string())
    }
}

trait InputReader {
    fn get_username_and_password() -> (String, String);
}

struct InputReaderFake;

impl InputReader for InputReaderFake {
    fn get_username_and_password() -> (String, String) {
        ("user_name".to_string(), "password".to_string())
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
            println!("requested {}", scope);
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }
    };
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
}

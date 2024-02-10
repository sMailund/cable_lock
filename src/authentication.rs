pub mod InputReader;
pub mod UserStore;

use std::io;
use std::io::Write;

use password_auth::{generate_hash, VerifyError};

struct User {
    username: String,
    hash: String,
    salt: String,
}

fn verify_password(user: User, password: &str) -> Result<(), VerifyError> {
    let with_salt = format!("{}{}", password, user.salt);
    password_auth::verify_password(with_salt, &*user.hash)
}

pub fn authenticate<I: InputReader::InputReader, U: UserStore::UserStore>(
    input_reader: &I,
    user_store: &U,
) -> Result<(), String> {
    let (user_name, password) = input_reader.get_username_and_password();
    match user_store.get_user_by_username(&user_name) {
        Ok(user) => match verify_password(user, &password) {
            Ok(_) => Ok(()),
            Err(_) => Err("incorrect username or password".to_string()),
        },
        Err(_) => Err("incorrect username or password".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use crate::authentication::UserStore::UserStoreFake;
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

    struct InputReaderFake {
        user_name: String,
        password: String,
    }

    impl InputReader::InputReader for InputReaderFake {
        fn get_username_and_password(&self) -> (String, String) {
            let usn = self.user_name.to_string();
            let pwd = self.password.clone().to_string();
            (usn, pwd)
        }
    }
}

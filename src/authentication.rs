pub mod input_reader;
pub mod user_store;

use std::io::Write;

use password_auth::{generate_hash, VerifyError};

const ERROR_INCORRECT_USER_NAME_OR_PASSWORD: &str = "incorrect username or password";

fn verify_password(user: user_store::User, password: &str) -> Result<(), VerifyError> {
    let with_salt = format!("{}{}", password, user.salt);
    password_auth::verify_password(with_salt, &*user.hash)
}

pub fn authenticate<I: input_reader::InputReader, U: user_store::UserStore>(
    input_reader: &I,
    user_store: &U,
) -> Result<(), String> {
    let (user_name, password) = input_reader.get_username_and_password();

    user_store
        .get_user_by_username(&user_name)
        .map_err(|_| ERROR_INCORRECT_USER_NAME_OR_PASSWORD.to_string())
        .and_then(|user| {
            verify_password(user, &password)
                .map_err(|_| ERROR_INCORRECT_USER_NAME_OR_PASSWORD.to_string())
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use crate::authentication::user_store::UserStoreFake;
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

        let user = user_store::User {
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

    impl input_reader::InputReader for InputReaderFake {
        fn get_username_and_password(&self) -> (String, String) {
            let usn = self.user_name.to_string();
            let pwd = self.password.clone().to_string();
            (usn, pwd)
        }
    }
}

use crate::authentication::User;
use password_auth::generate_hash;

pub(crate) trait UserStore {
    fn get_user_by_username(&self, username: &str) -> Result<User, String>;
}

pub(crate) struct UserStoreFake;
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

use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use rusqlite::Connection;

const TOKEN_LENGTH: usize = 32;

fn create_auth_code(username: &str, scopes: Vec<&str>, connection: Connection) -> String {
    let string = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    string
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use rusqlite_migration::{M, Migrations};

    use crate::repository::create_auth_code;

    #[test]
    fn should_return_generated_code() {
        let migrations = Migrations::new(vec![
            M::up("create table authorization_code(auth_code TEXT PRIMARY KEY, subject TEXT NOT NULL, scopes TEXT NOT NULL);")
                .down("drop table authorization_code;"),
            M::up("create table user(username text NOT NULL UNIQUE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL);")
                .down("drop table user;"),
            // In the future, add more migrations here:
            //M::up("ALTER TABLE friend ADD COLUMN email TEXT;"),
        ]);
        let mut conn = Connection::open_in_memory().unwrap();
        migrations.to_latest(&mut conn).unwrap();

        let scopes = vec!["scope"];
        let code = create_auth_code("user", scopes, conn);
        assert_ne!(0, code.len());
    }
}

use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use rusqlite::{params, Connection, Error as RusqliteError};
use std::error::Error;

const TOKEN_LENGTH: usize = 32;

fn create_auth_code(
    username: &str,
    scopes: Vec<&str>,
    connection: &Connection,
) -> Result<String, String> {
    let string = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

    // here
    let scopes_string = scopes.join(",");

    let insert_result = connection.execute(
        "INSERT INTO authorization_code (auth_code, subject, scopes) VALUES (?1, ?2, ?3)",
        params![&string, username, scopes_string],
    );

    if (insert_result.is_err()) {
        Err("failed to insert to db".to_string())
    } else {
        Ok(string)
    }
}

// TODO return whole entry
fn get_entry_by_auth_code(
    auth_code: &str,
    connection: &Connection,
) -> Result<Option<String>, RusqliteError> {
    let mut statement = connection
        .prepare("SELECT subject FROM authorization_code WHERE auth_code = ?1")?;
    let mut rows = statement
        .query(params![auth_code])?;

    if let Some(row) = rows.next()? {
        let result = row.get(0);
        match result {
            Ok(result) => Ok(result),
            Err(_) => Ok(None),
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString};
    use rusqlite::Connection;
    use rusqlite_migration::{Migrations, M};

    use crate::repository::{create_auth_code, get_entry_by_auth_code};

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
        let code = create_auth_code("user", scopes, &conn).unwrap();
        assert_ne!(0, code.len());
    }

    #[test]
    fn should_retrieve_stored_entry() {
        // TODO: one common place to store migrations
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
        let code = create_auth_code("user", scopes, &conn).unwrap();
        let response =
            get_entry_by_auth_code(code.as_str(), &conn).expect("failed to get by auth code");

        assert!(response.is_some());
        let string = response.unwrap();
        assert_eq!("user", string);
    }

    #[test]
    fn should_return_none_if_invalid_code() {
        // TODO: one common place to store migrations
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

        let code = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let response =
            get_entry_by_auth_code(code.as_str(), &conn).expect("failed to get auth code");
        assert!(response.is_none());
    }
}

use std::error::Error;
use std::fmt::{Display, Formatter};

use rand::distributions::{Alphanumeric, DistString};
use rusqlite::{params, Connection};
use rusqlite_migration::{Migrations, M};

use crate::repository::authorization_code_entry::AuthorizationCodeEntry;
use crate::repository::DatabaseError::{ConnectionError, RowNotFound};

mod authorization_code_entry;

const TOKEN_LENGTH: usize = 32;

pub fn apply_migrations(mut conn: &mut Connection) {
    let migrations = Migrations::new(vec![
        M::up("create table authorization_code(auth_code TEXT PRIMARY KEY, subject TEXT NOT NULL, scopes TEXT NOT NULL);")
            .down("drop table authorization_code;"),
        M::up("create table user(username text NOT NULL UNIQUE, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL);")
            .down("drop table user;"),
        // In the future, add more migrations here:
    ]);
    migrations.to_latest(&mut conn).unwrap();
}

pub fn create_auth_code(
    username: &str,
    scopes: Vec<&str>,
    connection: &Connection,
) -> Result<String, String> {
    let string = Alphanumeric.sample_string(&mut rand::thread_rng(), TOKEN_LENGTH);

    // here
    let scopes_string = scopes.join(",");

    let insert_result = connection.execute(
        "INSERT INTO authorization_code (auth_code, subject, scopes) VALUES (?1, ?2, ?3)",
        params![&string, username, scopes_string],
    );

    if insert_result.is_err() {
        Err("failed to insert to db".to_string())
    } else {
        Ok(string)
    }
}

#[derive(Debug)]
enum DatabaseError {
    RowNotFound,
    ConnectionError,
    // Add more error variants as needed
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DatabaseError {}

fn get_entry_by_auth_code(
    auth_code: &str,
    connection: &Connection,
) -> Result<AuthorizationCodeEntry, DatabaseError> {
    let mut statement = connection
        .prepare("SELECT subject, scopes FROM authorization_code WHERE auth_code = ?1")
        .map_err(|_| ConnectionError)?;

    let mut rows = statement
        .query_map(params![auth_code], |row| {
            Ok(AuthorizationCodeEntry::new(row.get(0)?, row.get(1)?))
        })
        .map_err(|_| ConnectionError)?;

    match rows.next() {
        None => Err(RowNotFound),
        Some(result) => match result {
            Ok(result) => Ok(result),
            Err(_) => Err(RowNotFound),
        },
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString};
    use rusqlite::Connection;

    use crate::repository::{
        apply_migrations, create_auth_code, get_entry_by_auth_code, DatabaseError, TOKEN_LENGTH,
    };

    #[test]
    fn should_return_generated_code() {
        let mut conn = Connection::open_in_memory().unwrap();

        apply_migrations(&mut conn);

        let scopes = vec!["scope"];
        let code = create_auth_code("user", scopes, &conn).unwrap();
        assert_ne!(0, code.len());
    }

    #[test]
    fn should_retrieve_stored_entry() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn);

        let scopes = vec!["scope"];
        let code = create_auth_code("user", scopes, &conn).unwrap();
        let response = get_entry_by_auth_code(code.as_str(), &conn);

        assert!(response.is_ok());
        let auth_code_entry = response.unwrap();
        assert_eq!("user", auth_code_entry.subject);
    }

    #[test]
    fn should_retrieve_all_stored_scopes() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn);

        let scopes = vec!["there", "are", "many", "scopes"];
        let code = create_auth_code("user", scopes, &conn).unwrap();
        let response = get_entry_by_auth_code(code.as_str(), &conn);
        assert!(response.is_ok());

        let auth_code_entry = response.unwrap();
        let scopes = auth_code_entry.scopes;
        assert_eq!(4, scopes.len());
        assert!(scopes.contains(&"there".to_string()));
        assert!(scopes.contains(&"are".to_string()));
        assert!(scopes.contains(&"many".to_string()));
        assert!(scopes.contains(&"scopes".to_string()));
    }

    #[test]
    fn should_return_none_if_invalid_code() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn);

        let code = Alphanumeric.sample_string(&mut rand::thread_rng(), TOKEN_LENGTH);
        let response = get_entry_by_auth_code(code.as_str(), &conn);
        match response {
            Ok(_) => panic!("should not return OK"),
            Err(err) => assert_eq!(DatabaseError::RowNotFound.to_string(), err.to_string()),
        }
    }
}

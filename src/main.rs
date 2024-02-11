use std::process::exit;

use clap::{arg, Command};
use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};
use crate::authentication::user_store::User;

pub mod authentication;

fn cli() -> Command {
    Command::new("cable_lock")
        .about("Local secret storage for linux")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("authorization_request")
                .about("Grant authorization for a client requesting to access resources")
                .arg(arg!(<SCOPE> "The requested scope"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("token")
                .about("Exchange authorization grant for access token")
                .arg(arg!(<AUTH_CODE> "Authorization grant"))
                .arg_required_else_help(true),
        )
}



fn main() {
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


    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("authorization_request", sub_matches)) => {
            let scope = sub_matches.get_one::<String>("SCOPE").expect("required");
            let input_reader = authentication::input_reader::InputReaderImpl;
            let user_store = authentication::user_store::UserStoreFake;
            match authentication::authenticate(&input_reader, &user_store) {
                Ok(_) => {
                    println!("SUCCESS");
                    println!("requested {}", scope);
                }
                Err(err) => {
                    eprintln!("{}", err);
                    exit(1)
                }
            }
        }
        Some(("token", sub_matches)) => {
            conn.execute("INSERT INTO user (username, password_hash, password_salt) VALUES ('test_user', 'hashed_password', 'random_salt');", ()).expect("failed to insert user");
            let user = conn.query_row("SELECT username, password_hash, password_salt from user where username = 'test_user';", (), |row| {
               Ok(User{
                   username: row.get(0)?,
                   hash: row.get(1)?,
                   salt: row.get(2)?,
               }) 
            }).expect("failed to get user");
            println!("{:?}", user);
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }
    };
}

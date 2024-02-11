use std::process::exit;

use crate::repository::{apply_migrations, create_auth_code};
use clap::{arg, Command};
use rusqlite::Connection;

pub mod authentication;
pub mod repository;

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
    let matches = cli().get_matches();

    let mut conn = Connection::open("./storage.db").unwrap();
    apply_migrations(&mut conn);

    match matches.subcommand() {
        Some(("authorization_request", sub_matches)) => {
            let scope = sub_matches.get_one::<String>("SCOPE").expect("required");
            let input_reader = authentication::input_reader::InputReaderImpl;
            let user_store = authentication::user_store::UserStoreFake;
            match authentication::authenticate(&input_reader, &user_store) {
                Ok(_) => {
                    let token = create_auth_code("username", vec![scope], &mut conn);
                    match token {
                        Ok(token) => {
                            println!("{}", token);
                        }
                        Err(_) => eprintln!("failed to get token"),
                    }
                }
                Err(err) => {
                    eprintln!("{}", err);
                    exit(1)
                }
            }
        }
        Some(("token", _sub_matches)) => {
            // TODO
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }
    };
}

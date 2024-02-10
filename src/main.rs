use std::process::exit;

use clap::{arg, Command};

pub mod authentication;

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

fn main() {
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("authorization_grant", sub_matches)) => {
            let scope = sub_matches.get_one::<String>("SCOPE").expect("required");
            let input_reader = authentication::InputReader::InputReaderImpl;
            let user_store = authentication::UserStore::UserStoreFake;
            match authentication::authenticate(&input_reader, &user_store) {
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

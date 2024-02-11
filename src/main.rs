use std::process::exit;

use clap::{arg, Command};

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
        Some(("token", _sub_matches)) => {
            // TODO
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }
    };
}

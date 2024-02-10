use clap::{arg, Command};

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
            println!(
                "requested {}",
                scope
            );
        }
        _ => {
            cli().print_help().expect("failed to print help");
        }

    };
}

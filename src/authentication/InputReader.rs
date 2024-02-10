use std::io;
use std::io::Write;

pub(crate) trait InputReader {
    fn get_username_and_password(&self) -> (String, String);
}

pub(crate) struct InputReaderImpl;
impl InputReader for InputReaderImpl {
    fn get_username_and_password(&self) -> (String, String) {
        print!("Username: ");
        io::stdout().flush().expect("Couldn't flush stdout");

        let mut user_name = String::new();
        io::stdin()
            .read_line(&mut user_name)
            .expect("Failed to read line");

        let password = rpassword::prompt_password("Password: ").unwrap();

        (user_name.trim().to_string(), password)
    }
}

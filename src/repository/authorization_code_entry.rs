struct AuthorizationCodeEntry {
    auth_code: String,
    subject: String,
    scopes: Vec<String>,
}

impl AuthorizationCodeEntry {
    fn new(auth_code: String, subject: String, scopes: String) -> Self {
        let scopes: Vec<String> = scopes.split(',').map(String::from).collect();

        AuthorizationCodeEntry {
            auth_code,
            subject,
            scopes,
        }
    }
}

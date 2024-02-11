pub struct AuthorizationCodeEntry {
    pub subject: String,
    pub scopes: Vec<String>,
}

impl AuthorizationCodeEntry {
    pub(crate) fn new(subject: String, scopes: String) -> Self {
        let scopes: Vec<String> = scopes.split(',').map(String::from).collect();

        AuthorizationCodeEntry { subject, scopes }
    }
}

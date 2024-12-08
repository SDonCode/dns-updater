use dotenv::dotenv;

#[derive(Debug)]
pub struct Config {
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_hosted_zone_id: String,
    pub record_name: String,
    pub dns_provider: String,
    pub transip_private_key: String,
    pub transip_login: String
}

impl Config {
    pub fn new() -> Self {
        match dotenv() {
            Ok(_) => println!("Loaded .env file"),
            Err(e) => println!("Failed to load .env file: {:?}", e),
        }

        Config {
            aws_access_key_id: std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID must be set"),
            aws_secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY must be set"),
            aws_hosted_zone_id: std::env::var("HOSTED_ZONE_ID").expect("HOSTED_ZONE_ID must be set"),
            record_name: std::env::var("RECORD_NAME").expect("RECORD_NAME must be set"),
            dns_provider: std::env::var("DNS_PROVIDER").expect("DNS Provider must be set"),
            transip_private_key: std::env::var("TRANSIP_PRIVATE_KEY").expect("TRANSIP_PRIVATE_KEY must be set"),
            transip_login: std::env::var("TRANSIP_LOGIN").expect("TRANSIP_LOGIN must be set"),
        }
    }
}
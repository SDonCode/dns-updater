use dotenv::dotenv;

pub struct Config {
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub hosted_zone_id: String,
    pub record_name: String,
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
            hosted_zone_id: std::env::var("HOSTED_ZONE_ID").expect("HOSTED_ZONE_ID must be set"),
            record_name: std::env::var("RECORD_NAME").expect("RECORD_NAME must be set"),
        }
    }
}
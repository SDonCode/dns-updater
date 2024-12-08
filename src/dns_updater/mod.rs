use crate::ip_fetcher::IpAddress;
use aws_config::BehaviorVersion;
use aws_sdk_route53::types::{Change, ChangeAction, ChangeBatch, ResourceRecord, RrType};
use aws_sdk_route53::Client;
use aws_sdk_route53::Error as Route53Error;
use reqwest::Client as ReqwestClient;

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde_json::json;
use sha2::Sha512;
use uuid::Uuid;

use crate::config::Config;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsUpdaterError {
    #[error("Failed to update IP address")]
    Route53Error(#[from] Route53Error),
    #[error("Failed to update TransIP: {0}")]
    TransIpError(String),
}

pub type DnsUpdaterResult<T> = Result<T, DnsUpdaterError>;

pub enum DnsUpdaterType {
    Route53(Route53Updater),
    TransIp(TransIpUpdater),
}

impl DnsUpdaterType {
    pub async fn new(config: Config) -> Self {
        // Use transip if specified in the config
        if config.dns_provider == "transip" {
            DnsUpdaterType::TransIp(TransIpUpdater::new(config).await)
        // or default to Route53
        } else {
            DnsUpdaterType::Route53(Route53Updater::new(config).await)
        }
    }
}
impl DnsUpdater for DnsUpdaterType {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool> {
        match self {
            DnsUpdaterType::Route53(updater) => updater.requires_update(ip).await,
            DnsUpdaterType::TransIp(updater) => updater.requires_update(ip).await,
        }
    }

    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()> {
        match self {
            DnsUpdaterType::Route53(updater) => updater.update_ip(ip).await,
            DnsUpdaterType::TransIp(updater) => updater.update_ip(ip).await,
        }
    }
}

pub trait DnsUpdater: Send + Sync {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool>;
    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()>;
}
pub struct Route53Updater {
    client: Client,
    config: Config,
    last_known_ip: Option<IpAddress>,
}

pub struct TransIpUpdater {
    client: TransIpClient,
    config: Config,
    last_known_ip: Option<IpAddress>,
}
impl TransIpUpdater {
    pub async fn new(config: Config) -> Self {
        let client = TransIpClient::new(
            config.transip_private_key.clone(),
            config.transip_login.clone(),
            "DynDNS30s".to_string(),
        );

        TransIpUpdater {
            last_known_ip: None,
            client,
            config,
        }
    }
}

impl DnsUpdater for TransIpUpdater {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool> {
        if let Some(ip_address) = &self.last_known_ip {
            return Ok(!ip_address.eq(&ip));
        }

        // Get token for authentication
        let token = self
            .client
            .get_token()
            .await
            .map_err(|e| DnsUpdaterError::TransIpError(e.to_string()))?;

        // Fetch current DNS entries
        let entries = self
            .client
            .get_dns_entries(&self.config.record_name, &token)
            .await
            .map_err(|e| DnsUpdaterError::TransIpError(e.to_string()))?;

        // Find the matching A record
        let current_ip = entries
            .iter()
            .find(|entry| entry.name == self.config.record_name && entry.entry_type == "A")
            .map(|entry| IpAddress {
                address: entry.content.clone(),
            });

        if let Some(current_ip) = current_ip {
            self.last_known_ip = Some(current_ip.clone());
            Ok(!current_ip.eq(ip))
        } else {
            Ok(true) // No existing record found, update needed
        }
    }
    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()> {
        let token = self
            .client
            .get_token()
            .await
            .map_err(|e| DnsUpdaterError::TransIpError(e.to_string()))?;
        println!("Hello: {token}");

        // Implement the update logic here using the token and IP
        // This would involve making a PATCH request to the TransIP API

        self.last_known_ip = Some(ip.to_owned());
        Ok(())
    }
}

impl DnsUpdater for Route53Updater {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool> {
        if let Some(ip_address) = &self.last_known_ip {
            println!("Using last known IP: {}", ip_address.address);
            return Ok(!ip_address.eq(&ip));
        } else {
            println!("No known last ip");
        }

        let result = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&self.config.aws_hosted_zone_id)
            .send()
            .await
            .map_err(|err| DnsUpdaterError::Route53Error(err.into()))?;

        let resource_record_set = result
            .resource_record_sets
            .into_iter()
            .find(|record| {
                record.name == self.config.record_name
                    || record.name == format!("{}.", self.config.record_name)
            })
            .expect("Record not found");

        let resource_record = resource_record_set
            .resource_records
            .expect("No resource records found")
            .first()
            .expect("No resource records found")
            .clone();

        let current_ip = IpAddress {
            address: resource_record.value().to_owned(),
        };

        self.last_known_ip = Some(current_ip.clone());

        Ok(!current_ip.eq(&ip))
    }

    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()> {
        // Use route53 API to update the IP address
        println!("Updating IP address to: {}", ip.address);

        let resource_record = ResourceRecord::builder()
            .value(ip.address.clone())
            .build()
            .unwrap();
        let resource_record_set = aws_sdk_route53::types::ResourceRecordSet::builder()
            .name(&self.config.record_name)
            .r#type(RrType::A)
            .ttl(300)
            .resource_records(resource_record)
            .build()
            .unwrap();
        let changes = Change::builder()
            .action(ChangeAction::Upsert)
            .resource_record_set(resource_record_set)
            .build()
            .unwrap();

        let change = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(&self.config.aws_hosted_zone_id)
            .change_batch(ChangeBatch::builder().changes(changes).build().unwrap())
            .send()
            .await
            .map_err(|err| DnsUpdaterError::Route53Error(err.into()))?;

        self.last_known_ip = Some(ip.to_owned());

        println!("{:?}", change);

        Ok(())
    }
}

impl Route53Updater {
    pub async fn new(config: Config) -> Self {
        let sdk_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = Client::new(&sdk_config);

        Route53Updater {
            last_known_ip: None,
            client,
            config,
        }
    }
}

pub struct TransIpClient {
    http_client: ReqwestClient,
    private_key: String,
    login: String,
    label: String,
}
impl TransIpClient {
    pub fn new(private_key: String, login: String, label: String) -> Self {
        Self {
            http_client: ReqwestClient::new(),
            private_key,
            login,
            label,
        }
    }
    fn sign_message(&self, message: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        // Parse the PEM-encoded private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(&self.private_key)?;
        
        // Create a signing key
        let signing_key = SigningKey::<Sha512>::new(private_key);
        
        // Sign the message
        let signature = signing_key.sign(message);
        
        // Convert to base64
        Ok(base64::encode(signature.as_bytes()))
    }

    async fn get_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Uuid::new_v4().to_string();

        let request_body = json!({
            "login": self.login,
            "nonce": nonce,
            "read_only": false,
            "expiration_time": "30 seconds",
            "label": self.label,
            "global_key": true
        });

        let response = self
            .http_client
            .post("https://api.transip.nl/v6/auth")
            .json(&request_body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        println!("{:?}", response);

        response["token"]
            .as_str()
            .map(|token| token.to_string())
            .ok_or_else(|| "Token not found in response".into())
    }

    async fn get_dns_entries(
        &self,
        domain: &str,
        token: &str,
    ) -> Result<Vec<DnsEntry>, Box<dyn std::error::Error>> {
        let response = self
            .http_client
            .get(&format!("https://api.transip.nl/v6/domains/{}/dns", domain))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        // Parse DNS entries from response
        // This is a simplified version - you'll need to implement proper parsing based on your needs
        Ok(vec![]) // Placeholder return
    }
    pub async fn update_dns_entry(
        &self,
        domain: &str,
        token: &str,
        dns_entry: DnsEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request_body = json!({
            "dnsEntry": {
                "name": dns_entry.name,
                "type": dns_entry.entry_type,
                "content": dns_entry.content,
                // Using same TTL as Route53 implementation
                "expire": 300
            }
        });

        self.http_client
            .patch(&format!("https://api.transip.nl/v6/domains/{}/dns", domain))
            .header("Authorization", format!("Bearer {}", token))
            .json(&request_body)
            .send()
            .await?;

        Ok(())
    }
}
#[derive(Debug, Clone)]
struct DnsEntry {
    name: String,
    content: String,
    entry_type: String,
}

#[cfg(test)]
mod dns_updater_tests {
    use crate::config::Config;
    use crate::dns_updater::{DnsUpdater, Route53Updater};
    use crate::ip_fetcher::IpAddress;

    #[tokio::test]
    async fn requires_update() {
        let ip_address = IpAddress {
            address: "*IP_address".to_owned(),
        };

        let config = Config::new();

        let mut updater = Route53Updater::new(config).await;

        let requires_update = updater
            .requires_update(&ip_address)
            .await
            .expect("Couldnt check");

        assert_eq!(requires_update, false);

        let ip_address = IpAddress {
            address: "127.0.0.1".to_owned(),
        };

        let requires_update = updater
            .requires_update(&ip_address)
            .await
            .expect("Couldnt check");

        assert_eq!(requires_update, true);
    }

    #[tokio::test]
    async fn test_dns_updater() {
        let ip_address = IpAddress {
            address: "*IP_address*".to_owned(),
        };

        let config = Config::new();

        let mut updater = Route53Updater::new(config).await;

        updater
            .update_ip(&ip_address)
            .await
            .expect("Couldnt update");
    }
}

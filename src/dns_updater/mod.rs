use aws_config::BehaviorVersion;
use aws_sdk_route53::{Client, Error};
use aws_sdk_route53::types::{Change, ChangeAction, ChangeBatch, ResourceRecord, RrType};
use crate::ip_fetcher::IpAddress;

use thiserror::Error;
use crate::config::Config;

#[derive(Error, Debug)]
pub enum DnsUpdaterError {
    #[error("Failed to update IP address")]
    UpdateError(#[from] Error),
}

pub type DnsUpdaterResult<T> = Result<T, DnsUpdaterError>;

pub trait DnsUpdater {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool>;
    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()>;
}

pub struct Route53Updater {
    client: Client,
    config: Config,
    last_known_ip: Option<IpAddress>,
}

impl DnsUpdater for Route53Updater {
    async fn requires_update(&mut self, ip: &IpAddress) -> DnsUpdaterResult<bool> {
        if let Some(ip_address) = &self.last_known_ip {
            println!("Using last known IP: {}", ip_address.address);
            return Ok(!ip_address.eq(&ip));
        } else {
            println!("No known last ip");
        }

        let result = self.client.list_resource_record_sets()
            .hosted_zone_id(&self.config.hosted_zone_id)
            .send()
            .await
            .map_err(|err| DnsUpdaterError::UpdateError(err.into()))?;

        let resource_record_set = result
            .resource_record_sets.into_iter()
            .find(|record| record.name == self.config.record_name || record.name == format!("{}.", self.config.record_name))
            .expect("Record not found");

        let resource_record = resource_record_set
            .resource_records
            .expect("No resource records found")
            .first()
            .expect("No resource records found")
            .clone();

        let current_ip = IpAddress {
            address: resource_record
                .value()
                .to_owned()
        };

        self.last_known_ip = Some(current_ip.clone());

        Ok(!current_ip.eq(&ip))
    }

    async fn update_ip(&mut self, ip: &IpAddress) -> DnsUpdaterResult<()> {
        // Use route53 API to update the IP address
        println!("Updating IP address to: {}", ip.address);

        let resource_record = ResourceRecord::builder().value(ip.address.clone()).build().unwrap();
        let resource_record_set = aws_sdk_route53::types::ResourceRecordSet::builder()
            .name(&self.config.record_name)
            .r#type(RrType::A)
            .ttl(300)
            .resource_records(resource_record)
            .build()
            .unwrap();
        let changes = Change::builder().action(ChangeAction::Upsert).resource_record_set(
            resource_record_set
        ).build()
            .unwrap();

        let change = self.client.change_resource_record_sets()
            .hosted_zone_id(&self.config.hosted_zone_id)
            .change_batch(ChangeBatch::builder()
                .changes(changes)
                .build()
                .unwrap())
            .send()
            .await
            .map_err(|err| DnsUpdaterError::UpdateError(err.into()))?;

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
            config
        }
    }
}

#[cfg(test)]
mod dns_updater_tests {
    use crate::config::Config;
    use crate::dns_updater::{DnsUpdater, Route53Updater};
    use crate::ip_fetcher::IpAddress;

    #[tokio::test]
    async fn requires_update() {
        let ip_address = IpAddress {
            address: "*IP_address".to_owned()
        };

        let config = Config::new();

        let mut updater = Route53Updater::new(config).await;

        let requires_update = updater.requires_update(&ip_address).await.expect("Couldnt check");

        assert_eq!(requires_update, false);

        let ip_address = IpAddress {
            address: "127.0.0.1".to_owned()
        };

        let requires_update = updater.requires_update(&ip_address).await.expect("Couldnt check");

        assert_eq!(requires_update, true);
    }

    #[tokio::test]
    async fn test_dns_updater() {
        let ip_address = IpAddress {
            address: "*IP_address*".to_owned()
        };

        let config = Config::new();

        let mut updater = Route53Updater::new(config).await;

        updater.update_ip(&ip_address).await.expect("Couldnt update");
    }
}
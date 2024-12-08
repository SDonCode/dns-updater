use dns_updater::DnsUpdaterType;

use crate::dns_updater::DnsUpdater;
use crate::ip_fetcher::IpFetcher;

mod config;
mod dns_updater;
mod ip_fetcher;
mod transip_client;

#[tokio::main]
async fn main() {
    let config = config::Config::new();

    let fetcher = ip_fetcher::CanIHazIpFetcher {};

    // Use Box<dyn DnsUpdater> to handle both updater types
    let mut dns_updater = DnsUpdaterType::new(config).await;

    loop {
        let ip = fetcher
            .fetch_ip()
            .await
            .expect("Failed to fetch IP address");
        println!("IP: {:?}", ip);

        if dns_updater.requires_update(&ip).await.unwrap() {
            let update_result = dns_updater.update_ip(&ip).await;
            println!("Update result: {:?}", update_result);
        } else {
            println!("No update required");
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

#[cfg(test)]
mod full_tests {
    use super::*;
    use crate::dns_updater::DnsUpdater;
    use crate::ip_fetcher::IpFetcher;

    #[tokio::test]
    async fn test_integration() {
        let fetcher = ip_fetcher::CanIHazIpFetcher {};

        println!("Fetching IP");
        let ip = fetcher
            .fetch_ip()
            .await
            .expect("Failed to fetch IP address");

        println!("IP: {:?}", ip);

        let mock_config = config::Config::new();
        println!("CONFIG: {:?}", mock_config);

        let mut updater = dns_updater::Route53Updater::new(mock_config).await;

        if updater.requires_update(&ip).await.unwrap() {
            println!("Updating IP");
            updater.update_ip(&ip).await.expect("Failed to update IP");
        } else {
            println!("No update required");
        }
    }
}

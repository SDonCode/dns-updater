use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IpAddress {
    pub address: String,
}

#[derive(Error, Debug)]
pub enum IpFetcherError {
    #[error("Failed to fetch IP address")]
    FetchError(#[from] reqwest::Error),
}

pub type IpFetcherResult<T> = Result<T, IpFetcherError>;

pub trait IpFetcher {
    async fn fetch_ip(&self) -> IpFetcherResult<IpAddress>;
}

pub struct CanIHazIpFetcher {}

impl IpFetcher for CanIHazIpFetcher {
    async fn fetch_ip(&self) -> IpFetcherResult<IpAddress> {
        let address = reqwest::get("https://api.ipify.org").await?
            .text().await?;

        Ok(IpAddress {
            address,
        })
    }
}

#[cfg(test)]
pub mod ip_fetcher_test {
    use super::*;

    #[tokio::test]
    async fn test_ip_fetcher() {
        let fetcher = CanIHazIpFetcher {};
        let ip = fetcher.fetch_ip().await;

        println!("IP: {:?}", ip);
    }
}
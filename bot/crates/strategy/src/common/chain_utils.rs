use ethers::{
    providers::{Middleware, ProviderError},
    types::{BlockNumber, Address, U64, NameOrAddress, BlockId}
};
use log::{info, debug};
use std::sync::Arc;

pub async fn get_inception_block<M: Middleware>(
    contract: Address,
    provider: Arc<M>) -> Result<BlockNumber, ProviderError>
{
    let mut last_block =
        provider.get_block_number().await
                .map_err(|err| ProviderError::CustomError(err.to_string()))?;

        // I am very confused about how to do the pattern matching here because provide_err is a reference
        // to ProviderError.
        //    |err| match err.as_provider_error() {
        //        Some(provider_err) => ProviderError::from_err(provider_err),
        //        _ => ProviderError::CustomError(err.to_string())
        //    };

    let mut start_block = U64([1]);
    let mut rpc_count = 0;

    while start_block < last_block {
        let mid_block = start_block + (last_block - start_block) / 2;
        let code =
            provider.get_code(
                NameOrAddress::Address(contract),
                Some(BlockId::Number(BlockNumber::Number(mid_block))))
                .await;
        rpc_count += 1;
        debug!("Searching ({}) at block {:?} (start: {:?}, last: {:?}).",
               rpc_count, mid_block, start_block, last_block);
        match code {
            Ok(_) => {
                info!("Successfully find the code of contract {:?}, block {:?}.", contract, mid_block);
                last_block = mid_block;
            },
            Err(e) => {
                info!("Failed to find the code of contract {:?}, block {:?}, err({:?}).", contract, mid_block, e);
                start_block = mid_block + 1;
            }
        }
    }
    return Ok(BlockNumber::Number(start_block));
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::str::FromStr;
    use ethers::providers::{Provider, Ws};
    use env_logger;
    use super::*;

    // For some reason, the url below couldn't fetch code from the last 128 blocks.
    // So that we cannot use the binary search to find the contract creation block.
    // More details see https://ethereum.stackexchange.com/questions/40648/full-node-sync-only-preserve-the-last-128-history-states.
    // In short, the current get_inception_block only works in the archive node.

    #[tokio::test]
    async fn test_get_inception_block() -> Result<(), Box<dyn Error>>
    {
        env_logger::init();

        let contract = Address::from_str("0x115934131916C8b277DD010Ee02de363c09d037c")?;
        let url: &str =
            "wss://capable-crimson-vineyard.discover.quiknode.pro/b0f808fe30ebe9dd7b2a7122c563e20f1e9966da/";
        let provider = Arc::new(Provider::new(Ws::connect(url).await?));
        let block = get_inception_block(contract, provider).await?;
        assert_eq!(block.as_number().unwrap().as_u64(), 12771526u64);
        return Ok(());
    }
}
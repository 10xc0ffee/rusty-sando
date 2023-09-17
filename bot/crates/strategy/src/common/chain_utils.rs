use ethers::{
    abi::{Function, Param, ParamType, StateMutability, Token},
    prelude::{abigen, Abigen},
    providers::{Middleware, ProviderError},
    signers::{LocalWallet, Signer},
    middleware::SignerMiddleware,
    types::{BlockNumber, Address, U64, NameOrAddress, BlockId, Bytes, H256, Eip1559TransactionRequest, TransactionRequest}, abi::AbiEncode
};
/*
use foundry_evm::executor::{
    fork::{BlockchainDb, BlockchainDbMeta, SharedBackend},
    ExecutionResult,
    Output,
    TxEnv,
    TransactTo, BlockEnv
};
use foundry_evm::revm::{
    db::CacheDB,
    primitives::{Address as rAddress, U256 as rU256},
    EVM
};
*/
use log::{info, debug};
use std::{collections::BTreeSet, str::FromStr, sync::Arc, error::Error};

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
        log::info!("Searching ({}) at block {:?} (start: {:?}, last: {:?}).",
               rpc_count, mid_block, start_block, last_block);
        match code {
            Ok(bytes) => {
                if bytes.len() > 0 {
                    debug!("Successfully find the code of contract {:?}, block {:?}, codelen {:?}.",
                          contract, mid_block, bytes.len());
                    last_block = mid_block;
                } else {
                    debug!("Failed to find the code of contract {:?}, block {:?} codelen {:?}.",
                          contract, mid_block, bytes.len());
                    start_block = mid_block + 1;
                }
            },
            Err(e) => {
                log::info!("Failed to find the code of contract {:?}, block {:?}, err({:?}).", contract, mid_block, e);
                start_block = mid_block + 1;
            }
        }
    }
    return Ok(BlockNumber::Number(start_block));
}

pub async fn create_contract_with_vanity_address<M: Middleware>(
    expected_addr_prefix: &str,
    code_to_deploy: &str,
    wallet: &LocalWallet,
    provider: Arc<M>) -> Result<(), Box<dyn Error>>
    where M: 'static
{
    abigen!(
        ImmutableCreate2Factory,
        r#"[
            function safeCreate2(bytes32 salt, bytes calldata initializationCode) external payable containsCaller(salt) returns (address deploymentAddress)
            function findCreate2Address(bytes32 salt, bytes calldata initCode) external view returns (address deploymentAddress)
            function hasBeenDeployed(address deploymentAddress) external view returns (bool)
        ]"#
    );
    let safe_create2_factory =
        Address::from_str("0x0000000000FFe8B47B3e2130213B802212439497").unwrap();
    let safe_create2_contract =
        ImmutableCreate2Factory::new(safe_create2_factory, provider.clone());
    let mut found_expected_prefix = false;
    let mut salt: H256 = H256::zero();
    let mut low12bytes = 0;
    while !found_expected_prefix {
        let prefix = format!("{:#x}", safe_create2_factory);
        let random = format!("{:#x}", low12bytes);
        low12bytes += 1;
        let tmp_salt =
            format!("{}{:0>24}",
                    prefix.get(0..).unwrap(),
                    random.get(2..).unwrap());
        salt = tmp_salt.parse().unwrap();
        match safe_create2_contract
            .find_create_2_address(
                salt.into(),
                Bytes::from_str(code_to_deploy)?)
            .call().await
        {
            Ok(address) => {
                log::info!("Dry run contract create at address {address:?} with salt {salt:?}");
                let addr_str: String = address.to_string();
                if addr_str.find(expected_addr_prefix) == Some(0) {
                    if let Ok(deployed) = safe_create2_contract
                        .has_been_deployed(
                            address)
                        .call().await
                    {
                        if !deployed {
                            found_expected_prefix = true;
                        }
                    }
                }
            },
            Err(e) => {
                log::error!("Failed to call contract find_create2_address. Error: {e:?}");
                return Err(e.into());
            }
        }
    }

    /*
    // Simulate the transaction in local EVM to get the gas estimation.
    let shared_backend =
        SharedBackend::spawn_backend_thread(
            provider.clone(),
            BlockchainDb::new(
                BlockchainDbMeta {
                    cfg_env: Default::default(),
                    block_env: Default::default(),
                    hosts: BTreeSet::from(["".to_string()])
                },
                None
            ),
            Some(BlockId::Number(BlockNumber::Latest)));
    let fork_db = CacheDB::new(shared_backend);
    let mut evm = EVM::new();
    evm.database(fork_db);
    */
    let client =
        SignerMiddleware::new(provider.clone(), wallet.clone());
    //safeCreate2(bytes32,bytes calldata) external payable returns (address deploymentAddress)
    #[allow(deprecated)]
    let function = Function {
        name: "safeCreate2".to_owned(),
        inputs: vec![
            Param { name: "".to_owned(), kind: ParamType::FixedBytes(32), internal_type: None },
            Param { name: "".to_owned(), kind: ParamType::Bytes, internal_type: None },
        ],
        outputs: vec![
            Param {name: "".to_owned(), kind: ParamType::Address, internal_type: None},
        ],
        constant: Some(false),
        state_mutability: StateMutability::Payable
    };
    let encoded_salt = Token::FixedBytes(salt.to_fixed_bytes().into());
    let encoded_code = Token::Bytes(code_to_deploy.into());
    log::info!("Function signature {:?}", function.signature());
    let tx =
        TransactionRequest::new()
        .to(safe_create2_factory)
        .value(500000000000000000u64)
        .gas(2000000)
        .data(function.encode_input(&[encoded_salt, encoded_code]).unwrap());
    //let tx =
    //    client.send_transaction(tx, None).await?.await?;
    log::info!("Completed Transaction. Receipt: {tx:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        str::FromStr,
        env
    };
    use ethers::providers::{Provider, Ws};
    use env_logger;
    use dotenv::dotenv;
    use anyhow::{anyhow, Result};
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
        let url: &str = "ws://192.168.0.12:8545/";
        let provider = Arc::new(Provider::new(Ws::connect(url).await?));
        let block = get_inception_block(contract, provider).await?;
        assert_eq!(block.as_number().unwrap().as_u64(), 12771526u64);
        return Ok(());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_create_sando_huff() -> Result<(), Box<dyn Error>>
    {
        dotenv().ok();

        let get_env = |var| {
            env::var(var).map_err(|_| anyhow!("Required environment variable \"{}\" not set", var))
        };

        let searcher_signer = get_env("SEARCHER_PRIVATE_KEY")?
            .parse::<LocalWallet>()
            .map_err(|_| anyhow!("Failed to parse \"SEARCHER_PRIVATE_KEY\""))?;

        let url: &str = "ws://192.168.0.12:8545/";
        let provider =
            Arc::new(Provider::new(Ws::connect(url).await?));

        // The code is generated by "huffc src/sando.huff --bytecode"
        let code_to_deploy = "61085d80600a3d393df35f355f1a565b6104d0565b610624565b61057a565b6106e5565b61043a565b6102d1565b61038c565b61022e565b6107a6565b6107c6565b6107ec56000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005b6099357fff000000000000000000000000000000000000000000000000000000000000005f527f1f98431c8ad98523631ae4a59f267346ea31f98400000000000000000000000046526015527fe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b5460355260555f2073ffffffffffffffffffffffffffffffffffffffff16331415610858575f5f60445f5f7effffffffffffffffffffffffffffffffffffffff00000000000000000000006084351660581c60843560f81c6101f8577fa9059cbb000000000000000000000000000000000000000000000000000000005f52336004526024356024525af11561085857005b7fa9059cbb000000000000000000000000000000000000000000000000000000005f52336004526004356024525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60f95f5f463560601c7f128acb08000000000000000000000000000000000000000000000000000000005f5230600452620186a0340260445273fffd8963efd1fc6a506488495d951d5263988d2560645260a0608452603560a45273c02aaa39b223fe8d0a0e5c4f27ead9083c756cc260581b60c45260153560d9525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60f95f5f463560601c7f128acb08000000000000000000000000000000000000000000000000000000005f52306004526001602452620186a034026044526401000276ad60645260a0608452603560a4527f010000000000000000000000000000000000000000000000000000000000000073c02aaa39b223fe8d0a0e5c4f27ead9083c756cc260581b0160c45260153560d9525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60f95f5f463560601c7f128acb08000000000000000000000000000000000000000000000000000000005f523060045260016024526049358060081b905f1a526401000276ad60645260a0608452603560a4527f010000000000000000000000000000000000000000000000000000000000000060153560601c60581b0160c45260293560d9525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60f95f5f463560601c7f128acb08000000000000000000000000000000000000000000000000000000005f52306004526049358060081b905f1a5273fffd8963efd1fc6a506488495d951d5263988d2560645260a0608452603560a45260153560601c60581b60c45260293560d9525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60a45f5f463560601c5f5f7fa9059cbb000000000000000000000000000000000000000000000000000000005f52826004526029358060081b905f1a5260445f5f60153560601c5af1507f022c0d9f000000000000000000000000000000000000000000000000000000005f52620186a034026004525f6024523060445260806064525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60a45f5f463560601c5f5f7fa9059cbb000000000000000000000000000000000000000000000000000000005f52826004526029358060081b905f1a5260445f5f60153560601c5af1507f022c0d9f000000000000000000000000000000000000000000000000000000005f525f600452620186a034026024523060445260806064525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60a45f5f463560601c5f5f7f23b872dd000000000000000000000000000000000000000000000000000000005f523060045282602452620186a0340260445260645f5f73c02aaa39b223fe8d0a0e5c4f27ead9083c756cc25af1507f022c0d9f000000000000000000000000000000000000000000000000000000005f525f6004525f6024526015358060081b905f1a523060445260806064525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f60a45f5f463560601c5f5f7f23b872dd000000000000000000000000000000000000000000000000000000005f523060045282602452620186a0340260445260645f5f73c02aaa39b223fe8d0a0e5c4f27ead9083c756cc25af1507f022c0d9f000000000000000000000000000000000000000000000000000000005f525f6004526015358060081b905f1a525f6024523060445260806064525af11561085857005b73e65575c0e8abd40d32c4c0fb528c5569b53401353314156108585733ff005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858575f5f5f5f47335af1005b73e65575c0e8abd40d32c4c0fb528c5569b5340135331415610858577fa9059cbb0000000000000000000000000000000000000000000000000000000059523360045246356024525f5f60445f5f73c02aaa39b223fe8d0a0e5c4f27ead9083c756cc25af11561085857005b600380fd";
        while true {
            match create_contract_with_vanity_address(
                "00000000", &code_to_deploy, &searcher_signer, provider.clone()).await
            {
                Ok(()) => break,
                _ => continue
            }
        }
        return Ok(());
    }
}
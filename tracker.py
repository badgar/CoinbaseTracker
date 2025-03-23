from web3 import Web3
import asyncio

w3 = Web3(Web3.HTTPProvider(''))

# Sourced from https://dune.com/queries/3237025, crosschecked with Etherscan and MetaSuites tags to ensure correctness
COINBASE_WALLETS = {addr.lower() for addr in [
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3",
        "0x503828976d22510aad0201ac7ec88293211d23da",
        "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740",
        "0x3cd751e6b0078be393132286c442345e5dc49699",
        "0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511",
        "0xeb2629a2734e272bcc07bda959863f316f4bd4cf",
        "0xd688aea8f7d450909ade10c47faa95707b0682d9",
        "0x02466e547bfdab679fc49e96bbfc62b9747d997c",
        "0x6b76f8b1e9e59913bfe758821887311ba1805cab",
        "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43",
        "0x77696bb39917c91a0c3908d577d5e322095425ca",
        "0x7c195d981abfdc3ddecd2ca0fed0958430488e34",
        "0x95a9bd206ae52c4ba8eecfc93d18eacdd41c88cc",
        "0xb739d0895772dbb71a89a3754a160269068f0d45",
        "0x4a4e859565d9b563afc8e63641542455cff0dfd2",
        "0xe1a0ddeb9b5b55e489977b438764e60e314e917c",
        "0x19ab546e77d0cd3245b2aad46bd80dc4707d6307",
        "0xc070a61d043189d99bbf4baa58226bf0991c7b11",
        "0xc8373edfad6d5c5f600b6b2507f78431c5271ff5",
        "0xb624219480543c54603fb6b07d5eb347e51bffe0",
        "0x20fe51a9229eef2cf8ad9e89d91cab9312cf3b7a",
        "0x333d17d3b42bf7930dbc6e852ca7bcf560a69003",
        "0x9810762578accf1f314320cca5b72506ae7d7630",
        "0x3dd1d15b3c78d6acfd75a254e857cbe5b9ff0af2",
        "0xf491d040110384dbcf7f241ffe2a546513fd873d",
        "0xc7bf35c9a3bdd1b1c19a6963de669cb45191a019",
        "0x05e3a758fdd29d28435019ac453297ea37b61b62",
        "0xa3682fe8fd73b90a7564585a436ec2d2aeb612ee",
        "0x739120ade7ed878fca5bbdb806263a8258fe2360",
        "0x8af8485e1f178be06386cd3877fde20626e0284f",
        "0x6dcbce46a8b494c885d0e7b6817d2b519df64467",
        "0xa656f7d2a93a6f5878aa768f24eb38ec8c827fe2",
        "0x7830c87c02e56aff27fa8ab1241711331fa86f43",
        "0xd34ea7278e6bd48defe656bbe263aef11101469c",
        "0xe68ee8a12c611fd043fb05d65e1548dc1383f2b9",
        "0x28c5b0445d0728bc25f143f8eba5c5539fae151a",
        "0xc9aaa6ca0e05b87d53a3e51edbc44b406eeaf299",
        "0x7ed53f6e3de6b2b4156fa8e618506e60d8e65843",
        "0x5122e9aa635c13afd2fc31de3953e0896bac7ab4",
        "0xd839c179a4606f46abd7a757f7bb77d7593ae249",
        "0x1985ea6e9c68e1c272d8209f3b478ac2fdb25c87",
        "0xb4807865a786e9e9e26e6a9610f2078e7fc507fb",
        "0x731307f3b12cc56191ade83ea630a377d9a941f6",
        "0x28e71d0b7f7f29106a1be2a5b289cab331e7b56f",
        "0xe86f3aaa57f63b2afeca68178182a91bc3909962",
        "0x563537412ad5d49faa7fa442b9193b8238d98c3c",
        "0x6321f9f02d9d56261c8c79131ae74d7b427ccaf5",
        "0x14af92363379f3548958f9de1fb2e6e5df74476e",
        "0xe3aac971590635f601ea751096f11343c70ebadf",
        "0xe7ee701bdaa5b446c985bfecc8933f3e5eeed867",
        "0x760dce7ea6e8ba224bffbeb8a7ff4dd1ef122bff",
        "0x4d8336bda6c11bd2a805c291ec719baedd10acb9",
        "0xb0fa34c866e1e1e7030820b4f846bb58d6f75b04",
        "0x2a410f11a6f520398447bf423dcedd25dfd3a568",
        "0x40ebc1ac8d4fedd2e144b75fe9c0420be82750c6",
        "0x3dd87411a3754deea8cc52c4cf57e2fc254924cc",
        "0x441cacfd43856409b163b90e094bb42aeb70a70e",
        "0xa14d57f5ea867572b0d239798d2c1dde13153902"
    ]
}

TRANSFER_EVENT_SIGNATURE = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
WETH = "0xC02aaa39b223FE8D0A0e5C4F27eaD9083C756Cc2"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
UNISWAP_V2_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
UNISWAP_V3_FACTORY = "0x1F98431c8aD98523631AE4a59f267346ea31F984"

# Most liquid WETH pool
WETH_POOL = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"

# Stablecoins
STABLECOINS = {USDC.lower(), USDT.lower()}

V3_FEE_TIERS = [100, 500, 3000, 10000]

UNISWAP_V2_FACTORY_ABI = '[{"constant":true,"inputs":[{"name":"tokenA","type":"address"},{"name":"tokenB","type":"address"}],"name":"getPair","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}]'
UNISWAP_V2_PAIR_ABI = '[{"constant":true,"inputs":[],"name":"token0","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"token1","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getReserves","outputs":[{"name":"_reserve0","type":"uint112"},{"name":"_reserve1","type":"uint112"},{"name":"_blockTimestampLast","type":"uint32"}],"payable":false,"stateMutability":"view","type":"function"}]'
UNISWAP_V3_FACTORY_ABI = '[{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint24","name":"fee","type":"uint24"}],"name":"getPool","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]'
UNISWAP_V3_POOL_ABI = '[{"inputs":[],"name":"slot0","outputs":[{"internalType":"uint160","name":"sqrtPriceX96","type":"uint160"},{"internalType":"int24","name":"tick","type":"int24"},{"internalType":"uint16","name":"observationIndex","type":"uint16"},{"internalType":"uint16","name":"observationCardinality","type":"uint16"},{"internalType":"uint16","name":"observationCardinalityNext","type":"uint16"},{"internalType":"uint8","name":"feeProtocol","type":"uint8"},{"internalType":"bool","name":"unlocked","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"liquidity","outputs":[{"internalType":"uint128","name":"","type":"uint128"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}]'
ERC20_ABI = '[{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"}]'

class TransactionStats:
    def __init__(self):
        self.incoming_usd = 0
        self.outgoing_usd = 0

    def add_transaction(self, amount_usd, is_incoming):
        if is_incoming:
            self.incoming_usd += amount_usd
        else:
            self.outgoing_usd += amount_usd

    @property
    def combined_total(self):
        return self.incoming_usd + self.outgoing_usd

    def merge(self, other_stats):
        """Add another stats object's values to this one"""
        self.incoming_usd += other_stats.incoming_usd
        self.outgoing_usd += other_stats.outgoing_usd
        return self

    def print_summary(self, block_number=None, is_final=False, is_running_total=False):
        if is_final:
            print("\n=== Final Summary ===")
        elif is_running_total:
            print("\n=== Running Totals ===")
        elif block_number:
            print(f"\n=== Block {block_number} Summary ===")
        print(f"Incoming: ${self.incoming_usd:,.2f}")
        print(f"Outgoing: ${self.outgoing_usd:,.2f}")
        print(f"Combined Total: ${self.combined_total:,.2f}")

_token_decimals_cache = {}
async def get_token_decimals(token_address):
    token_address = token_address.lower()

    if token_address in _token_decimals_cache:
        return _token_decimals_cache[token_address]

    token_contract = w3.eth.contract(
        address=Web3.to_checksum_address(token_address),
        abi=ERC20_ABI
    )
    decimals = token_contract.functions.decimals().call()
    _token_decimals_cache[token_address] = decimals
    return decimals

async def get_weth_price(block_num):

    pool = w3.eth.contract(address=WETH_POOL, abi=UNISWAP_V3_POOL_ABI)

    slot0 = pool.functions.slot0().call(block_identifier=block_num)
    sqrt_price_x96 = slot0[0]

    weth_decimals = 18
    usdc_decimals = 6

    # Since we're always using the same pool this does not change
    base_in_0 = False

    price = calculate_v3_price(sqrt_price_x96, weth_decimals, usdc_decimals, base_in_0)

    return price

async def get_v2_pool_contract(tokenA, tokenB):
    """Find the Uniswap V2 pool for two tokens"""
    factory = w3.eth.contract(address=UNISWAP_V2_FACTORY, abi=UNISWAP_V2_FACTORY_ABI)
    pair_address = factory.functions.getPair(
        Web3.to_checksum_address(tokenA),
        Web3.to_checksum_address(tokenB)
    ).call()

    # If there's no pool, we get the zero address
    if pair_address == "0x0000000000000000000000000000000000000000":
        return None

    return w3.eth.contract(address=pair_address, abi=UNISWAP_V2_PAIR_ABI)


async def get_v3_pool_contract(tokenA, tokenB, fee):
    """Find the Uniswap V3 pool for two tokens with a specific fee"""
    factory = w3.eth.contract(address=UNISWAP_V3_FACTORY, abi=UNISWAP_V3_FACTORY_ABI)
    pool_address = factory.functions.getPool(
        Web3.to_checksum_address(tokenA),
        Web3.to_checksum_address(tokenB),
        fee
    ).call()

    if pool_address == "0x0000000000000000000000000000000000000000":
        return None

    return w3.eth.contract(address=pool_address, abi=UNISWAP_V3_POOL_ABI)

def calculate_v3_price(sqrt_price_x96, decimals0, decimals1, base_in_0):

    price = sqrt_price_x96 * sqrt_price_x96 / (2 ** 192)

    if not base_in_0 and price != 0:
        return 1 / (price * (10 ** (decimals1 - decimals0)))
    else:
        return price * (10 ** (decimals0 - decimals1))

async def check_v3_pool(tokenA, tokenB, fee, block_number):

    try:
        pool = await get_v3_pool_contract(tokenA, tokenB, fee)
        if not pool:
            return None

        liquidity = pool.functions.liquidity().call(block_identifier=block_number)
        if liquidity == 0:
            return None

        token0 = pool.functions.token0().call()
        token1 = pool.functions.token1().call()

        slot0 = pool.functions.slot0().call(block_identifier=block_number)
        if slot0[0] == 0:
            return None

        dec0 = await get_token_decimals(token0)
        dec1 = await get_token_decimals(token1)

        return {
            'type': 'v3',
            'pool': pool,
            'liquidity': liquidity,
            'fee': fee,
            'address': pool.address,
            'token0': token0,
            'token1': token1,
            'decimals': (dec0, dec1),
            'slot0': slot0
        }
    except Exception as e:
        print(f"Error checking V3 pool with fee {fee}: {str(e)}")
        return None


async def check_all_pools(tokenA, tokenB, block_number):

    v3_pool_checks = [check_v3_pool(tokenA, tokenB, fee, block_number) for fee in V3_FEE_TIERS]
    v3_results = await asyncio.gather(*v3_pool_checks)

    v2_pool = await get_v2_pool_contract(tokenA, tokenB)
    v2_info = None

    if v2_pool:
        try:
            token0 = v2_pool.functions.token0().call()
            token1 = v2_pool.functions.token1().call()

            dec0 = await get_token_decimals(token0)
            dec1 = await get_token_decimals(token1)

            reserves = v2_pool.functions.getReserves().call(block_identifier=block_number)

            reserve0_adjusted = reserves[0] / (10 ** dec0)
            reserve1_adjusted = reserves[1] / (10 ** dec1)
            liquidity = (reserve0_adjusted * reserve1_adjusted) ** 0.5

            v2_info = {
                'type': 'v2',
                'pool': v2_pool,
                'liquidity': liquidity,
                'address': v2_pool.address,
                'token0': token0,
                'token1': token1,
                'reserves': reserves,
                'decimals': (dec0, dec1)
            }
        except Exception as e:
            print(f"Error checking V2 pool: {str(e)}")

    all_pools = [p for p in v3_results if p is not None]
    if v2_info:
        all_pools.append(v2_info)

    if not all_pools:
        return None

    return max(all_pools, key=lambda x: x['liquidity'])


async def get_price_from_pool_info(pool_info, tokenA, tokenB):
    try:
        tokenA = tokenA.lower()
        tokenB = tokenB.lower()

        # Compare values to determine which one is token0
        tokenA_int = int(tokenA.replace('0x', ''), 16)
        tokenB_int = int(tokenB.replace('0x', ''), 16)

        calculated_token0 = tokenA if tokenA_int < tokenB_int else tokenB

        base_in_0 = tokenA == calculated_token0

        if pool_info['type'] == 'v2':
            reserves = pool_info['reserves']
            dec0, dec1 = pool_info['decimals']
            reserve0 = reserves[0] / (10 ** dec0)
            reserve1 = reserves[1] / (10 ** dec1)

            if reserve0 == 0 or reserve1 == 0:
                return None

            price = reserve1 / reserve0 if base_in_0 else reserve0 / reserve1
        else:
            sqrt_price_x96 = pool_info['slot0'][0]

            if sqrt_price_x96 == 0:
                return None

            dec0, dec1 = pool_info['decimals']

            if not base_in_0 and sqrt_price_x96 != 0:
                price = 1 / ((sqrt_price_x96 * sqrt_price_x96 / (2 ** 192)) * (10 ** (dec1 - dec0)))
            else:
                price = (sqrt_price_x96 * sqrt_price_x96 / (2 ** 192)) * (10 ** (dec0 - dec1))

        return price

    except Exception as e:
        print(f"Error calculating price: {str(e)}")
        return None

async def get_token_prices_parallel(unique_tokens, block_num):

    token_prices = {}

    # Stablecoins will be counted as $1
    for token in unique_tokens:
        if token in STABLECOINS:
            token_prices[token] = 1.0

    remaining_tokens = [t for t in unique_tokens if t not in STABLECOINS]
    if not remaining_tokens:
        return token_prices

    weth_price = await get_weth_price(block_num)
    if not weth_price:
        print(f"Failed to get WETH price at block {block_num}. Cannot price other tokens.")
        return token_prices

    token_prices[WETH.lower()] = weth_price

    async def get_single_token_price(token):
        try:
            token_weth_pool = await check_all_pools(
                Web3.to_checksum_address(token),
                WETH,
                block_num
            )

            if not token_weth_pool:
                return None

            token_price_in_eth = await get_price_from_pool_info(
                token_weth_pool,
                Web3.to_checksum_address(token),
                WETH
            )

            if token_price_in_eth is None:
                return None

            final_price = token_price_in_eth * weth_price

            if final_price > 1e6:
                return None

            return final_price
        except Exception as e:
            print(f"Error getting price for {token}: {e}")
            return None

    price_tasks = [get_single_token_price(token) for token in remaining_tokens]
    prices = await asyncio.gather(*price_tasks)

    for token, price in zip(remaining_tokens, prices):
        if price is not None:
            token_prices[token] = price

    return token_prices


async def process_single_transfer(transfer, token_prices):

    try:
        if transfer['type'] == 'ether':
            adjusted_amount = w3.from_wei(transfer['raw_amount'], 'ether')
            usd_price = token_prices.get(WETH.lower())
        else:
            token_address = transfer['token_address']
            decimals = await get_token_decimals(Web3.to_checksum_address(token_address))
            adjusted_amount = transfer['raw_amount'] / (10 ** decimals)
            usd_price = token_prices.get(token_address)

        usd_value = float(adjusted_amount) * usd_price if usd_price else 0
        is_incoming = transfer['is_incoming']

        print(f"Transaction: {transfer['transaction_hash']}")
        print(f"Amount: {adjusted_amount:.6f}")
        print(f"USD Price: ${usd_price if usd_price else 'N/A'}")
        print(f"USD Value: ${usd_value if usd_value else 'N/A'}\n")

        return usd_value, is_incoming
    except Exception as e:
        print(f"Error processing transfer {transfer['transaction_hash']}: {str(e)}")
        return 0, False


async def process_block_transfers(block_num, stats):
    max_attempts = 2
    current_attempt = 0
    retry_delay = 5

    while current_attempt < max_attempts:
        try:
            block_task = asyncio.create_task(asyncio.to_thread(
                w3.eth.get_block, block_num, full_transactions=True
            ))
            logs_task = asyncio.create_task(asyncio.to_thread(
                w3.eth.get_logs,
                {
                    "fromBlock": block_num,
                    "toBlock": block_num,
                    "topics": [TRANSFER_EVENT_SIGNATURE]
                }
            ))

            block, logs = await asyncio.gather(block_task, logs_task)

            relevant_transfers = []
            unique_tokens = {WETH.lower()}

            for tx in block.transactions:
                from_addr = tx['from'].lower()
                to_addr = tx['to'].lower() if tx.get('to') else ''

                if (to_addr in COINBASE_WALLETS or from_addr in COINBASE_WALLETS) and tx['value'] > 0:
                    relevant_transfers.append({
                        'type': 'ether',
                        'transaction_hash': tx['hash'].hex(),
                        'from_addr': from_addr,
                        'to_addr': to_addr,
                        'raw_amount': tx['value'],
                        'is_incoming': to_addr in COINBASE_WALLETS
                    })

            for log in logs:
                if len(log.topics) != 3:
                    continue

                from_addr = "0x" + log.topics[1].hex()[-40:].lower()
                to_addr = "0x" + log.topics[2].hex()[-40:].lower()
                amount = int.from_bytes(log.data, "big")

                if (to_addr in COINBASE_WALLETS or from_addr in COINBASE_WALLETS) and amount > 0:
                    relevant_transfers.append({
                        'type': 'erc20',
                        'transaction_hash': log.transactionHash.hex(),
                        'token_address': log.address.lower(),
                        'from_addr': from_addr,
                        'to_addr': to_addr,
                        'raw_amount': amount,
                        'is_incoming': to_addr in COINBASE_WALLETS
                    })
                    unique_tokens.add(log.address.lower())

            if not relevant_transfers:
                return

            token_prices = await get_token_prices_parallel(unique_tokens, block_num)

            transfer_tasks = [process_single_transfer(transfer, token_prices)
                              for transfer in relevant_transfers]
            transfer_results = await asyncio.gather(*transfer_tasks)

            for usd_value, is_incoming in transfer_results:
                if usd_value > 0:
                    stats.add_transaction(usd_value, is_incoming)
            break

        except Exception as e:
            current_attempt += 1

            if current_attempt < max_attempts:
                await asyncio.sleep(retry_delay)
            else:
                print(f"Error processing block {block_num} after retry: {str(e)}")
                import traceback
                traceback.print_exc()

async def process_single_block(block_num):
    print(f"Processing block {block_num}...")
    block_stats = TransactionStats()
    await process_block_transfers(block_num, block_stats)
    return block_stats


async def get_historical_transfers(start_block, end_block):

    block_tasks = []
    for block_num in range(start_block, end_block + 1):
        task = process_single_block(block_num)
        block_tasks.append(task)

    block_results = await asyncio.gather(*block_tasks)

    combined_stats = TransactionStats()
    for block_stats in block_results:
        combined_stats.merge(block_stats)

    combined_stats.print_summary(is_final=True)

async def track_real_time():

    current_block = w3.eth.block_number
    total_stats = TransactionStats()

    while True:
        try:
            latest_block = w3.eth.block_number

            while current_block <= latest_block:
                print(f"\nProcessing block {current_block}...")

                block_stats = TransactionStats()
                await process_block_transfers(current_block, block_stats)

                if block_stats.combined_total > 0:
                    block_stats.print_summary(current_block)

                total_stats.merge(block_stats)

                if block_stats.combined_total > 0:
                    total_stats.print_summary(is_running_total=True)

                current_block += 1

            await asyncio.sleep(1)

        except Exception as e:
            print(f"Error in real-time tracking at block {current_block}: {str(e)}")
            await asyncio.sleep(1)

if __name__ == "__main__":
    mode = input("Enter mode\n1 Historical\n2 Real-time\n")
    if mode.lower() == "1":
        start_block = int(input("Enter start block: "))
        end_block = int(input("Enter end block: "))
        asyncio.run(get_historical_transfers(start_block, end_block))
    elif mode.lower() == "2":
        asyncio.run(track_real_time())
    else:
        print("Invalid mode")
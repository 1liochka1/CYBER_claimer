import asyncio
import csv
from loguru import logger
from config import amount_wallets_in_batch, rpc
from utils import CyberConnect



async def write_to_csv(key, address, result):
    with open('result.csv', 'a', newline='') as file:
        writer = csv.writer(file)

        if file.tell() == 0:
            writer.writerow(['key', 'address', 'result'])

        writer.writerow([key, address, result])


async def main():
    with open("accs.txt", "r") as f:
        accs = [row.strip() for row in f]

    batches = [accs[i:i + amount_wallets_in_batch] for i in range(0, len(accs), amount_wallets_in_batch)]

    for batch in batches:
        tasks = []
        for acc in batch:
            key, address, proxy = acc.split(';')
            cyber = CyberConnect(key, rpc, address, f'http://{proxy}')
            tasks.append(cyber.transfer_cyber())

        res = await asyncio.gather(*tasks)
        for res_ in res:
            key, address_, info = res_
            await write_to_csv(key, address_, info)

        tasks = []

    logger.success(f'muнетинг закончен...')
    print(f'\n{" " * 32}автор - https://t.me/iliocka{" " * 32}\n')
    print(f'\n{" " * 32}donate - EVM 0xFD6594D11b13C6b1756E328cc13aC26742dBa868{" " * 32}\n')
    print(f'\n{" " * 32}donate - trc20 TMmL915TX2CAPkh9SgF31U4Trr32NStRBp{" " * 32}\n')


if __name__ == '__main__':
    asyncio.run(main())

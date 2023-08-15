import asyncio
import json
import datetime

from eth_account.messages import encode_defunct
from eth_utils import to_int, to_hex
from web3 import Web3
from loguru import logger
import aiohttp
from web3.eth import AsyncEth

from abi.abis import claim_abi, token_abi


class CyberConnect:
    def __init__(self, key, rpc, address_to, proxy=None):
        self.key = key
        self.w3 = Web3(Web3.AsyncHTTPProvider(rpc, request_kwargs={"proxy": proxy}),
                       modules={'eth': (AsyncEth,)}, middlewares=[])
        self.account = self.w3.eth.account.from_key(key)
        self.address = self.account.address
        self.proxy = proxy
        self.claim_contract = Web3.to_checksum_address('0xB2BbFC07948fedeB5935316203C33ce70beF57d0')
        self.ep = Web3.to_checksum_address('0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789')
        self.cyber_contract = Web3.to_checksum_address('0x14778860E937f509e651192a90589dE711Fb88a9')
        self.address_to = address_to

    async def get_nonce(self):
        headers = {
            'authorization': '',
        }

        json_data = {
            'query': '\n    mutation nonce($address: EVMAddress!) {\n  nonce(input: {address: $address}) {\n    status\n    message\n    data\n  }\n}\n    ',
            'variables': {
                'address': self.address,
            },
            'operationName': 'nonce',
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post('https://api.cyberconnect.dev/wallet/', headers=headers, json=json_data,
                                        proxy=self.proxy) as response:  # todo поменять на норм версию!!!

                    if response.status == 200:
                        logger.success(f'{self.address} - успешно получил nonce...')
                        nonce = json.loads(await response.text())['data']['nonce']['data']
                        return nonce, headers
                    logger.error(f'{self.address} - Ошибка при получении nonce...')
                    await asyncio.sleep(1)
                    return await self.get_nonce()

        except Exception as e:
            logger.error(f'{self.address} - {e}, пробую еще раз...')
            await asyncio.sleep(2)
            return self.get_nonce()

    async def auth(self):
        nonce, headers = await self.get_nonce()
        now = datetime.datetime.utcnow()
        timenow = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        futuredate = now + datetime.timedelta(days=14)
        timefuture = futuredate.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
        msg = f'wallet.cyber.co wants you to sign in with your Ethereum account:\n{self.address}\n\n\nURI: https://wallet.cyber.co\nVersion: 1\nChain ID: 10\nNonce: {nonce}\nIssued At: {timenow}\nExpiration Time: {timefuture}\nNot Before: {timenow}'
        msg_ = self.w3.eth.account.sign_message(encode_defunct(text=msg), self.key)
        signature = msg_.signature.hex()
        json_data = {
            'query': '\n    mutation login($request: LoginInput!) {\n  login(input: $request) {\n    status\n    message\n    data {\n      accessToken\n      address\n      cyberAccount\n    }\n  }\n}\n    ',
            'variables': {
                'request': {
                    'address': self.address,
                    'signature': signature,
                    'signedMessage': msg,
                },
            },
            'operationName': 'login',
        }
        try:
            session = aiohttp.ClientSession()
            async with session.post('https://api.cyberconnect.dev/wallet/', headers=headers, json=json_data,
                                    proxy=self.proxy) as response:
                if response.status == 200:
                    logger.success(f'{self.address} - успешно авторизовался...')
                    token = json.loads(await response.text())['data']['login']['data']['accessToken']
                    headers['authorization'] = token
                    session.headers.update(headers)
                    return session
                logger.error(f'{self.address} - Ошибка при попытке авторизации, пробую еще раз...')
                await asyncio.sleep(1)
                return await self.auth()

        except Exception as e:
            logger.error(f'{self.address} - {e}, ошибка при авторизации')
            await asyncio.sleep(2)
            return
    async def get_merkle_proof(self):
        session = await self.auth()
        if not session:
            logger.error('Не могу получить пруф для клейма тк не смог авторизоваться...')
            return

        json_data = {
            'query': '\n    query merkleProof {\n  me {\n    cyberRewardMerkleProof {\n      index\n      address\n      amountHex\n      proofs\n    }\n  }\n}\n    ',
            'operationName': 'merkleProof',
        }

        try:
            # async with session as session:
            async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                    proxy=self.proxy) as response:
                if response.status == 200:
                    data = json.loads(await response.text())
                    if data['data']['me'] == None:
                        logger.error(f'{self.address} - Нечего клеймить')
                        await session.close()
                        return
                    logger.success(f'{self.address} - успешно получил меркл пруф...')
                    merkle_proof = data['data']['me']['cyberRewardMerkleProof']['proofs']
                    cyber_address = data['data']['me']['cyberRewardMerkleProof']['address']
                    index = int(data['data']['me']['cyberRewardMerkleProof']['index'])
                    amount = int(data['data']['me']['cyberRewardMerkleProof']['amountHex'], 16)
                    return session, merkle_proof, cyber_address, index, amount
                logger.error(f'{self.address} - Ошибка при попытке получения меркл пруфа, пробую еще раз...')
                await asyncio.sleep(1)
                return await self.get_merkle_proof()

        except Exception as e:
            logger.error(f'{self.address} - {e}, ошибка при получении меркл пруфа')
            await asyncio.sleep(2)
            return await self.get_merkle_proof()

    async def prepare_tx(self):
        data = await self.get_merkle_proof()
        if not data:
            return
        session, merkle_proof, cyber_address, index, amount = data
        claim = self.w3.eth.contract(address=Web3.to_checksum_address('0x0B1bbaC2A57F530C0454232082Ab061AF9cA724F'),
                                     abi=claim_abi)
        call_data = claim.encodeABI(fn_name='claim', args=[index, cyber_address, amount, merkle_proof])
        json_data = {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'cc_estimateUserOperation',
            'params': [
                {
                    'sender': cyber_address,
                    'callData': call_data,
                    'to': self.claim_contract,
                    'value': '0',
                    'nonce': None,
                    'maxFeePerGas': None,
                    'maxPriorityFeePerGas': None,
                    'ep': self.ep,
                },
                {
                    'chainId': 10,
                    'owner': self.address,
                },
            ],
        }
        try:
            # async with session as session:
            async with session.post('https://api.cyberconnect.dev/paymaster/', json=json_data,
                                    proxy=self.proxy) as response:
                if response.status == 200:
                    data = json.loads(await response.text())
                    print(data)
                    if 'error' in data:
                        logger.error(
                            f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                        await asyncio.sleep(1)
                        return await self.prepare_tx()

                    logger.success(f'{self.address} - успешно получил данные для транзакции...')

                    credits = data['result']['credits']
                    gas = data['result']['fast']
                    maxFeePerGas = gas['maxFeePerGas']
                    maxPriorityFeePerGas = gas['maxPriorityFeePerGas']
                    return session, credits, maxPriorityFeePerGas, maxFeePerGas, call_data, cyber_address, amount

                logger.error(f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                await asyncio.sleep(1)
                return await self.prepare_tx()

        except Exception as e:
            logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
            await asyncio.sleep(2)
            return await self.prepare_tx()

    async def claim(self):

        async def get_userOperationHash():
            data = await self.prepare_tx()
            if not data:
                return
            session, credits, maxPriorityFeePerGas, maxFeePerGas, call_data, cyber_address, amount = data
            json_data = {
                'query': '\n    mutation sponsorUserOperation($input: SponsorUserOperationInput!) {\n  sponsorUserOperation(input: $input) {\n    userOperation {\n      sender\n      nonce\n      initCode\n      callData\n      callGasLimit\n      verificationGasLimit\n      preVerificationGas\n      maxFeePerGas\n      maxPriorityFeePerGas\n      paymasterAndData\n      signature\n    }\n    userOperationHash\n    errorCode\n  }\n}\n    ',
                'variables': {
                    'input': {
                        'params': {
                            'sponsorUserOpParams': {
                                'sender': cyber_address,
                                'callData': call_data,
                                'to': self.claim_contract,
                                'value': '0',
                                'nonce': None,
                                'maxFeePerGas': maxFeePerGas,
                                'maxPriorityFeePerGas': maxPriorityFeePerGas,
                                'entryPoint': self.ep,
                            },
                            'sponsorUserOpContext': {
                                'chainId': 10,
                                'owner': self.address,
                            },
                        },
                        'type': 'CONTRACT_CALL',
                        'readableTransaction': '{"token":{"chainId":10,"decimals":18,"symbol":"Cyber","name":"CyberConnect","balance":"","cmcTokenId":"24781"},"recipient":' + f'"{cyber_address}",' + f'"amount":"{int(amount / 10 ** 18)}"' + ',"noTopUp":false,"estimatedFee":{' + f'"value":{int(credits) / 10 ** 6},' + '"tier":"gasPriceFast"}}',
                    },
                },
                'operationName': 'sponsorUserOperation',
            }
            try:
                # async with session as session:
                async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data_ = json.loads(await response.text())
                        data = data_['data']['sponsorUserOperation']['userOperation']
                        print(data_)
                        if data_ is None:
                            logger.error(
                                f'{self.address} - Ошибка при попытке получения данных для транзакции, возможно не хватает средств для клейма')
                            return
                        if data is None:
                            return await get_userOperationHash()
                        print(data)
                        logger.success(f'{self.address} - успешно получил данные для транзакции...')
                        tx_data = data
                        claim_hash = data_['data']['sponsorUserOperation']['userOperationHash']
                        return session, tx_data, claim_hash, amount
                    logger.error(
                        f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                    await asyncio.sleep(1)
                    return await get_userOperationHash()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
                await asyncio.sleep(2)
                return await get_userOperationHash()

        async def sendUserOperation():
            data = await get_userOperationHash()

            if not data:
                return
            await asyncio.sleep(10)
            session, tx_data, claim_hash, amount = data
            signature = self.w3.eth.account.sign_message(encode_defunct(hexstr=claim_hash), self.key).signature.hex()
            tx_data['signature'] = signature
            json_data = {
                'jsonrpc': '2.0',
                'id': 4,
                'method': 'eth_sendUserOperation',
                'params': [
                    tx_data,
                    self.ep,
                    {
                        'chainId': 10,
                        'owner': self.address,
                    },
                ],
            }
            try:
                # async with session as session:
                async with session.post('https://api.cyberconnect.dev/paymaster/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data_ = json.loads(await response.text())
                        print(data_)
                        logger.success(f'{self.address} - Успешно проверил транзакцию клейма')
                        result = data_['result']
                        return result, session, amount
                    logger.error(f'{self.address} - Ошибка при попытке проверки транзакцию клейма...')
                    await asyncio.sleep(1)
                    return await sendUserOperation()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при попытке проверки транзакции клейма')
                await asyncio.sleep(2)
                return await sendUserOperation()

        async def get_opti_claim_hash():
            data = await sendUserOperation()
            if not data:
                return
            await asyncio.sleep(15)
            res, session, amount = data
            json_data = {
                'query': '\n    query txHashByOperationHash($userOpHash: String!) {\n  userOperationByHash(userOpHash: $userOpHash) {\n    txHash\n    chainId\n  }\n}\n    ',
                'variables': {
                    'userOpHash': res,
                },
                'operationName': 'txHashByOperationHash',
            }
            while True:
                try:
                    # async with session as session:
                    async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                            proxy=self.proxy) as response:
                        if response.status == 200:
                            data_ = json.loads(await response.text())
                            hash_ = data_['data']['userOperationByHash']['txHash']
                            if hash_ is None:
                                logger.error(
                                    f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                                await asyncio.sleep(1)

                            logger.success(
                                f'{self.address} - Успешно заклеймил {amount / 10 ** 18} CYBER - https://optimistic.etherscan.io/tx/{hash_}')
                            return session, amount
                        logger.error(
                            f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                        await asyncio.sleep(1)
                        return await get_opti_claim_hash()

                except Exception as e:
                    logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
                    await asyncio.sleep(2)
                    return await get_opti_claim_hash()

        return await get_opti_claim_hash()

    async def transfer_cyber(self):
        session, amount = await self.claim()
        if not session:
            return

        logger.debug("Начинаю отправку CYBER")
        async def get_address():
            json_data = {
                'query': '\n    query me {\n  me {\n    accessToken\n    address\n    cyberAccount\n    earlyAccess\n    cyberRewardClaimStatus {\n      restrictedByIP\n      claimed\n      amount\n    }\n  }\n}\n    ',
                'operationName': 'me',
            }
            try:
                # async with session as session:
                async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data = json.loads(await response.text())
                        cyber_acc = data['data']['me']['cyberAccount']
                        return cyber_acc
                    logger.error(
                        f'{self.address} - Ошибка при попытке получении адреса кибераккаунта, пробую еще раз...')
                    await asyncio.sleep(1)
                    return await get_address()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при получении адреса кибераккаунта')
                await asyncio.sleep(2)
                return await get_address()

        async def prepare_tx():
            cyber = self.w3.eth.contract(address=self.cyber_contract, abi=token_abi)
            call_data = cyber.encodeABI(fn_name='transfer', args=[self.address_to, amount])
            cyber_address = await get_address()
            json_data = {
                'jsonrpc': '2.0',
                'id': 2,
                'method': 'cc_estimateUserOperation',
                'params': [
                    {
                        'sender': cyber_address,
                        'callData': call_data,
                        'to': self.cyber_contract,
                        'value': '0',
                        'nonce': None,
                        'maxFeePerGas': None,
                        'maxPriorityFeePerGas': None,
                        'ep': self.ep,
                    },
                    {
                        'chainId': 10,
                        'owner': self.address,
                    },
                ],
            }
            try:
                async with session.post('https://api.cyberconnect.dev/paymaster/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data = json.loads(await response.text())
                        print(data)
                        if 'error' in data:
                            logger.error(
                                f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                            await asyncio.sleep(1)
                            return await prepare_tx()

                        logger.success(f'{self.address} - успешно получил данные для транзакции...')

                        credits = data['result']['credits']
                        gas = data['result']['fast']
                        maxFeePerGas = gas['maxFeePerGas']
                        maxPriorityFeePerGas = gas['maxPriorityFeePerGas']
                        return session, credits, maxPriorityFeePerGas, maxFeePerGas, call_data, cyber_address, amount

                    logger.error(
                        f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                    await asyncio.sleep(1)
                    return await prepare_tx()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
                await asyncio.sleep(2)
                return await prepare_tx()

        async def get_userOperationHash():
            data = await prepare_tx()
            if not data:
                return
            session, credits, maxPriorityFeePerGas, maxFeePerGas, call_data, cyber_address, amount = data
            json_data = {
                'query': '\n    mutation sponsorUserOperation($input: SponsorUserOperationInput!) {\n  sponsorUserOperation(input: $input) {\n    userOperation {\n      sender\n      nonce\n      initCode\n      callData\n      callGasLimit\n      verificationGasLimit\n      preVerificationGas\n      maxFeePerGas\n      maxPriorityFeePerGas\n      paymasterAndData\n      signature\n    }\n    userOperationHash\n    errorCode\n  }\n}\n    ',
                'variables': {
                    'input': {
                        'params': {
                            'sponsorUserOpParams': {
                                'sender': cyber_address,
                                'callData': call_data,
                                'to': self.cyber_contract,
                                'value': '0',
                                'nonce': None,
                                'maxFeePerGas': maxFeePerGas,
                                'maxPriorityFeePerGas': maxPriorityFeePerGas,
                                'entryPoint': self.ep,
                            },
                            'sponsorUserOpContext': {
                                'chainId': 10,
                                'owner': self.address,
                            },
                        },
                        'type': 'CONTRACT_CALL',
                        'readableTransaction': '{"recipient":' + f'"{self.address_to}"' + f',"amount":"{int(amount / 10 ** 18)}"' + ',"tokenIndex":0,"estimatedFee":{"value":' + f'"{int(credits) / 10 ** 6}"' + ',"tier":"gasPriceFast"},' + '"token":{"name":"CyberConnect",' + f'"contract":"{cyber_address}"' + f',"chainId":10,"decimals":18,"balance":"{amount}",' + '"symbol":"CYBER","cmcTokenId":"24781","usdPrice":"","cmcUsdPrice":"","priceChange":""}}'
                    },
                },
                'operationName': 'sponsorUserOperation',
            }
            try:
                # async with session as session:
                async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data_ = json.loads(await response.text())
                        data = data_['data']['sponsorUserOperation']['userOperation']
                        print(data_)
                        if data_ is None:
                            logger.error(
                                f'{self.address} - Ошибка при попытке получения данных для транзакции, возможно не хватает средств для клейма')
                            return
                        print(data)
                        logger.success(f'{self.address} - успешно получил данные для транзакции...')
                        tx_data = data
                        claim_hash = data_['data']['sponsorUserOperation']['userOperationHash']
                        return session, tx_data, claim_hash, amount
                    logger.error(
                        f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                    await asyncio.sleep(1)
                    return await get_userOperationHash()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
                await asyncio.sleep(2)
                return await get_userOperationHash()

        async def sendUserOperation():
            data = await get_userOperationHash()

            if not data:
                return
            await asyncio.sleep(10)
            session, tx_data, claim_hash, amount = data
            signature = self.w3.eth.account.sign_message(encode_defunct(hexstr=claim_hash), self.key).signature.hex()
            tx_data['signature'] = signature
            json_data = {
                'jsonrpc': '2.0',
                'id': 4,
                'method': 'eth_sendUserOperation',
                'params': [
                    tx_data,
                    self.ep,
                    {
                        'chainId': 10,
                        'owner': self.address,
                    },
                ],
            }
            try:
                # async with session as session:
                async with session.post('https://api.cyberconnect.dev/paymaster/', json=json_data,
                                        proxy=self.proxy) as response:
                    if response.status == 200:
                        data_ = json.loads(await response.text())
                        print(data_)
                        logger.success(f'{self.address} - Успешно проверил транзакцию клейма')
                        result = data_['result']
                        return result, session, amount
                    logger.error(f'{self.address} - Ошибка при попытке проверки транзакцию клейма...')
                    await asyncio.sleep(1)
                    return await sendUserOperation()

            except Exception as e:
                logger.error(f'{self.address} - {e}, ошибка при попытке проверки транзакции клейма')
                await asyncio.sleep(2)
                return await sendUserOperation()

        async def get_opti_claim_hash():
            data = await sendUserOperation()
            if not data:
                return
            await asyncio.sleep(15)
            res, session, amount = data
            json_data = {
                'query': '\n    query txHashByOperationHash($userOpHash: String!) {\n  userOperationByHash(userOpHash: $userOpHash) {\n    txHash\n    chainId\n  }\n}\n    ',
                'variables': {
                    'userOpHash': res,
                },
                'operationName': 'txHashByOperationHash',
            }
            while True:
                try:
                    async with session.post('https://api.cyberconnect.dev/wallet/', json=json_data,
                                            proxy=self.proxy) as response:
                        if response.status == 200:
                            data_ = json.loads(await response.text())
                            hash_ = data_['data']['userOperationByHash']['txHash']
                            print(data_)
                            if hash_ is None:
                                logger.error(
                                    f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                                await asyncio.sleep(1)

                            logger.success(
                                f'{self.address} - Успешно отправил {amount / 10 ** 18} CYBER на {self.address} - https://optimistic.etherscan.io/tx/{hash_}')
                            return self.key, self.address_to, amount/10**18
                        logger.error(
                            f'{self.address} - Ошибка при попытке получения данных для транзакции, пробую еще раз...')
                        await asyncio.sleep(1)
                        return await get_opti_claim_hash()

                except Exception as e:
                    logger.error(f'{self.address} - {e}, ошибка при получение данных для транзакции')
                    await asyncio.sleep(2)
                    return await get_opti_claim_hash()

        return await get_opti_claim_hash()



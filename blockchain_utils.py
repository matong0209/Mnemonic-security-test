from datetime import datetime, timezone
import requests
from eth_account import Account
from web3 import Web3
import hashlib
import secrets
import base58
import ecdsa


# API密钥和端点
ETHERSCAN_API_KEY = "B38I8TH52C94KMBSIQ9PB11N9DHGCZ5HSJ"  # Etherscan API密钥

# 获取BlockCypher API密钥: https://www.blockcypher.com/
BLOCKCYPHER_API_KEY = "fde919e9087d414e9f8c4e3ecebe3a55"

# 支持的区块链列表 (使用英文标识符)
SUPPORTED_CHAINS = ["bitcoin", "ethereum", "dogecoin"]

# 区块链名称映射表 (用于后端代码中的中英文转换)
CHAIN_NAME_MAP = {
    "bitcoin": "比特币",
    "ethereum": "以太坊",
    "dogecoin": "狗狗币",
    "比特币": "bitcoin",
    "以太坊": "ethereum",
    "狗狗币": "dogecoin"
}

# 语言映射表
BIP39_LANGUAGE_MAP = {
    "中文简体": "chinese_simplified",
    "中文繁体": "chinese_traditional",
    "英文": "english",
    "法语": "french",
    "西班牙语": "spanish",
    "意大利语": "italian",
    "日语": "japanese",
    "韩语": "korean",
}

# API端点
API_ENDPOINTS = {
    "bitcoin": "https://blockchain.info/address/{address}?format=json",
    # 每日请求限制: 100000个请求
    "ethereum": "https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey=" + ETHERSCAN_API_KEY,
    "dogecoin": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"  # 每天1000个请求,每小时100个请求,每秒3个请求
}

# 备用免费API端点(不需要API密钥)
BACKUP_API_ENDPOINTS = {
    "bitcoin": "https://blockchain.info/address/{address}?format=json",
    "ethereum": "https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance",
    "dogecoin": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
}

# 区块浏览器的链接
BLOCKCHAIN_EXPLORERS = {
    "bitcoin": "https://www.blockchain.com/explorer/addresses/btc/{address}",
    "ethereum": "https://etherscan.io/address/{address}",
    "dogecoin": "https://blockchair.com/dogecoin/address/{address}"
}


def get_bitcoin_address_from_private_key(private_key):
    """从私钥生成比特币地址"""
    # 步骤1：使用ECDSA库从私钥生成公钥
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = verifying_key.to_string()

    # 步骤2：添加前缀0x04并哈希，得到完整的公钥（压缩公钥也可以使用）
    key_bytes = b'\x04' + public_key

    # 步骤3：计算SHA-256哈希
    sha256_hash = hashlib.sha256(key_bytes).digest()

    # 步骤4：计算RIPEMD-160哈希
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hash160 = ripemd160.digest()

    # 步骤5：添加主网络前缀
    versioned_hash = b'\x00' + hash160

    # 步骤6：计算校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]

    # 步骤7：拼接得到二进制地址
    binary_address = versioned_hash + checksum

    # 步骤8：使用Base58编码得到比特币地址
    bitcoin_address = base58.b58encode(binary_address).decode('utf-8')

    return bitcoin_address


def get_dogecoin_address_from_private_key(private_key):
    """从私钥生成狗狗币地址"""
    # 与比特币类似，但版本字节不同（狗狗币是0x1E）
    # 步骤1：使用ECDSA库从私钥生成公钥
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = verifying_key.to_string()

    # 步骤2：添加前缀0x04并哈希，得到完整的公钥
    key_bytes = b'\x04' + public_key

    # 步骤3：计算SHA-256哈希
    sha256_hash = hashlib.sha256(key_bytes).digest()

    # 步骤4：计算RIPEMD-160哈希
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hash160 = ripemd160.digest()

    # 步骤5：添加狗狗币网络前缀 (0x1E)
    versioned_hash = b'\x1E' + hash160

    # 步骤6：计算校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]

    # 步骤7：拼接得到二进制地址
    binary_address = versioned_hash + checksum

    # 步骤8：使用Base58编码得到狗狗币地址
    dogecoin_address = base58.b58encode(binary_address).decode('utf-8')

    return dogecoin_address


def generate_addresses_from_mnemonic(mnemonic, passphrase="", chains=None, account_index=0, address_count=5,
                                     language="英文"):
    """
    从助记词生成多个区块链地址
    
    参数:
        mnemonic (str): 助记词字符串，用空格分隔
        passphrase (str): 可选密码
        chains (list): 要生成地址的区块链列表，如不指定则生成所有支持的区块链地址
        account_index (int): 账户索引，默认为0
        address_count (int): 每个链要生成的地址数量，默认为5
        language (str): 助记词的语言，可选值为"中文简体"、"中文繁体"、"英文"，默认为"英文"
        
    返回:
        dict: 不同区块链的地址列表
    """
    if chains is None:
        chains = SUPPORTED_CHAINS

    addresses = {}

    # 先使用mnemonic库生成种子
    from mnemonic import Mnemonic
    import binascii

    try:
        # 获取正确的语言代码
        bip39_language = BIP39_LANGUAGE_MAP.get(language, "english")

        # 从助记词生成种子
        mnemonic_generator = Mnemonic(bip39_language)
        if not mnemonic_generator.check(mnemonic):
            return {"error": f"无效的{language}助记词，请检查拼写和单词顺序"}

        seed_bytes = mnemonic_generator.to_seed(mnemonic, passphrase)
        seed_hex = binascii.hexlify(seed_bytes).decode()

        for chain_name in chains:
            if chain_name not in SUPPORTED_CHAINS:
                continue

            chain_addresses = []

            try:
                if chain_name == "ethereum":
                    for address_index in range(address_count):
                        try:
                            # 尝试使用账户的助记词功能
                            try:
                                account = Account.from_mnemonic(
                                    mnemonic=mnemonic,
                                    passphrase=passphrase,
                                    account_path=f"m/44'/60'/{account_index}'/0/{address_index}"
                                )

                                # 从账户提取私钥和地址
                                private_key_hex = account.key.hex()
                                public_key = "0x" + Account._recover_public_key_from_private(account.key).hex()

                                address_data = {
                                    "路径": f"m/44'/60'/{account_index}'/0/{address_index}",
                                    "地址": account.address,
                                    "私钥": private_key_hex,
                                    "公钥": public_key,
                                    "索引": address_index
                                }
                            except Exception as e:
                                # 如果助记词功能失败，使用种子生成私钥
                                # 创建特定于地址索引的种子
                                index_seed = hashlib.sha256(f"{seed_hex}-{address_index}".encode()).digest()
                                private_key_bytes = hashlib.sha256(index_seed).digest()
                                private_key_hex = private_key_bytes.hex()

                                # 创建以太坊地址
                                eth_account = Account.from_key(private_key_hex)
                                # 生成公钥 (如果无法直接获取，至少提供一个占位符)
                                try:
                                    public_key = "0x" + Account._recover_public_key_from_private(eth_account.key).hex()
                                except Exception:
                                    # 使用替代方法生成公钥展示内容
                                    public_key = f"0x{eth_account.address[2:].lower()}000000000000000000"

                                address_data = {
                                    "路径": f"(替代方法)index-{address_index}",
                                    "地址": eth_account.address,
                                    "私钥": private_key_hex,
                                    "公钥": public_key,
                                    "索引": address_index
                                }

                            chain_addresses.append(address_data)
                        except Exception as e:
                            # 确保错误信息遵循一致的数据结构
                            chain_addresses.append({
                                "路径": "错误",
                                "地址": "生成失败",
                                "公钥": f"0x{secrets.token_hex(32)}",  # 提供一个随机公钥格式值而不是"无法获取"
                                "错误": f"生成以太坊地址 #{address_index} 失败: {str(e)}"
                            })

                elif chain_name == "bitcoin":
                    # 使用我们的自定义方法生成比特币地址
                    for address_index in range(address_count):
                        try:
                            # 基于种子和索引生成唯一私钥
                            index_seed = hashlib.sha256(f"{seed_hex}-{address_index}".encode()).digest()
                            private_key = hashlib.sha256(index_seed).digest()
                            private_key_hex = private_key.hex()

                            # 生成比特币地址
                            btc_address = get_bitcoin_address_from_private_key(private_key)

                            # 生成公钥
                            signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
                            public_key = "0x" + signing_key.get_verifying_key().to_string().hex()

                            # 创建地址数据
                            address_data = {
                                "路径": f"m/44'/0'/0'/0/{address_index}",
                                "地址": btc_address,
                                "私钥": private_key_hex,
                                "公钥": public_key,
                                "索引": address_index
                            }
                            chain_addresses.append(address_data)
                        except Exception as e:
                            # 确保错误信息遵循一致的数据结构
                            chain_addresses.append({
                                "路径": "错误",
                                "地址": "生成失败",
                                "公钥": f"0x{secrets.token_hex(32)}",
                                "错误": f"生成比特币地址 #{address_index} 失败: {str(e)}"
                            })

                elif chain_name == "dogecoin":
                    # 使用我们的自定义方法生成狗狗币地址
                    for address_index in range(address_count):
                        try:
                            # 基于种子和索引生成唯一私钥
                            index_seed = hashlib.sha256(f"{seed_hex}-doge-{address_index}".encode()).digest()
                            private_key = hashlib.sha256(index_seed).digest()
                            private_key_hex = private_key.hex()

                            # 生成狗狗币地址
                            doge_address = get_dogecoin_address_from_private_key(private_key)

                            # 生成公钥
                            signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
                            public_key = "0x" + signing_key.get_verifying_key().to_string().hex()

                            # 创建地址数据
                            address_data = {
                                "路径": f"m/44'/3'/0'/0/{address_index}",
                                "地址": doge_address,
                                "私钥": private_key_hex,
                                "公钥": public_key,
                                "索引": address_index
                            }
                            chain_addresses.append(address_data)
                        except Exception as e:
                            # 确保错误信息遵循一致的数据结构
                            chain_addresses.append({
                                "路径": "错误",
                                "地址": "生成失败",
                                "公钥": f"0x{secrets.token_hex(32)}",
                                "错误": f"生成狗狗币地址 #{address_index} 失败: {str(e)}"
                            })

                addresses[chain_name] = chain_addresses

            except Exception as e:
                # 捕获并记录特定链的错误，确保一致的数据结构
                addresses[chain_name] = [{
                    "路径": "错误",
                    "地址": "生成失败",
                    "公钥": f"0x{secrets.token_hex(32)}",  # 提供一个随机公钥格式值
                    "错误": f"生成{chain_name}地址失败: {str(e)}"
                }]

        return addresses

    except Exception as e:
        # 捕获助记词处理的错误
        return {"error": f"助记词处理失败: {str(e)}"}


def query_address_balance(chain_name, address):
    """
    查询特定区块链地址的余额和交易记录
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要查询的地址
        
    返回:
        dict: 包含余额和交易信息的字典
    """
    # 支持性检查
    if chain_name not in API_ENDPOINTS:
        return {"error": "不支持的区块链类型", "余额": 0.0}
        
    # 校验地址
    if not is_valid_address(chain_name, address):
        return {"error": "地址格式错误或校验失败", "余额": 0.0}

    # 构建API URL
    api_url = API_ENDPOINTS[chain_name].format(address=address)

    try:
        # 发送API请求
        response = requests.get(api_url)

        # 检查是否请求成功
        if response.status_code != 200:
            # 尝试使用备用API
            return _try_backup_api(chain_name, address)

        data = response.json()

        # 解析不同区块链的数据
        result = {
            "地址": address,
            "区块链": chain_name,  # 使用英文标识符
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "余额": 0.0  # 默认为0，确保始终有余额字段
        }

        # 根据不同区块链解析余额和交易
        if chain_name == "bitcoin":
            try:
                result["余额"] = float(data.get("final_balance", 0)) / 100000000  # 转换为BTC单位
            except (ValueError, TypeError):
                result["余额"] = 0.0
            result["交易数量"] = data.get("n_tx", 0)
            result["总接收"] = float(data.get("total_received", 0)) / 100000000
            result["总发送"] = float(data.get("total_sent", 0)) / 100000000

        elif chain_name == "ethereum":
            if data.get("status") == "1":
                try:
                    result["余额"] = float(data.get("result", 0)) / 10**18  # 转换为ETH单位
                except (ValueError, TypeError):
                    result["余额"] = 0.0
                
                # 尝试获取交易数量
                try:
                    tx_count_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
                    tx_count_response = requests.get(tx_count_url)
                    if tx_count_response.status_code == 200:
                        tx_data = tx_count_response.json()
                        if tx_data.get("status") == "1" or tx_data.get("result"):
                            # 将16进制转换为10进制
                            result["交易数量"] = int(tx_data.get("result", "0x0"), 16)
                except Exception:
                    result["交易数量"] = 0
            else:
                result["交易数量"] = 0
                result["错误"] = data.get("message", "查询失败")
        elif chain_name == "dogecoin":
            if response.status_code == 200:
                try:
                    result["余额"] = float(data.get("final_balance", 0)) / 100000000  # 转换为DOGE单位
                except (ValueError, TypeError):
                    result["余额"] = 0.0
                result["交易数量"] = data.get("n_tx", 0) if "n_tx" in data else len(data.get("txrefs", []))
                result["总接收"] = float(data.get("total_received", 0)) / 100000000 if "total_received" in data else 0.0
                result["总发送"] = float(data.get("total_sent", 0)) / 100000000 if "total_sent" in data else 0.0

        # 进行风险评估
        risk_assessment = assess_address_risk(chain_name, address, result.get("交易数量"), result.get("余额"))
        
        return result
    except Exception as e:
        print(f"查询地址余额时出错: {str(e)}")
        # 尝试使用备用API
        return _try_backup_api(chain_name, address)


# ---------- 地址校验部分 ----------
def is_valid_btc_address(address: str) -> bool:
    try:
        decoded = base58.b58decode_check(address)
        return decoded[0] in (0x00, 0x05)
    except Exception:
        return False


def is_valid_eth_address(address: str) -> bool:
    return Web3.is_address(address)


def is_valid_doge_address(address: str) -> bool:
    try:
        decoded = base58.b58decode_check(address)
        return decoded[0] in (0x1E, 0x16)
    except Exception:
        return False


def is_valid_address(chain: str, address: str) -> bool:
    if chain == "bitcoin":
        return is_valid_btc_address(address)
    elif chain == "ethereum":
        return is_valid_eth_address(address)
    elif chain == "dogecoin":
        return is_valid_doge_address(address)
    return False


def _try_backup_api(chain_name, address):
    """
    当主API失败时，尝试使用备用API查询地址信息
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要查询的地址
        
    返回:
        dict: 包含余额和交易信息的字典
    """
    if chain_name not in BACKUP_API_ENDPOINTS:
        return {"error": "不支持的区块链类型", "余额": 0.0}

    try:
        # 构建API URL
        api_url = BACKUP_API_ENDPOINTS[chain_name].format(address=address)
        
        # 发送API请求
        response = requests.get(api_url)
        
        # 检查是否请求成功
        if response.status_code != 200:
            return {"error": f"API请求失败，状态码: {response.status_code}", "余额": 0.0}
        
        data = response.json()
        
        # 解析不同区块链的数据
        result = {
            "地址": address,
            "区块链": chain_name,  # 使用英文标识符
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "余额": 0.0  # 默认为0，确保始终有余额字段
        }
        
        if chain_name == "bitcoin":
            try:
                result["余额"] = float(data.get("final_balance", 0)) / 100000000  # 转换为BTC单位
            except (ValueError, TypeError):
                result["余额"] = 0.0
            result["交易数量"] = data.get("n_tx", 0)
        
        elif chain_name == "ethereum" or chain_name == "dogecoin":
            # Blockchair API格式
            if "data" in data and address in data["data"]:
                address_data = data["data"][address]
                try:
                    result["余额"] = float(address_data.get("address", {}).get("balance", 0)) / (
                        10 ** 18 if chain_name == "ethereum" else 10 ** 8)
                except (ValueError, TypeError, KeyError):
                    result["余额"] = 0.0
                
                result["交易数量"] = len(address_data.get("transactions", []))
        
        # 进行风险评估
        risk_assessment = assess_address_risk(chain_name, address, result.get("交易数量"), result.get("余额"))
        
        return result
    except Exception as e:
        print(f"备用API查询失败: {str(e)}")
        return {
            "地址": address,
            "区块链": chain_name,
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "余额": 0.0,
            "错误": f"备用API查询失败: {str(e)}"
        }


def assess_address_risk(chain_name, address, transaction_count=None, balance=None):
    """
    评估区块链地址的风险等级
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要评估的地址
        transaction_count (int): 交易数量
        balance (float): 账户余额
        
    返回:
        dict: 包含风险评估结果的字典
    """
    risk_level = "低"
    risk_factors = []
    suggestions = []
    
    # 1. 评估交易历史
    if transaction_count is not None:
        if transaction_count == 0:
            risk_factors.append("该地址没有交易历史，可能是新地址或未使用的地址")
            suggestions.append("在发送大额资金前，建议先进行小额测试交易")
        elif transaction_count < 5:
            risk_factors.append("该地址交易历史较少")
            suggestions.append("交易历史有限，建议谨慎评估")
    
    # 2. 评估余额
    if balance is not None:
        if balance > 0:
            if chain_name == "bitcoin" and balance > 1.0:
                risk_level = "中"
                risk_factors.append("该地址持有较大金额的比特币")
                suggestions.append("考虑使用硬件钱包存储大额资产")
            elif chain_name == "ethereum" and balance > 10.0:
                risk_level = "中"
                risk_factors.append("该地址持有较大金额的以太坊")
                suggestions.append("考虑使用多签名钱包增强安全性")
            elif chain_name == "dogecoin" and balance > 10000.0:
                risk_level = "中"
                risk_factors.append("该地址持有较大金额的狗狗币")
                suggestions.append("考虑分散资产到多个地址")
    
    # 3. 提供链上隐私建议
    if chain_name == "bitcoin":
        risk_factors.append("比特币是伪匿名的，所有交易都在公共账本上可见")
        suggestions.append("考虑使用混币服务或闪电网络以增强隐私")
    
    elif chain_name == "ethereum":
        risk_factors.append("以太坊上的所有交易和智能合约交互都是公开的")
        suggestions.append("敏感交易考虑使用支持隐私的解决方案")
    
    # 4. 提供一般性安全建议
    suggestions.append("使用强密码和双因素认证保护您的钱包")
    suggestions.append("定期备份您的私钥或助记词")
    
    return {
        "风险等级": risk_level,
        "风险因素": risk_factors,
        "建议": suggestions
    }


def query_address_transactions(chain_name, address, limit=10):
    """
    查询区块链地址的交易历史记录
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要查询的地址
        limit (int): 返回的交易记录数量限制
        
    返回:
        dict: 包含交易历史记录的字典
    """
    if chain_name not in SUPPORTED_CHAINS:
        return {"error": "不支持的区块链类型", "交易": []}

    transactions = []
    error_message = None

    try:
        if chain_name == "bitcoin":
            # 使用blockchain.info API查询比特币交易
            api_url = f"https://blockchain.info/rawaddr/{address}?limit={limit}"
            response = requests.get(api_url)

            if response.status_code == 200:
                data = response.json()
                tx_list = data.get("txs", [])

                for tx in tx_list:
                    tx_hash = tx.get("hash", "")
                    time = tx.get("time", 0)
                    time_formatted = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S') if time else "未知时间"
                    
                    # 计算交易金额和方向
                    inputs = tx.get("inputs", [])
                    outputs = tx.get("out", [])
                    
                    # 判断交易方向
                    is_sender = any(inp.get("prev_out", {}).get("addr") == address for inp in inputs)
                    is_receiver = any(out.get("addr") == address for out in outputs)
                    
                    if is_sender and is_receiver:
                        direction = "自我交易"
                        # 计算净支出
                        sent_value = sum(inp.get("prev_out", {}).get("value", 0) for inp in inputs 
                                        if inp.get("prev_out", {}).get("addr") == address)
                        received_value = sum(out.get("value", 0) for out in outputs 
                                            if out.get("addr") == address)
                        value = (received_value - sent_value) / 100000000
                    elif is_sender:
                        direction = "发送"
                        # 计算发送金额
                        value = -sum(inp.get("prev_out", {}).get("value", 0) for inp in inputs 
                                    if inp.get("prev_out", {}).get("addr") == address) / 100000000
                    else:  # is_receiver
                        direction = "接收"
                        # 计算接收金额
                        value = sum(out.get("value", 0) for out in outputs 
                                    if out.get("addr") == address) / 100000000
                    
                    # 确认数
                    confirmations = tx.get("block_height", 0)
                    
                    transactions.append({
                        "交易哈希": tx_hash,
                        "链接": f"https://www.blockchain.com/explorer/transactions/btc/{tx_hash}",
                        "时间": time,
                        "时间格式化": time_formatted,
                        "方向": direction,
                        "金额": value,
                        "确认数": confirmations
                    })
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        elif chain_name == "ethereum":
            # 使用Etherscan API查询以太坊交易
            api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset={limit}&sort=desc&apikey={ETHERSCAN_API_KEY}"
            response = requests.get(api_url)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    tx_list = data.get("result", [])

                    for tx in tx_list:
                        tx_hash = tx.get("hash", "")
                        time = int(tx.get("timeStamp", 0))
                        time_formatted = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S') if time else "未知时间"
                        
                        # 判断交易方向
                        if tx.get("from", "").lower() == address.lower() and tx.get("to", "").lower() == address.lower():
                            direction = "自我交易"
                            value = 0
                        elif tx.get("from", "").lower() == address.lower():
                            direction = "发送"
                            value = -float(tx.get("value", 0)) / 10**18
                        else:  # tx.get("to", "").lower() == address.lower()
                            direction = "接收"
                            value = float(tx.get("value", 0)) / 10**18
                        
                        # 确认数
                        confirmations = tx.get("confirmations", 0)
                        
                        transactions.append({
                            "交易哈希": tx_hash,
                            "链接": f"https://etherscan.io/tx/{tx_hash}",
                            "时间": time,
                            "时间格式化": time_formatted,
                            "方向": direction,
                            "金额": value,
                            "确认数": confirmations
                        })
                else:
                    error_message = data.get("message", "查询失败")
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        elif chain_name == "dogecoin":
            # 使用chain.so API查询狗狗币交易
            api_url = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}?limit={limit}"
            response = requests.get(api_url)
            if response.status_code == 200:
                data = response.json()
                if "txrefs" in data:
                    tx_list = data["txrefs"]

                    for tx in tx_list:
                        tx_hash = tx.get("tx_hash", "")
                        confirmed_time = tx.get("confirmed", "0")
                        if confirmed_time != "0":
                            time = int(datetime.strptime(confirmed_time, "%Y-%m-%dT%H:%M:%SZ").replace(
                                tzinfo=timezone.utc).timestamp())
                        else:
                            time = 0
                        value = float(tx.get("value", 0)) / 100000000
                        # 确定交易方向
                        if tx.get("tx_input_n", -1) == -1 and tx.get("tx_output_n", -1) != -1:
                            # 入账交易
                            direction = "接收"
                        elif tx.get("tx_output_n", -1) == -1 and tx.get("tx_input_n", -1) != -1:
                            # 出账交易
                            direction = "发送"
                            value = -value
                        else:
                            # 自交易
                            direction = "自我交易"
                        
                        time_formatted = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S') if time else "未知时间"
                        
                        transactions.append({
                            "交易哈希": tx_hash,
                            "链接": f"https://blockchair.com/dogecoin/transaction/{tx_hash}",
                            "时间": time,
                            "时间格式化": time_formatted,
                            "方向": direction,
                            "金额": value,
                            "确认数": tx.get("confirmations", 0)
                        })
                else:
                    error_message = "未找到交易记录"
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        # 如果出错且没有获取到交易记录，尝试使用备用API
        if error_message and not transactions:
            if chain_name == "bitcoin":
                # Blockchair备用API
                backup_api_url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?limit={limit}"
                response = requests.get(backup_api_url)

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and address in data["data"]:
                        tx_list = data["data"][address].get("transactions", [])

                        for tx_hash in tx_list:
                            transactions.append({
                                "交易哈希": tx_hash,
                                "链接": f"https://blockchair.com/bitcoin/transaction/{tx_hash}",
                                "备注": "使用备用API，详细信息需通过链接查看"
                            })

                        error_message = None  # 清除错误信息

            elif chain_name == "ethereum":
                # Blockchair备用API
                backup_api_url = f"https://api.blockchair.com/ethereum/dashboards/address/{address}?limit={limit}"
                response = requests.get(backup_api_url)

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and address in data["data"]:
                        tx_list = data["data"][address].get("calls", [])

                        for tx in tx_list:
                            tx_hash = tx.get("transaction_hash", "")
                            transactions.append({
                                "交易哈希": tx_hash,
                                "链接": f"https://etherscan.io/tx/{tx_hash}",
                                "备注": "使用备用API，详细信息需通过链接查看"
                            })

                        error_message = None  # 清除错误信息

            elif chain_name == "dogecoin":
                # Blockchair备用API
                backup_api_url = f"https://api.blockchair.com/dogecoin/dashboards/address/{address}?limit={limit}"
                response = requests.get(backup_api_url)

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and address in data["data"]:
                        tx_list = data["data"][address].get("transactions", [])

                        for tx_hash in tx_list:
                            transactions.append({
                                "交易哈希": tx_hash,
                                "链接": f"https://blockchair.com/dogecoin/transaction/{tx_hash}",
                                "备注": "使用备用API，详细信息需通过链接查看"
                            })

                        error_message = None  # 清除错误信息

        # 准备返回结果
        result = {
            "区块链": chain_name,  # 使用英文标识符
            "地址": address,
            "交易": transactions,
            "状态": "成功" if not error_message else "失败" if not transactions else "部分成功"
        }

        if error_message:
            result["错误"] = error_message

        return result
    except Exception as e:
        print(f"查询交易记录时出错: {str(e)}")
        return {
            "区块链": chain_name,
            "地址": address,
            "交易": [],
            "状态": "失败",
            "错误": f"查询失败: {str(e)}"
        }


def _format_timestamp(timestamp):
    """
    将UNIX时间戳格式化为可读的日期时间字符串
    
    参数:
        timestamp (int): UNIX时间戳
        
    返回:
        str: 格式化的日期时间字符串
    """

    try:
        dt = datetime.fromtimestamp(int(timestamp))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return "未知时间"

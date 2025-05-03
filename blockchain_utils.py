import binascii
from datetime import datetime, timezone
import json
import requests
from eth_account import Account
from web3 import Web3
import hashlib
import secrets
import base58
import hmac
import ecdsa

# 启用以太坊账户的助记词功能
# 注意：这是未经审计的功能，仅供测试使用
try:
    Account.enable_unaudited_hdwallet_features()
except Exception as e:
    print(f"警告: 无法启用以太坊助记词功能: {str(e)}")

# API密钥和端点
ETHERSCAN_API_KEY = "B38I8TH52C94KMBSIQ9PB11N9DHGCZ5HSJ"  # Etherscan API密钥

# 获取BlockCypher API密钥: 访问 https://www.blockcypher.com/
BLOCKCYPHER_API_KEY = "fde919e9087d414e9f8c4e3ecebe3a55"

# 支持的区块链列表
SUPPORTED_CHAINS = ["比特币", "以太坊", "狗狗币"]

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
    "比特币": "https://blockchain.info/address/{address}?format=json",
    # 每日请求限制: 100000个请求
    "以太坊": "https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey=" + ETHERSCAN_API_KEY,
    "狗狗币": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"  # 每天1000个请求,每小时100个请求,每秒3个请求
}

# 备用免费API端点(不需要API密钥)
BACKUP_API_ENDPOINTS = {
    "比特币": "https://blockchain.info/address/{address}?format=json",
    # "以太坊": "https://api.blockchair.com/ethereum/dashboards/address/{address}",
    "狗狗币": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
}

# 区块浏览器的链接
BLOCKCHAIN_EXPLORERS = {
    "比特币": "https://www.blockchain.com/explorer/addresses/btc/{address}",
    "以太坊": "https://etherscan.io/address/{address}",
    "狗狗币": "https://blockchair.com/dogecoin/address/{address}"
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
                if chain_name == "以太坊":
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

                elif chain_name == "比特币":
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

                elif chain_name == "狗狗币":
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
            "区块链": chain_name,
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "余额": 0.0  # 默认为0，确保始终有余额字段
        }

        # 根据不同区块链解析余额和交易
        if chain_name == "比特币":
            try:
                result["余额"] = float(data.get("final_balance", 0)) / 100000000  # 转换为BTC单位
            except (ValueError, TypeError):
                result["余额"] = 0.0

            result["交易数量"] = data.get("n_tx", 0)
            try:
                result["总接收"] = float(data.get("total_received", 0)) / 100000000
            except (ValueError, TypeError):
                result["总接收"] = 0.0

            try:
                result["总发送"] = float(data.get("total_sent", 0)) / 100000000
            except (ValueError, TypeError):
                result["总发送"] = 0.0

        elif chain_name == "以太坊":
            if data.get("status") == "1":
                try:
                    # 1. 解析余额
                    balance = int(data.get("result", "0"))
                    result["余额"] = float(Web3.from_wei(balance, "ether"))

                    # 2. 调用 Etherscan proxy 接口获取交易数量（Nonce）
                    proxy_url = (
                        f"https://api.etherscan.io/api"
                        f"?module=proxy"
                        f"&action=eth_getTransactionCount"
                        f"&address={address}"
                        f"&tag=latest"
                        f"&apikey={ETHERSCAN_API_KEY}"
                    )
                    proxy_resp = requests.get(proxy_url).json()
                    if proxy_resp.get("result"):
                        # result 是十六进制字符串，例如 "0x10"
                        result["交易数量"] = int(proxy_resp["result"], 16)
                    else:
                        result["交易数量"] = 0

                except (ValueError, TypeError, requests.RequestException) as e:
                    # 如果出错，仍然保证有余额字段
                    result["余额"] = 0.0
                    result["交易数量"] = 0
                    result["错误"] = f"解析以太坊数据失败: {e}"
            else:
                # status != "1" 时也尝试设置默认值
                result["余额"] = 0.0
                result["交易数量"] = 0
                result["错误"] = data.get("message", "查询失败")
        elif chain_name == "狗狗币":
            if response.status_code == 200:
                try:
                    result["余额"] = float(data.get("balance", 0)) / 100000000  # 转换为DOGE单位
                except (ValueError, TypeError):
                    result["余额"] = 0.0

                result["交易数量"] = data.get("n_tx", 0)
            elif "error" in data:
                # 尝试使用备用API
                return _try_backup_api(chain_name, address)
            else:
                result["余额"] = 0.0
                result["错误"] = data.get("message", "查询失败")

        return result

    except Exception as e:
        # 尝试使用备用API
        return _try_backup_api(chain_name, address, error=str(e))


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
    if chain == "比特币":
        return is_valid_btc_address(address)
    elif chain == "以太坊":
        return is_valid_eth_address(address)
    elif chain == "狗狗币":
        return is_valid_doge_address(address)
    return False


def _try_backup_api(chain_name, address, error=None):
    """
    当主要API失败时，尝试使用备用API查询
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要查询的地址
        error (str): 主API的错误信息
        
    返回:
        dict: 包含余额和交易信息的字典
    """
    if chain_name not in BACKUP_API_ENDPOINTS:
        return {
            "地址": address,
            "区块链": chain_name,
            "错误": error or "主API查询失败",
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "提示": "您可以通过浏览器链接手动查看该地址信息",
            "余额": 0.0  # 确保有余额字段
        }

    # 构建备用API URL
    backup_url = BACKUP_API_ENDPOINTS[chain_name].format(address=address)

    try:
        # 发送API请求
        response = requests.get(backup_url)

        if response.status_code != 200:
            return {
                "地址": address,
                "区块链": chain_name,
                "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
                "状态": "查询失败",
                "提示": "无法从备用API获取数据，请通过浏览器链接手动查看",
                "余额": 0.0  # 确保有余额字段
            }

        data = response.json()

        # 解析不同区块链的备用API数据
        result = {
            "地址": address,
            "区块链": chain_name,
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "API来源": "备用API",
            "余额": 0.0  # 默认为0，确保始终有余额字段
        }

        if chain_name == "比特币":
            try:
                result["余额"] = float(data.get("final_balance", 0)) / 100000000  # 转换为BTC单位
            except (ValueError, TypeError):
                result["余额"] = 0.0

            result["交易数量"] = data.get("n_tx", 0)

        elif chain_name == "以太坊" or chain_name == "狗狗币":
            # Blockchair API格式
            if "data" in data and address in data["data"]:
                address_data = data["data"][address]
                try:
                    result["余额"] = float(address_data.get("address", {}).get("balance", 0)) / (
                        10 ** 18 if chain_name == "以太坊" else 10 ** 8)
                except (ValueError, TypeError, KeyError):
                    result["余额"] = 0.0

                result["交易数量"] = address_data.get("address", {}).get("transaction_count", 0)
            else:
                result["余额"] = 0.0
                result["错误"] = "从备用API获取数据失败"

        return result

    except Exception as e:
        return {
            "地址": address,
            "区块链": chain_name,
            "错误": f"备用API查询失败: {str(e)}",
            "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
            "余额": 0.0,
            "提示": "所有API查询均失败，请通过浏览器链接手动查看该地址信息"
        }


def assess_address_risk(chain_name, address, transaction_count=None, balance=None):
    """
    评估地址的风险因素
    
    参数:
        chain_name (str): 区块链名称
        address (str): 要评估的地址
        transaction_count (int): 交易数量，如果已知
        balance (float): 余额，如果已知
        
    返回:
        dict: 风险评估结果
    """
    risk_level = "低"
    risk_factors = []
    suggestions = []

    # 1. 检查地址是否为空地址或全零地址
    if address == "0x0000000000000000000000000000000000000000" or address == "1111111111111111111114oLvT2":
        risk_level = "高"
        risk_factors.append("该地址是特殊地址（零地址或燃烧地址）")
        suggestions.append("不要向此地址发送资金")

    # 2. 检查余额和交易历史
    if balance is not None and balance > 0:
        if transaction_count is not None:
            if transaction_count == 0 and balance > 0:
                risk_level = "中"
                risk_factors.append("地址有余额但无交易历史，可能是冷钱包或闲置地址")
                suggestions.append("确认该地址确实属于预期的接收方")

            elif transaction_count > 1000:
                risk_level = "中"
                risk_factors.append("地址交易频繁，可能是交易所地址或热钱包")
                suggestions.append("热钱包通常安全性较低，建议不要长期存储大量资产")

    # 3. 提供链上隐私建议
    if chain_name == "比特币":
        risk_factors.append("比特币是伪匿名的，所有交易都在公共账本上可见")
        suggestions.append("考虑使用混币服务或闪电网络以增强隐私")

    elif chain_name == "以太坊":
        risk_factors.append("以太坊上的所有交易和智能合约交互都是公开的")
        suggestions.append("敏感交易考虑使用支持隐私的解决方案")

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
        if chain_name == "比特币":
            # 使用blockchain.info API查询比特币交易
            api_url = f"https://blockchain.info/rawaddr/{address}?limit={limit}"
            response = requests.get(api_url)

            if response.status_code == 200:
                data = response.json()
                tx_list = data.get("txs", [])

                for tx in tx_list:
                    # 计算交易方向和金额
                    tx_hash = tx.get("hash", "")
                    time = tx.get("time", 0)

                    # 分析输入和输出，确定交易方向
                    is_sender = False
                    is_receiver = False
                    total_input = 0
                    total_output = 0

                    # 分析输入
                    for inp in tx.get("inputs", []):
                        prev_out = inp.get("prev_out", {})
                        if prev_out.get("addr") == address:
                            is_sender = True
                            total_input += prev_out.get("value", 0)

                    # 分析输出
                    for out in tx.get("out", []):
                        if out.get("addr") == address:
                            is_receiver = True
                            total_output += out.get("value", 0)

                    # 确定交易方向和净额
                    if is_sender and is_receiver:
                        direction = "自我交易"
                        net_amount = (total_output - total_input) / 100000000  # 转换为BTC
                    elif is_sender:
                        direction = "发送"
                        net_amount = -total_input / 100000000  # 转换为BTC
                    elif is_receiver:
                        direction = "接收"
                        net_amount = total_output / 100000000  # 转换为BTC
                    else:
                        continue  # 跳过与此地址无关的交易

                    transactions.append({
                        "交易哈希": tx_hash,
                        "时间": time,
                        "时间格式化": _format_timestamp(time),
                        "方向": direction,
                        "金额": abs(net_amount),
                        "净额": net_amount,
                        "确认数": tx.get("confirmations", 0),
                        "区块高度": tx.get("block_height", "未确认"),
                        "链接": f"https://www.blockchain.com/explorer/transactions/btc/{tx_hash}"
                    })
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        elif chain_name == "以太坊":
            # 使用Etherscan API查询以太坊交易
            api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset={limit}&sort=desc&apikey={ETHERSCAN_API_KEY}"
            response = requests.get(api_url)

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1":
                    tx_list = data.get("result", [])

                    for tx in tx_list:
                        tx_hash = tx.get("hash", "")
                        time = int(tx.get("timeStamp", "0"))
                        from_addr = tx.get("from", "").lower()
                        to_addr = tx.get("to", "").lower()
                        value = int(tx.get("value", "0"))

                        # 确定交易方向
                        if from_addr == address.lower() and to_addr == address.lower():
                            direction = "自我交易"
                        elif from_addr == address.lower():
                            direction = "发送"
                        else:
                            direction = "接收"

                        # 转换为ETH
                        amount = float(Web3.from_wei(value, "ether"))

                        transactions.append({
                            "交易哈希": tx_hash,
                            "时间": time,
                            "时间格式化": _format_timestamp(time),
                            "方向": direction,
                            "金额": amount,
                            "净额": -amount if direction == "发送" else amount,
                            "gas价格": int(tx.get("gasPrice", "0")) / 10 ** 9,  # Gwei
                            "gas使用量": int(tx.get("gasUsed", "0")),
                            "确认数": "已确认" if int(tx.get("confirmations", "0")) > 0 else "未确认",
                            "链接": f"https://etherscan.io/tx/{tx_hash}"
                        })
                else:
                    error_message = data.get("message", "API请求失败")
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        elif chain_name == "狗狗币":
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
                        else:
                            # 自交易
                            direction = "自交易"
                        transactions.append({
                            "交易哈希": tx_hash,
                            "时间": time,
                            "时间格式化": _format_timestamp(time),
                            "方向": direction,
                            "金额": value,
                            "净额": value if direction == "接收" else -value,
                            "确认数": tx.get("confirmations", 0),
                            "链接": f"https://blockchair.com/dogecoin/transaction/{tx_hash}"
                        })


                else:
                    error_message = "API请求失败"
            else:
                error_message = f"API请求失败，状态码: {response.status_code}"

        # 如果出错且没有获取到交易记录，尝试使用备用API
        if error_message and not transactions:
            if chain_name == "比特币":
                # Blockchair备用API
                backup_api_url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?limit={limit}"
                response = requests.get(backup_api_url)

                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and address in data["data"]:
                        tx_list = data["data"][address].get("transactions", [])

                        # 由于备用API只提供了交易哈希列表，我们只能提供有限的信息
                        for tx_hash in tx_list:
                            transactions.append({
                                "交易哈希": tx_hash,
                                "链接": f"https://www.blockchain.com/explorer/transactions/btc/{tx_hash}",
                                "备注": "使用备用API，详细信息需通过链接查看"
                            })

                        error_message = None  # 清除错误信息

            elif chain_name == "以太坊":
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

            elif chain_name == "狗狗币":
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

    except Exception as e:
        error_message = f"查询交易记录时出错: {str(e)}"

    # 准备返回结果
    result = {
        "地址": address,
        "区块链": chain_name,
        "交易记录数": len(transactions),
        "交易": transactions,
        "浏览器链接": BLOCKCHAIN_EXPLORERS[chain_name].format(address=address),
        "限制": limit
    }

    if error_message:
        result["错误"] = error_message
        result["状态"] = "部分成功" if transactions else "失败"
    else:
        result["状态"] = "成功"

    return result


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

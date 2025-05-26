from blockchain_utils import is_valid_btc_address
def test_is_valid_btc_address_valid_p2pkh():
    # Valid P2PKH address (starts with 1)
    assert is_valid_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is True

def test_is_valid_btc_address_valid_p2sh():
    # Valid P2SH address (starts with 3)
    assert is_valid_btc_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

def test_is_valid_btc_address_invalid_checksum():
    # Invalid address (bad checksum)
    assert is_valid_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb") is False

def test_is_valid_btc_address_invalid_prefix():
    # Valid base58 but wrong prefix (not 0x00 or 0x05)
    # Litecoin address as example (starts with L)
    assert is_valid_btc_address("LZMFZrVv7i3rGk1ZQ1QK1QK1QK1QK1QK1Q") is False

def test_is_valid_btc_address_invalid_format():
    # Not a base58 string
    assert is_valid_btc_address("not_a_btc_address") is False

def test_is_valid_btc_address_empty():
    # Empty string
    assert is_valid_btc_address("") is False
// 国际化翻译配置
const translations = {
    'zh': {
        // 导航菜单
        'nav_home': '首页',
        'nav_mnemonic': '助记词生成',
        'nav_about': '关于系统',
        'nav_profile': '个人资料',
        'nav_logout': '退出登录',
        'system_title': '区块链助记词安全性测试系统',
        'mnemonic_tool': '助记词生成工具',
        
        // 首页
        'start_generate': '开始生成',
        'system_description': '一个基于Python Flask框架的区块链助记词安全性测试系统，遵循BIP39标准协议，专注于助记词的生成、验证和安全性评估。系统提供了全面的区块链助记词管理和多链地址派生功能，包括生成12至24个单词的标准BIP39助记词(128-256位熵)、支持8种语言词库、助记词有效性验证、多链(比特币、以太坊、狗狗币)钱包地址派生、区块链余额查询以及完整的种子派生过程可视化。',
        'feature_bip39': 'BIP39标准',
        'feature_bip39_desc': '完全实现Bitcoin改进提案BIP39，生成兼容区块链标准的助记词和种子',
        'feature_multilang': '多语言支持',
        'feature_multilang_desc': '支持中文简体、中文繁体、英文、韩语、日语等多种语言的助记词生成，满足不同场景需求',
        'feature_seed': '种子派生',
        'feature_seed_desc': '从助记词派生出512位种子，可用于后续的确定性密钥生成和区块链应用',
        'login_required_title': '请先登录',
        'login_required_text': '您需要登录后才能访问助记词生成功能',
        'go_login': '去登录',
        'cancel': '取消',
        
        // 关于页面
        'about_system': '关于区块链助记词安全性测试系统',
        'what_is_mnemonic': '什么是助记词？',
        'mnemonic_desc_1': '<strong>助记词</strong>(Mnemonic)是一种用于记忆和恢复密钥的技术，在加密货币、密码管理和信息安全领域被广泛应用。',
        'mnemonic_desc_2': '传统的私钥或种子通常是一长串随机字节，难以记忆和抄写。<strong>助记词</strong>通过将这些随机字节映射为一组人类可读的单词，使得备份和恢复过程变得更加简单和可靠。',
        'mnemonic_desc_3': '在比特币和以太坊等区块链系统中，通常使用12-24个随机单词作为钱包的备份方式，这些<strong>助记词</strong>可以完全恢复用户的私钥和资产。',
        'bip39_standard': 'BIP39标准',
        'supported': '已支持',
        'bip39_desc': 'BIP39（Bitcoin Improvement Proposal 39）是比特币改进提案之一，定义了生成确定性钱包的助记词标准。本系统现已完全支持BIP39标准',
        'bip39_generation_process': 'BIP39助记词生成流程',
        'generate_entropy': '生成熵',
        'generate_entropy_desc': ' ： 使用密码学安全的随机数生成器创建一定位数（128-256位）的熵源',
        'add_checksum': '添加校验和',
        'add_checksum_desc': ' ： 对熵进行SHA-256哈希运算，取结果的前(熵位数/32)位作为校验和',
        'split_bits': '拆分比特',
        'split_bits_desc': ' ： 将熵和校验和组合后拆分为每组11位的段',
        'map_to_words': '映射到单词',
        'map_to_words_desc': ' ： 将每个11位段映射到预定义的2048个单词列表中对应的单词',
        'generate_seed': '生成种子',
        'generate_seed_desc': ' ： 使用PBKDF2函数（使用2048轮HMAC-SHA512）将助记词转换为512位的种子',
        'derive_keys': '派生密钥',
        'derive_keys_desc': ' ： 基于生成的种子派生密钥（通常使用BIP32标准）',
        'system_features': '系统特点',
        'standard_compatible': '标准兼容',
        'standard_compatible_desc': '：完全符合BIP39标准，可用于实际加密货币钱包',
        'multi_language': '多语言支持',
        'multi_language_desc': '：支持中文简体、中文繁体和英文等多种语言',
        'seed_derivation': '种子派生',
        'seed_derivation_desc': '：生成标准的512位种子，可用于后续密钥派生',
        'custom_wordlist': '自定义词库',
        'custom_wordlist_desc': '：支持用户上传自定义词库（注：自定义词库不符合BIP39标准）',
        'mnemonic_validation': '助记词验证',
        'mnemonic_validation_desc': '：提供BIP39助记词的验证功能，确保助记词有效',
        'security_recommendations': '安全建议',
        'important_security_tips': '重要安全提示',
        'security_intro': '虽然本系统实现了标准的BIP39，但对于实际加密资产管理，我们仍有以下安全建议：',
        'security_tip_1': '使用离线设备（如硬件钱包）生成和存储真正重要的助记词',
        'security_tip_2': '不要在联网设备上输入已有的助记词，除非确实需要访问相关资产',
        'security_tip_3': '使用物理方式（如纸质记录、金属板）备份助记词',
        'security_tip_4': '将备份存放在安全的物理位置，考虑多地保存',
        'security_tip_5': '不要向任何人透露您的助记词，任何要求您提供助记词的人都可能是诈骗者',
        'security_tip_6': '考虑使用BIP39密码短语提供额外安全层级',
        
        // 助记词页面
        'generate_tab': '生成助记词',
        'validate_tab': '验证助记词',
        'blockchain_tab': '区块链地址',
        'word_count': '词语数量',
        'language': '语言',
        'generate_btn': '生成助记词',
        'security_analysis_btn': '安全性分析',
        'copy_btn': '复制助记词',
        'copy_seed_btn': '复制种子',
        'derived_seed': '派生种子 (H)',
        'security_analysis': '助记词安全性分析',
        'entropy_value': '熵值',
        'strength': '强度',
        'crack_time': '估计破解时间',
        'security_tips': '安全提示',
        'security_tip_1': '12个词的助记词提供约128位熵，24个词提供约256位熵',
        'security_tip_2': '您的助记词应当保存在离线环境中，永远不要通过电子方式共享',
        'security_tip_3': '使用硬件钱包可以大大提高您的资金安全性',
        'input_mnemonic': '输入助记词',
        'mnemonic_language': '助记词语言',
        'validate_btn': '验证助记词',
        
        // 表单和提示
        'bits': '位',
        'not_generated': '未生成',
        'mnemonic_placeholder': '请输入空格分隔的助记词，例如：apple banana cherry ...',
        'mnemonic_tip': '请确保单词的准确性和顺序，单词间使用空格分隔',
        'info_tip': '本系统仅使用符合BIP39标准的助记词词库，确保生成的助记词可用于加密货币钱包和区块链应用。',
        'validate_info': '请输入BIP39标准助记词进行验证。验证成功后将显示派生的种子。',
        
        // 页脚
        'footer_copyright': '© 2025 区块链助记词安全性测试系统 | 版权所有',
        
        // 区块链地址模块
        'blockchain_info': '从助记词生成各种区块链地址，并查询余额和交易记录。请确保您的助记词安全，不要在不信任的环境中输入。',
        'blockchain_mnemonic_placeholder': '请输入助记词，单词间用空格分隔',
        'mnemonic_security_tip': '助记词非常重要，请确保在安全的环境中操作',
        'passphrase_optional': '密码(可选)',
        'passphrase_placeholder': 'BIP39密码短语(可选)',
        'address_count': '每个链生成地址数量',
        'address_count_1': '1个地址',
        'address_count_3': '3个地址',
        'address_count_5': '5个地址',
        'address_count_10': '10个地址',
        'select_blockchain': '选择区块链',
        'loading': '加载中...',
        'loading_blockchain_list': '加载区块链列表...',
        'generate_blockchain_address': '生成区块链地址',
        'generated_addresses': '生成的区块链地址',
        'query_address_balance': '查询地址余额与交易',
        'input_address': '输入地址',
        'address_placeholder': '输入要查询的区块链地址',
        'query_btn': '查询',
        'balance_info': '余额信息',
        'transaction_history': '交易历史',
        'transaction_records': '交易记录',
        'show_5': '显示5条',
        'show_10': '显示10条',
        'show_20': '显示20条',
        'show_50': '显示50条',
        'refresh': '刷新',
        'click_query_tip': '点击"查询交易"按钮获取交易历史',
        
        // 币种名称
        'bitcoin': '比特币',
        'ethereum': '以太坊',
        'dogecoin': '狗狗币',
    },
    'en': {
        // Navigation menu
        'nav_home': 'Home',
        'nav_mnemonic': 'Mnemonic Generator',
        'nav_about': 'About',
        'nav_profile': 'Profile',
        'nav_logout': 'Logout',
        'system_title': 'Blockchain Mnemonic Security Testing System',
        'mnemonic_tool': 'Mnemonic Generation Tool',
        
        // Home page
        'start_generate': 'Start Generate',
        'system_description': 'A blockchain mnemonic security testing system based on Python Flask framework, following the BIP39 standard protocol, focusing on mnemonic generation, verification, and security assessment. The system provides comprehensive blockchain mnemonic management and multi-chain address derivation functions, including generating standard BIP39 mnemonics of 12 to 24 words (128-256 bits of entropy), supporting 8 language wordlists, mnemonic validity verification, multi-chain (Bitcoin, Ethereum, Dogecoin) wallet address derivation, blockchain balance query, and complete seed derivation process visualization.',
        'feature_bip39': 'BIP39 Standard',
        'feature_bip39_desc': 'Fully implements Bitcoin Improvement Proposal BIP39, generating mnemonics and seeds compatible with blockchain standards',
        'feature_multilang': 'Multi-language Support',
        'feature_multilang_desc': 'Supports mnemonic generation in multiple languages including Simplified Chinese, Traditional Chinese, English, Korean, Japanese, etc., to meet different scenario needs',
        'feature_seed': 'Seed Derivation',
        'feature_seed_desc': 'Derives 512-bit seeds from mnemonics, which can be used for subsequent deterministic key generation and blockchain applications',
        'login_required_title': 'Login Required',
        'login_required_text': 'You need to log in to access the mnemonic generation feature',
        'go_login': 'Go to Login',
        'cancel': 'Cancel',
        
        // About page
        'about_system': 'About Blockchain Mnemonic Security Testing System',
        'what_is_mnemonic': 'What is a Mnemonic?',
        'mnemonic_desc_1': '<strong>Mnemonic</strong> is a technique used for memorizing and recovering keys, widely applied in cryptocurrency, password management, and information security fields.',
        'mnemonic_desc_2': 'Traditional private keys or seeds are typically long strings of random bytes, difficult to memorize and transcribe. <strong>Mnemonics</strong> make backup and recovery processes simpler and more reliable by mapping these random bytes to a set of human-readable words.',
        'mnemonic_desc_3': 'In blockchain systems like Bitcoin and Ethereum, 12-24 random words are commonly used as wallet backup methods. These <strong>mnemonics</strong> can fully restore users\' private keys and assets.',
        'bip39_standard': 'BIP39 Standard',
        'supported': 'Supported',
        'bip39_desc': 'BIP39 (Bitcoin Improvement Proposal 39) is one of the Bitcoin improvement proposals that defines the mnemonic standard for generating deterministic wallets. This system now fully supports the BIP39 standard.',
        'bip39_generation_process': 'BIP39 Mnemonic Generation Process',
        'generate_entropy': 'Generate Entropy',
        'generate_entropy_desc': ' : Use a cryptographically secure random number generator to create entropy of a certain bit length (128-256 bits)',
        'add_checksum': 'Add Checksum',
        'add_checksum_desc': ' : Perform SHA-256 hash operation on the entropy, take the first (entropy bits/32) bits of the result as the checksum',
        'split_bits': 'Split Bits',
        'split_bits_desc': ' : Split the combined entropy and checksum into segments of 11 bits each',
        'map_to_words': 'Map to Words',
        'map_to_words_desc': ' : Map each 11-bit segment to the corresponding word in a predefined list of 2048 words',
        'generate_seed': 'Generate Seed',
        'generate_seed_desc': ' : Use the PBKDF2 function (with 2048 rounds of HMAC-SHA512) to convert the mnemonic into a 512-bit seed',
        'derive_keys': 'Derive Keys',
        'derive_keys_desc': ' : Derive keys based on the generated seed (typically using the BIP32 standard)',
        'system_features': 'System Features',
        'standard_compatible': 'Standard Compatible',
        'standard_compatible_desc': ': Fully compliant with the BIP39 standard, usable for actual cryptocurrency wallets',
        'multi_language': 'Multi-language Support',
        'multi_language_desc': ': Supports multiple languages including Simplified Chinese, Traditional Chinese, and English',
        'seed_derivation': 'Seed Derivation',
        'seed_derivation_desc': ': Generates standard 512-bit seeds for subsequent key derivation',
        'custom_wordlist': 'Custom Wordlists',
        'custom_wordlist_desc': ': Supports user-uploaded custom wordlists (Note: custom wordlists do not comply with the BIP39 standard)',
        'mnemonic_validation': 'Mnemonic Validation',
        'mnemonic_validation_desc': ': Provides validation functionality for BIP39 mnemonics to ensure their validity',
        'security_recommendations': 'Security Recommendations',
        'important_security_tips': 'Important Security Tips',
        'security_intro': 'Although this system implements the standard BIP39, we still have the following security recommendations for actual crypto asset management:',
        'security_tip_1': 'Use offline devices (such as hardware wallets) to generate and store truly important mnemonics',
        'security_tip_2': 'Do not enter existing mnemonics on networked devices unless you really need to access the related assets',
        'security_tip_3': 'Use physical methods (such as paper records, metal plates) to back up mnemonics',
        'security_tip_4': 'Store backups in secure physical locations, consider storing in multiple places',
        'security_tip_5': 'Do not reveal your mnemonic to anyone; anyone asking for your mnemonic may be a scammer',
        'security_tip_6': 'Consider using a BIP39 passphrase to provide an additional security layer',
        
        // Mnemonic page
        'generate_tab': 'Generate Mnemonic',
        'validate_tab': 'Validate Mnemonic',
        'blockchain_tab': 'Blockchain Address',
        'word_count': 'Word Count',
        'language': 'Language',
        'generate_btn': 'Generate Mnemonic',
        'security_analysis_btn': 'Security Analysis',
        'copy_btn': 'Copy Mnemonic',
        'copy_seed_btn': 'Copy Seed',
        'derived_seed': 'Derived Seed (H)',
        'security_analysis': 'Mnemonic Security Analysis',
        'entropy_value': 'Entropy',
        'strength': 'Strength',
        'crack_time': 'Estimated Crack Time',
        'security_tips': 'Security Tips',
        'security_tip_1': '12-word mnemonics provide about 128 bits of entropy, 24-word mnemonics provide about 256 bits',
        'security_tip_2': 'Your mnemonic should be stored offline and never shared electronically',
        'security_tip_3': 'Using a hardware wallet can greatly improve the security of your funds',
        'input_mnemonic': 'Input Mnemonic',
        'mnemonic_language': 'Mnemonic Language',
        'validate_btn': 'Validate Mnemonic',
        
        // Forms and tips
        'bits': 'bits',
        'not_generated': 'Not Generated',
        'mnemonic_placeholder': 'Please enter space-separated mnemonic words, e.g.: apple banana cherry ...',
        'mnemonic_tip': 'Please ensure the accuracy and order of words, separated by spaces',
        'info_tip': 'This system only uses BIP39 standard mnemonic wordlists, ensuring generated mnemonics can be used for cryptocurrency wallets and blockchain applications.',
        'validate_info': 'Please enter a BIP39 standard mnemonic for validation. The derived seed will be displayed after successful validation.',
        
        // Footer
        'footer_copyright': '© 2025 Blockchain Mnemonic Security Testing System | All Rights Reserved',
        
        // Blockchain Address Module
        'blockchain_info': 'Generate various blockchain addresses from mnemonics and query balances and transaction records. Please ensure your mnemonic is secure and do not enter it in untrusted environments.',
        'blockchain_mnemonic_placeholder': 'Please enter mnemonic words separated by spaces',
        'mnemonic_security_tip': 'Mnemonics are extremely important, please ensure you operate in a secure environment',
        'passphrase_optional': 'Passphrase (optional)',
        'passphrase_placeholder': 'BIP39 passphrase (optional)',
        'address_count': 'Number of addresses per chain',
        'address_count_1': '1 address',
        'address_count_3': '3 addresses',
        'address_count_5': '5 addresses',
        'address_count_10': '10 addresses',
        'select_blockchain': 'Select Blockchain',
        'loading': 'Loading...',
        'loading_blockchain_list': 'Loading blockchain list...',
        'generate_blockchain_address': 'Generate Blockchain Address',
        'generated_addresses': 'Generated Blockchain Addresses',
        'query_address_balance': 'Query Address Balance & Transactions',
        'input_address': 'Input Address',
        'address_placeholder': 'Enter blockchain address to query',
        'query_btn': 'Query',
        'balance_info': 'Balance Information',
        'transaction_history': 'Transaction History',
        'transaction_records': 'Transaction Records',
        'show_5': 'Show 5',
        'show_10': 'Show 10',
        'show_20': 'Show 20',
        'show_50': 'Show 50',
        'refresh': 'Refresh',
        'click_query_tip': 'Click "Query" button to get transaction history',
        
        // 币种名称
        'bitcoin': 'Bitcoin',
        'ethereum': 'Ethereum',
        'dogecoin': 'Dogecoin',
        'litecoin': 'Litecoin',
        'bitcoin_cash': 'Bitcoin Cash',
        'ripple': 'Ripple',
        'cardano': 'Cardano',
        'polkadot': 'Polkadot',
        'solana': 'Solana',
    }
};

// 当前语言
let currentLanguage = localStorage.getItem('app_language') || 'zh';

// 初始化时从服务器获取语言设置
function initLanguage() {
    fetch('/api/get_language')
        .then(response => response.json())
        .then(data => {
            if (data.language) {
                currentLanguage = data.language;
                localStorage.setItem('app_language', currentLanguage);
                updatePageText();
                updateButtonState();
            }
        })
        .catch(error => {
            console.error('获取语言设置失败:', error);
        });
}

// 更新语言切换按钮状态
function updateButtonState() {
    const langZh = document.getElementById('lang-zh');
    const langEn = document.getElementById('lang-en');
    
    if (langZh && langEn) {
        langZh.classList.toggle('active', currentLanguage === 'zh');
        langEn.classList.toggle('active', currentLanguage === 'en');
    }
}

// 切换语言
function switchLanguage(lang) {
    if (translations[lang]) {
        currentLanguage = lang;
        localStorage.setItem('app_language', lang);
        
        // 同步到服务器
        fetch('/api/set_language', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ language: lang })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updatePageText();
                updateButtonState();
                // 触发自定义事件，通知其他可能需要更新的组件
                document.dispatchEvent(new CustomEvent('languageChanged', { detail: { language: lang } }));
            }
        })
        .catch(error => {
            console.error('设置语言失败:', error);
        });
        
        return true;
    }
    return false;
}

// 获取翻译文本
function getTranslation(key) {
    if (!key) return '';
    
    // 确保key是小写的，因为我们的翻译键都是小写的
    const lowerKey = key.toLowerCase();
    
    // 尝试获取当前语言的翻译
    if (translations[currentLanguage] && translations[currentLanguage][lowerKey] !== undefined) {
        return translations[currentLanguage][lowerKey];
    }
    
    // 如果找不到翻译，返回原始key
    return key;
}

// 更新页面上的所有文本
function updatePageText() {
    // 更新带有data-i18n属性的元素
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (key) {
            // 检查是否为占位符文本
            if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
                if (element.getAttribute('placeholder')) {
                    element.setAttribute('placeholder', getTranslation(key) || key);
                }
            } else {
                // 如果找不到翻译，使用键名作为默认值
                element.textContent = getTranslation(key) || element.textContent;
            }
        }
    });
    
    // 更新select元素中的选项
    document.querySelectorAll('select option[data-i18n]').forEach(option => {
        const key = option.getAttribute('data-i18n');
        if (key) {
            option.textContent = getTranslation(key) || option.textContent;
        }
    });
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    initLanguage();
    updatePageText();
});

// 导出函数供其他模块使用
window.i18n = {
    switchLanguage,
    getTranslation,
    getCurrentLanguage: () => currentLanguage,
    updateButtonState
};
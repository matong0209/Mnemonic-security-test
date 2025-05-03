from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import binascii
import hashlib
import secrets
import unicodedata
import blockchain_utils
import datetime
import hmac


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# ---------- 数据库配置 ----------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------- 用户模型 ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

# 助记词历史模型
class MnemonicHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    language = db.Column(db.String(20), nullable=False)
    word_count = db.Column(db.Integer, nullable=False)
    seed_hash = db.Column(db.String(64), nullable=False)  # 存储种子的哈希，不存储明文
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    
    user = db.relationship('User', backref=db.backref('mnemonic_histories', lazy=True))


# 在MnemonicHistory类定义后添加

# 安全日志模型
class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 操作类型，如 "mnemonic_view"
    details = db.Column(db.Text)  # 详细信息
    ip_address = db.Column(db.String(50))  # 可选：记录操作IP地址
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    
    user = db.relationship('User', backref=db.backref('security_logs', lazy=True))

# 词库文件路径
txt_word_files = {
    "中文简体": os.path.join('static', 'data', 'data', 'chinese_simplified.txt'),
    "中文繁体": os.path.join('static', 'data', 'data', 'chinese_traditional.txt'),
    "英文":     os.path.join('static', 'data', 'data', 'english.txt'),
    "法语":     os.path.join('static', 'data', 'data', 'french.txt'),
    "西班牙语": os.path.join('static', 'data', 'data', 'spanish.txt'),
    "意大利语": os.path.join('static', 'data', 'data', 'italian.txt'),
    "日语":     os.path.join('static', 'data', 'data', 'japanese.txt'),
    "韩语":     os.path.join('static', 'data', 'data', 'korean.txt')
}

# 语言映射到 BIP39 代码
BIP39_LANGUAGE_MAP = {
    "中文简体": "chinese_simplified",
    "中文繁体": "chinese_traditional",
    "英文":     "english",
    "法语":     "french",
    "西班牙语": "spanish",
    "意大利语": "italian",
    "日语":     "japanese",
    "韩语":     "korean"
}

class MnemonicGenerator:
    def __init__(self, language="english"):
        self.radix = 2048
        self.language = language
        # 找到中文名对应的词库路径
        for lang_cn, code in BIP39_LANGUAGE_MAP.items():
            if code == language:
                wordlist_path = txt_word_files[lang_cn]
                break
        else:
            wordlist_path = os.path.join('static', 'data', 'data', f'{language}.txt')
        # 加载词库
        if not os.path.isfile(wordlist_path):
            raise ValueError(f"语言 {language} 的词库不存在 ({wordlist_path})")
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            self.wordlist = [w.strip() for w in f if w.strip()]
        if len(self.wordlist) != self.radix:
            raise ValueError(f"词库必须包含 {self.radix} 个单词，当前 {len(self.wordlist)} 个")
        # 日语用全角空格
        self.delimiter = "\u3000" if language == "japanese" else " "
    
    @staticmethod
    def normalize_string(txt):
        if isinstance(txt, bytes):
            txt = txt.decode('utf-8')
        if not isinstance(txt, str):
            raise TypeError("文本必须是 str 或 bytes")
        return unicodedata.normalize('NFKD', txt)
    
    def generate(self, strength=128):
        if strength not in (128,160,192,224,256):
            raise ValueError("strength 必须是 128,160,192,224,256 之一")
        entropy = secrets.token_bytes(strength // 8)
        return self.to_mnemonic(entropy)
    
    def to_mnemonic(self, data: bytes) -> str:
        if len(data) not in (16,20,24,28,32):
            raise ValueError("熵字节长度必须是 16,20,24,28 或 32")
        h = hashlib.sha256(data).hexdigest()
        bits = bin(int.from_bytes(data,'big'))[2:].zfill(len(data)*8) \
             + bin(int(h,16))[2:].zfill(256)[:len(data)*8//32]
        words = []
        for i in range(len(bits)//11):
            idx = int(bits[i*11:(i+1)*11], 2)
            words.append(self.wordlist[idx])
        return self.delimiter.join(words)
    
    def check(self, mnemonic: str) -> bool:
        mn = self.normalize_string(mnemonic)
        parts = mn.split(self.delimiter)
        if len(parts) not in (12,15,18,21,24):
            return False
        try:
            bitstr = ''.join(bin(self.wordlist.index(w))[2:].zfill(11) for w in parts)
        except ValueError:
            return False
        l = len(bitstr)
        ent_bits = bitstr[:l//33*32]
        cs_bits  = bitstr[l//33*32:]
        ent_bytes = int(ent_bits,2).to_bytes(len(ent_bits)//8,'big')
        hash_bits = bin(int(hashlib.sha256(ent_bytes).hexdigest(),16))[2:].zfill(256)
        return hash_bits[:len(cs_bits)] == cs_bits
    
    @staticmethod
    def to_seed(mnemonic: str, passphrase: str="") -> bytes:
        mn = MnemonicGenerator.normalize_string(mnemonic)
        pw = MnemonicGenerator.normalize_string(passphrase)
        salt = ("mnemonic" + pw).encode('utf-8')
        return hashlib.pbkdf2_hmac('sha512', mn.encode('utf-8'), salt, 2048)

# 辅助函数
def generate_bip39_mnemonic(strength=128, language="english"):
    mg = MnemonicGenerator(language)
    return mg.generate(strength).split(MnemonicGenerator(language).delimiter)

def validate_mnemonic(mnemonic, language="english"):
    mg = MnemonicGenerator(language)
    return mg.check(mnemonic)

ENTROPY_BITS_MAP = {12:128,15:160,18:192,21:224,24:256}



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')

# 注册
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        e = request.form.get('email','').strip()
        p = request.form.get('password','')
        c = request.form.get('confirm_password','')
        if not all((u,e,p,c)):
            flash('请填写所有字段','danger'); return render_template('register.html')
        if p!=c:
            flash('两次密码不一致','danger'); return render_template('register.html')
        if User.query.filter_by(username=u).first():
            flash('用户名已存在','danger'); return render_template('register.html')
        if User.query.filter_by(email=e).first():
            flash('邮箱已被注册','danger'); return render_template('register.html')
        new = User(username=u,email=e)
        new.set_password(p)
        db.session.add(new); db.session.commit()
        flash('注册成功，请登录','success')
        return redirect(url_for('login'))
    return render_template('register.html')

# 登录
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if not all((u,p)):
            flash('请填写所有字段','danger'); return render_template('login.html')
        user = User.query.filter_by(username=u).first()
        if user and user.check_password(p):
            session['user_id']=user.id
            session['username']=user.username
            flash('登录成功','success')
            return redirect(url_for('index'))
        flash('用户名或密码错误','danger')
    return render_template('login.html')

# 登出
@app.route('/logout')
def logout():
    session.pop('user_id',None)
    session.pop('username',None)
    flash('已登出','success')
    return redirect(url_for('index'))

# 用户中心
@app.route('/profile')
def profile():
    uid = session.get('user_id')
    if not uid:
        flash('请先登录','warning'); return redirect(url_for('login'))
    user = User.query.get(uid)
    if not user:
        session.clear(); flash('用户不存在','danger'); return redirect(url_for('login'))
    return render_template('profile.html', user=user)

# 助记词页面（需登录）
@app.route('/mnemonic')
def mnemonic():
    if 'user_id' not in session:
        flash('请先登录','warning'); return redirect(url_for('login'))
    return render_template('mnemonic.html')

# 生成助记词 API
@app.route('/api/generate_mnemonic', methods=['POST'])
def generate_mnemonic_api():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}),401
    data = request.json or {}
    count = int(data.get('count',12))
    lang_key = data.get('language','中文简体')
    if lang_key not in BIP39_LANGUAGE_MAP:
        return jsonify({"error":"不支持的语言"}),400
    strength = ENTROPY_BITS_MAP.get(count,128)
    lang_code = BIP39_LANGUAGE_MAP[lang_key]
    words = generate_bip39_mnemonic(strength, lang_code)
    
    # 添加历史记录（不保存明文助记词，只保存安全信息）
    mnemonic_str = ' '.join(words)  # 或根据语言使用适当的分隔符
    seed = hmac.new(b"mnemonic", mnemonic_str.encode('utf-8'), digestmod=hashlib.sha512).digest()
    seed_hash = hashlib.sha256(seed).hexdigest()
    
    history = MnemonicHistory(
        user_id=session['user_id'],
        language=lang_key,
        word_count=count,
        seed_hash=seed_hash,
        description=data.get('description', '助记词生成于 ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    db.session.add(history)
    db.session.commit()
    
    # 方案2: 如果不使用Redis，可以使用会话存储短期保留
    temp_cache_key = f"mnemonic_cache_{history.id}"
    session[temp_cache_key] = mnemonic_str
    
    # 记录日志
    log_entry = SecurityLog(
        user_id=session['user_id'],
        action="mnemonic_create",
        details=f"创建助记词记录ID: {history.id}"
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return jsonify({"words":words,"count":count,"language":lang_key,"is_bip39":True})

# 验证助记词 API
@app.route('/api/validate_mnemonic', methods=['POST'])
def validate_mnemonic_api():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}),401
    data = request.json or {}
    mn = data.get('mnemonic','')
    lang_key = data.get('language','中文简体')
    if lang_key not in BIP39_LANGUAGE_MAP:
        return jsonify({"error":"不支持的语言"}),400
    lang_code = BIP39_LANGUAGE_MAP[lang_key]
    valid = validate_mnemonic(mn, lang_code)
    if valid:
        seed = binascii.hexlify(MnemonicGenerator.to_seed(mn)).decode()
        wc = len(mn.split(MnemonicGenerator(lang_code).delimiter))
        eb = ENTROPY_BITS_MAP.get(wc,'未知')
        return jsonify({"valid":True,"seed":seed,"word_count":wc,"language":lang_key,"entropy_bits":eb})
    return jsonify({"valid":False,"message":"无效的助记词，请检查拼写和顺序"})

# 获取用户助记词历史记录
@app.route('/api/mnemonic_history')
def get_mnemonic_history():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
        
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 10, type=int), 50)  # 限制最大每页条数
    
    # 查询用户历史记录，按时间倒序
    history_query = MnemonicHistory.query.filter_by(
        user_id=session['user_id']
    ).order_by(MnemonicHistory.created_at.desc())
    
    # 分页
    pagination = history_query.paginate(page=page, per_page=per_page)
    
    # 格式化结果
    history_items = []
    for item in pagination.items:
        history_items.append({
            'id': item.id,
            'language': item.language,
            'word_count': item.word_count,
            'created_at': item.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'description': item.description
        })
    
    return jsonify({
        'history': history_items,
        'pagination': {
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }
    })

# 更新助记词历史描述
@app.route('/api/mnemonic_history/update_description', methods=['POST'])
def update_mnemonic_history_description():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
    
    data = request.json or {}
    history_id = data.get('id')
    description = data.get('description')
    
    if not history_id:
        return jsonify({"success": False, "error": "缺少历史记录ID"}), 400
    
    history = MnemonicHistory.query.filter_by(
        id=history_id,
        user_id=session['user_id']
    ).first()
    
    if not history:
        return jsonify({"success": False, "error": "找不到该历史记录或您无权修改"}), 404
    
    history.description = description
    db.session.commit()
    
    return jsonify({"success": True})



# 更新个人资料API
@app.route('/api/user/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
    
    data = request.json or {}
    username = data.get('username')
    email = data.get('email')
    
    if not username or not email:
        return jsonify({"success": False, "error": "用户名和邮箱为必填项"}), 400
    
    # 获取用户
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"success": False, "error": "用户不存在"}), 404
    
    # 检查用户名是否已被使用(排除当前用户)
    if username != user.username and User.query.filter_by(username=username).first():
        return jsonify({"success": False, "error": "用户名已被使用"}), 409
    
    # 检查邮箱是否已被使用(排除当前用户)
    if email != user.email and User.query.filter_by(email=email).first():
        return jsonify({"success": False, "error": "电子邮箱已被使用"}), 409
    
    # 邮箱格式验证
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "error": "邮箱格式不正确"}), 400
    
    # 更新资料
    user.username = username
    user.email = email
    
    db.session.commit()
    
    # 更新会话中的用户名
    session['username'] = username
    
    return jsonify({"success": True, "username": username})






# 导入必要的模块
from werkzeug.security import generate_password_hash, check_password_hash
import re

# 修改密码API
@app.route('/api/user/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
    
    data = request.json or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({"success": False, "error": "缺少必要参数"}), 400
    
    # 密码长度和复杂度检查
    if len(new_password) < 8:
        return jsonify({"success": False, "error": "密码长度至少为8位"}), 400
    
    if not (any(c.isalpha() for c in new_password) and any(c.isdigit() for c in new_password)):
        return jsonify({"success": False, "error": "密码必须同时包含字母和数字"}), 400
    
    # 获取用户
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"success": False, "error": "用户不存在"}), 404
    
    # 验证当前密码
    if not check_password_hash(user.password_hash, current_password):
        return jsonify({"success": False, "error": "当前密码错误"}), 403
    
    # 更新密码
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    # 如果需要记录操作日志，可以添加以下代码
    # log_entry = SecurityLog(
    #     user_id=session['user_id'],
    #     action="password_change",
    #     details="密码已修改",
    #     ip_address=request.remote_addr
    # )
    # db.session.add(log_entry)
    # db.session.commit()
    
    return jsonify({"success": True})

# 删除助记词历史
@app.route('/api/mnemonic_history/delete', methods=['POST'])
def delete_mnemonic_history():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
    
    data = request.json or {}
    history_id = data.get('id')
    
    if not history_id:
        return jsonify({"success": False, "error": "缺少历史记录ID"}), 400
    
    history = MnemonicHistory.query.filter_by(
        id=history_id,
        user_id=session['user_id']
    ).first()
    
    if not history:
        return jsonify({"success": False, "error": "找不到该历史记录或您无权删除"}), 404
    
    db.session.delete(history)
    db.session.commit()
    
    return jsonify({"success": True})



@app.route('/api/mnemonic_history/get_mnemonic', methods=['POST'])
def get_mnemonic():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}), 401
        
    data = request.json or {}
    history_id = data.get('id')
    
    if not history_id:
        return jsonify({"success": False, "error": "缺少历史记录ID"}), 400
    
    # 查询历史记录
    history = MnemonicHistory.query.filter_by(
        id=history_id,
        user_id=session['user_id']
    ).first()
    
    if not history:
        return jsonify({"success": False, "error": "找不到该历史记录或您无权查看"}), 404
    
    temp_cache_key = f"mnemonic_cache_{history.id}"
    cached_mnemonic = session.get(temp_cache_key)
    
    # 检查生成时间（24小时内）
    time_diff = datetime.datetime.now() - history.created_at
    recent_enough = time_diff.total_seconds() < 43200  # 12小时以内
    
    if cached_mnemonic and recent_enough:
        # 记录安全日志
        log_entry = SecurityLog(
            user_id=session['user_id'],
            action="mnemonic_view",
            details=f"查看助记词历史记录ID: {history.id}",
            ip_address=request.remote_addr  # 记录 IP 地址
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({"success": True, "mnemonic": cached_mnemonic})
    elif not recent_enough:
        return jsonify({
            "success": False, 
            "error": "出于安全考虑，超过24小时的助记词无法查看。请确保您已妥善保存助记词。"
        }), 403
    else:
        return jsonify({
            "success": False, 
            "error": "无法获取助记词。如果您刚刚重新登录，系统会清除临时缓存。请在生成后立即保存您的助记词。"
        }), 404
# 可用语言
@app.route('/api/languages')
def get_languages():
    return jsonify({"languages":list(BIP39_LANGUAGE_MAP.keys())})

# 支持的链
@app.route('/api/supported_chains')
def get_chains():
    return jsonify({"chains":blockchain_utils.SUPPORTED_CHAINS})

# 从助记词派生地址
@app.route('/api/generate_addresses', methods=['POST'])
def generate_addresses_api():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}),401
    data = request.json or {}
    try:
        addrs = blockchain_utils.generate_addresses_from_mnemonic(
            mnemonic=data.get('mnemonic',''),
            passphrase=data.get('passphrase',''),
            chains=data.get('chains',[]),
            account_index=int(data.get('account_index',0)),
            address_count=min(int(data.get('address_count',1)),10),
            language=data.get('language','英文')
        )
        # 移除私钥
        for chain in addrs:
            for a in addrs[chain]:
                a.pop('私钥',None)
        return jsonify({"success":True,"addresses":addrs})
    except Exception as e:
        return jsonify({"success":False,"error":str(e)}),400

# 查询余额与风险
@app.route('/api/query_address', methods=['POST'])
def query_address_api():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}),401
    data = request.json or {}
    chain = data.get('chain','')
    addr  = data.get('address','')
    if not chain or not addr:
        return jsonify({"error":"缺少参数"}),400
    info = blockchain_utils.query_address_balance(chain, addr)
    risk = blockchain_utils.assess_address_risk(chain, addr,
            transaction_count=info.get("交易数量"),
            balance=info.get("余额"))
    return jsonify({"success":True,"address_info":info,"risk_assessment":risk})

# 查询交易记录
@app.route('/api/query_transactions', methods=['POST'])
def query_transactions_api():
    if 'user_id' not in session:
        return jsonify({"error":"未授权访问，请先登录"}),401
    data = request.get_json() or {}
    chain = data.get('chain')
    addr  = data.get('address')
    limit = min(max(int(data.get('limit',10)),1),50)
    txs = blockchain_utils.query_address_transactions(chain, addr, limit)
    if "error" in txs and not txs.get("交易"):
        return jsonify({"success":False,"error":txs["error"]}),404
    return jsonify({"success":True,"transaction_info":txs})

# 初始化数据库 & 启动
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

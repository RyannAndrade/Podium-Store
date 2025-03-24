from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps
import re
from flask_mail import Mail, Message
import cloudinary
import cloudinary.uploader
import cloudinary.api

app = Flask(__name__)
CORS(app)

# Configuração do Cloudinary
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET')
)

# Configuração do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///podium.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sua-chave-secreta-aqui')

# Configuração do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'reachthepodiumbrand@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Configure esta variável de ambiente

db = SQLAlchemy(app)
mail = Mail(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    cpf = db.Column(db.String(14))
    addresses = db.relationship('Address', backref='user', lazy=True)
    payment_methods = db.relationship('PaymentMethod', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    street = db.Column(db.String(200), nullable=False)
    number = db.Column(db.String(20), nullable=False)
    complement = db.Column(db.String(100))
    neighborhood = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(2), nullable=False)
    zip_code = db.Column(db.String(9), nullable=False)
    is_default = db.Column(db.Boolean, default=False)

class PaymentMethod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    card_number = db.Column(db.String(16), nullable=False)
    card_name = db.Column(db.String(100), nullable=False)
    card_expiry = db.Column(db.String(5), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    brand = db.Column(db.String(20))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    subtotal = db.Column(db.Float, nullable=False)
    shipping = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)
    tracking_code = db.Column(db.String(50))
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    size = db.Column(db.String(10), nullable=False)
    color = db.Column(db.String(50), nullable=False)
    image_id = db.Column(db.String(200), nullable=False)

# Decorator para verificar se o usuário está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Validações de formulário
def validar_email(email):
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        flash('E-mail inválido.', 'error')
        return False
    return True

def validar_cpf(cpf):
    if not re.match(r'^\d{3}\.\d{3}\.\d{3}-\d{2}$', cpf):
        flash('CPF inválido.', 'error')
        return False
    return True

def validar_telefone(phone):
    if not re.match(r'^\(\d{2}\) \d{5}-\d{4}$', phone):
        flash('Telefone inválido.', 'error')
        return False
    return True

# Mensagens flash
MENSAGENS = {
    'login_required': 'Por favor, faça login ou crie uma contapara acessar esta página.',
    'login_success': 'Login realizado com sucesso!',
    'login_error': 'E-mail ou senha inválidos.',
    'register_success': 'Conta criada com sucesso! Faça login para continuar.',
    'logout_success': 'Você foi desconectado.',
    'campos_obrigatorios': 'Todos os campos são obrigatórios.',
    'senhas_nao_coincidem': 'As senhas não coincidem.',
    'email_ja_cadastrado': 'Este e-mail já está cadastrado.',
    'cpf_ja_cadastrado': 'Este CPF já está cadastrado.',
    'info_atualizada': 'Informações atualizadas com sucesso!',
    'erro_atualizacao': 'Erro ao atualizar informações.',
    'endereco_adicionado': 'Endereço adicionado com sucesso!',
    'erro_endereco': 'Erro ao adicionar endereço.',
    'cartao_adicionado': 'Cartão adicionado com sucesso!',
    'erro_cartao': 'Erro ao adicionar cartão.',
    'senha_alterada': 'Senha alterada com sucesso!',
    'erro_senha': 'Erro ao alterar senha.',
    'senha_atual_incorreta': 'Senha atual incorreta.',
    'senha_minima': 'A nova senha deve ter pelo menos 8 caracteres.',
    'endereco_excluido': 'Endereço excluído com sucesso!',
    'erro_excluir_endereco': 'Erro ao excluir endereço.',
    'cartao_excluido': 'Cartão excluído com sucesso!',
    'erro_excluir_cartao': 'Erro ao excluir cartão.',
    'acesso_negado': 'Acesso negado.'
}

# Lista de produtos
PRODUTOS = [
    {
        'id': 1,
        'name': 'EFFORT BLACK TEE',
        'price': 125.00,
        'image': 'https://i.postimg.cc/kgNkDfjV/8edc1933-3f5f-4180-a4cf-78e13c4dee6d.jpg',
        'description': 'Camiseta preta com estampa minimalista EFFORT. Feita com 100% algodão com tecido de alta qualidade.',
        'category': 'camisetas'
    },
    {
        'id': 2,
        'name': 'EFFORT WHITE TEE',
        'price': 125.00,
        'image': 'https://i.postimg.cc/bJvX7k9Z/90ec3019-2a08-459a-a446-d1f1027a6852.jpg',
        'description': 'Camiseta branca com estampa minimalista EFFORT. Feita com 100% algodão com tecido de alta qualidade.',
        'category': 'camisetas'
    }
]

# Imagens do Lookbook
LOOKBOOK_IMAGES = [
    {
        'url': 'https://i.postimg.cc/g2qRvqWL/256da6bb-fe38-4a80-b7dd-13eaa13fc257.jpg',
        'description': 'Modelo vestindo EFFORT BLACK TEE'
    },
    {
        'url': 'https://i.postimg.cc/yxS68kkV/2ef19bf9-e0ff-471b-81e4-ec7323074fd9.jpg',
        'description': 'Modelo vestindo EFFORT BLACK TEE'
    },
    {
        'url': 'https://i.postimg.cc/cJXLDppN/2f139d6c-4644-4a61-a50a-6c0f26d1ff98.jpg',
        'description': 'Modelo vestindo EFFORT WHITE TEE'
    },
    {
        'url': 'https://i.postimg.cc/ryd5rj4p/344a5f03-f4c4-4d4a-aae7-32c77d4f0d97.jpg',
        'description': 'Detalhe da estampa EFFORT'
    },
    {
        'url': 'https://i.postimg.cc/mhfLzBH7/6fb9b415-3169-406a-aa7b-3eaa729a87b8.jpg',
        'description': 'Modelo vestindo EFFORT BLACK TEE'
    },
    {
        'url': 'https://i.postimg.cc/MTLKwyZP/f77af150-d71c-4ade-b074-142f6065a933.jpg',
        'description': 'Modelo vestindo EFFORT WHITE TEE'
    },
    {
        'url': 'https://i.postimg.cc/Z5rqtBdZ/0d5679c5-b87c-4137-928e-5ce84970b100.jpg',
        'description': 'Detalhe da estampa EFFORT'
    },
    {
        'url': 'https://i.postimg.cc/CKSxFhG8/1b1690a2-21b3-4142-bfc6-bfdc72391951.jpg',
        'description': 'Modelo vestindo EFFORT BLACK TEE'
    },
    {
        'url': 'https://i.postimg.cc/28Dg62cs/604bd935-0083-4629-b7f3-e4c46a4966e3.jpg',
        'description': 'Modelo vestindo EFFORT WHITE TEE'
    },
    {
        'url': 'https://i.postimg.cc/WprQTQnm/76fc8600-605b-4170-b596-093a749c4de7.jpg',
        'description': 'Detalhe da estampa EFFORT'
    },
    {
        'url': 'https://i.postimg.cc/cJbVLW2h/8e613f94-8cb6-476e-ab7f-d66dc042125c.jpg',
        'description': 'Modelo vestindo EFFORT BLACK TEE'
    },
    {
        'url': 'https://i.postimg.cc/NFhSR4gr/a45bd4af-05b5-4310-9b24-b680c997c316.jpg',
        'description': 'Modelo vestindo EFFORT WHITE TEE'
    }
]

# Rota para a página inicial
@app.route('/')
def index():
    return render_template('index.html', products=PRODUTOS)

# Rota para a página de contato
@app.route('/contato')
def contact():
    return render_template('contact.html')

# Rota para a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember-me') == 'on'

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            if remember:
                session.permanent = True
            flash(MENSAGENS['login_success'], 'success')
            return redirect(url_for('profile'))
        
        flash(MENSAGENS['login_error'], 'error')
    
    return render_template('login.html')

# Rota para a página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        cpf = request.form.get('cpf')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([first_name, last_name, email, cpf, phone, password, confirm_password]):
            flash(MENSAGENS['campos_obrigatorios'], 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash(MENSAGENS['senhas_nao_coincidem'], 'error')
            return redirect(url_for('register'))

        if not validar_email(email) or not validar_cpf(cpf) or not validar_telefone(phone):
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash(MENSAGENS['email_ja_cadastrado'], 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(cpf=cpf).first():
            flash(MENSAGENS['cpf_ja_cadastrado'], 'error')
            return redirect(url_for('register'))

        user = User(
            name=f"{first_name} {last_name}",
            email=email,
            cpf=cpf,
            phone=phone
        )
        user.password = generate_password_hash(password)

        db.session.add(user)
        db.session.commit()

        flash(MENSAGENS['register_success'], 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Rota para logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash(MENSAGENS['logout_success'], 'success')
    return redirect(url_for('login'))

# Rota para a página de perfil
@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    addresses = Address.query.filter_by(user_id=user.id).all()
    cards = PaymentMethod.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, addresses=addresses, cards=cards)

# Rota para editar informações do perfil
@app.route('/perfil/editar', methods=['POST'])
@login_required
def editar_perfil():
    user = User.query.get(session['user_id'])
    
    # Validar e atualizar informações
    first_name = request.form.get('first-name')
    last_name = request.form.get('last-name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    if not all([first_name, last_name, email, phone]):
        flash(MENSAGENS['campos_obrigatorios'], 'error')
        return redirect(url_for('perfil'))
    
    # Validar formato do email
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash('Email inválido.', 'error')
        return redirect(url_for('perfil'))
    
    # Validar formato do telefone
    phone = re.sub(r'\D', '', phone)
    if len(phone) != 11:
        flash('Telefone inválido.', 'error')
        return redirect(url_for('perfil'))
    
    # Verificar se o email já está em uso por outro usuário
    if email != user.email and User.query.filter_by(email=email).first():
        flash('Este email já está em uso.', 'error')
        return redirect(url_for('perfil'))
    
    # Atualizar informações
    user.name = f"{first_name} {last_name}"
    user.email = email
    user.phone = phone
    try:
        db.session.commit()
        flash(MENSAGENS['info_atualizada'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_atualizacao'], 'error')
    
    return redirect(url_for('perfil'))

# Rota para adicionar endereço
@app.route('/perfil/enderecos/adicionar', methods=['POST'])
@login_required
def adicionar_endereco():
    user = User.query.get(session['user_id'])
    
    # Validar e processar dados do endereço
    street = request.form.get('street')
    number = request.form.get('number')
    complement = request.form.get('complement')
    neighborhood = request.form.get('neighborhood')
    zip_code = request.form.get('zip-code')
    city = request.form.get('city')
    state = request.form.get('state')
    
    if not all([street, number, neighborhood, zip_code, city, state]):
        flash(MENSAGENS['campos_obrigatorios'], 'error')
        return redirect(url_for('perfil'))
    
    # Validar formato do CEP
    zip_code = re.sub(r'\D', '', zip_code)
    if len(zip_code) != 8:
        flash('CEP inválido.', 'error')
        return redirect(url_for('perfil'))
    
    # Criar novo endereço
    new_address = Address(
        user_id=user.id,
        type="Residencial",
        name=f"{user.name} - {neighborhood}",
        street=street,
        number=number,
        complement=complement,
        neighborhood=neighborhood,
        city=city,
        state=state,
        zip_code=zip_code,
        is_default=False
    )
    
    try:
        db.session.add(new_address)
        db.session.commit()
        flash(MENSAGENS['endereco_adicionado'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_endereco'], 'error')
    
    return redirect(url_for('perfil'))

# Rota para adicionar cartão
@app.route('/perfil/cartoes/adicionar', methods=['POST'])
@login_required
def adicionar_cartao():
    user = User.query.get(session['user_id'])
    
    # Validar e processar dados do cartão
    card_number = request.form.get('card-number')
    card_name = request.form.get('card-name')
    card_expiry = request.form.get('card-expiry')
    card_cvv = request.form.get('card-cvv')
    
    if not all([card_number, card_name, card_expiry, card_cvv]):
        flash(MENSAGENS['campos_obrigatorios'], 'error')
        return redirect(url_for('perfil'))
    
    # Validar número do cartão
    card_number = re.sub(r'\D', '', card_number)
    if len(card_number) != 16:
        flash('Número do cartão inválido.', 'error')
        return redirect(url_for('perfil'))
    
    # Validar validade do cartão
    if not re.match(r'^(0[1-9]|1[0-2])/([0-9]{2})$', card_expiry):
        flash('Data de validade inválida.', 'error')
        return redirect(url_for('perfil'))
    
    # Validar CVV
    card_cvv = re.sub(r'\D', '', card_cvv)
    if len(card_cvv) not in [3, 4]:
        flash('CVV inválido.', 'error')
        return redirect(url_for('perfil'))
    
    # Criar novo cartão
    new_card = PaymentMethod(
        user_id=user.id,
        type="Cartão de Crédito",
        card_number=card_number,
        card_name=card_name,
        card_expiry=card_expiry,
        is_default=False,
        brand="Outro"
    )
    
    try:
        db.session.add(new_card)
        db.session.commit()
        flash(MENSAGENS['cartao_adicionado'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_cartao'], 'error')
    
    return redirect(url_for('perfil'))

# Rota para alterar senha
@app.route('/perfil/senha/alterar', methods=['POST'])
@login_required
def alterar_senha():
    user = User.query.get(session['user_id'])
    
    current_password = request.form.get('current-password')
    new_password = request.form.get('new-password')
    confirm_password = request.form.get('confirm-password')
    
    if not all([current_password, new_password, confirm_password]):
        flash(MENSAGENS['campos_obrigatorios'], 'error')
        return redirect(url_for('perfil'))
    
    # Verificar senha atual
    if not check_password_hash(user.password, current_password):
        flash(MENSAGENS['senha_atual_incorreta'], 'error')
        return redirect(url_for('perfil'))
    
    # Verificar se as novas senhas coincidem
    if new_password != confirm_password:
        flash(MENSAGENS['senhas_nao_coincidem'], 'error')
        return redirect(url_for('perfil'))
    
    # Validar força da senha
    if len(new_password) < 8:
        flash(MENSAGENS['senha_minima'], 'error')
        return redirect(url_for('perfil'))
    
    # Atualizar senha
    user.password = generate_password_hash(new_password)
    
    try:
        db.session.commit()
        flash(MENSAGENS['senha_alterada'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_senha'], 'error')
    
    return redirect(url_for('perfil'))

# Rota para excluir endereço
@app.route('/perfil/enderecos/<int:address_id>/excluir', methods=['POST'])
@login_required
def excluir_endereco(address_id):
    address = Address.query.get_or_404(address_id)
    
    # Verificar se o endereço pertence ao usuário
    if address.user_id != session['user_id']:
        flash(MENSAGENS['acesso_negado'], 'error')
        return redirect(url_for('perfil'))
    
    try:
        db.session.delete(address)
        db.session.commit()
        flash(MENSAGENS['endereco_excluido'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_excluir_endereco'], 'error')
    
    return redirect(url_for('perfil'))

# Rota para excluir cartão
@app.route('/perfil/cartoes/<int:card_id>/excluir', methods=['POST'])
@login_required
def excluir_cartao(card_id):
    card = PaymentMethod.query.get_or_404(card_id)
    
    # Verificar se o cartão pertence ao usuário
    if card.user_id != session['user_id']:
        flash(MENSAGENS['acesso_negado'], 'error')
        return redirect(url_for('perfil'))
    
    try:
        db.session.delete(card)
        db.session.commit()
        flash(MENSAGENS['cartao_excluido'], 'success')
    except Exception as e:
        db.session.rollback()
        flash(MENSAGENS['erro_excluir_cartao'], 'error')
    
    return redirect(url_for('perfil'))

# Rotas de Autenticação
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email já cadastrado'}), 400
    
    user = User(
        name=data['name'],
        email=data['email'],
        password=generate_password_hash(data['password']),
        phone=data.get('phone'),
        cpf=data.get('cpf')
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Usuário cadastrado com sucesso'}), 201

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Email ou senha inválidos'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    })

# Rotas de Usuário
@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'cpf': user.cpf
        })
    except:
        return jsonify({'error': 'Token inválido'}), 401

@app.route('/api/user/profile', methods=['PUT'])
def update_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        update_data = request.get_json()
        
        if 'name' in update_data:
            user.name = update_data['name']
        if 'phone' in update_data:
            user.phone = update_data['phone']
        if 'cpf' in update_data:
            user.cpf = update_data['cpf']
        
        db.session.commit()
        return jsonify({'message': 'Perfil atualizado com sucesso'})
    except:
        return jsonify({'error': 'Token inválido'}), 401

# Rotas de Endereços
@app.route('/api/addresses', methods=['GET'])
def get_addresses():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        addresses = [{
            'id': addr.id,
            'type': addr.type,
            'name': addr.name,
            'street': addr.street,
            'number': addr.number,
            'complement': addr.complement,
            'neighborhood': addr.neighborhood,
            'city': addr.city,
            'state': addr.state,
            'zip_code': addr.zip_code,
            'is_default': addr.is_default
        } for addr in user.addresses]
        
        return jsonify(addresses)
    except:
        return jsonify({'error': 'Token inválido'}), 401

@app.route('/api/addresses', methods=['POST'])
def create_address():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        address_data = request.get_json()
        
        address = Address(
            user_id=user.id,
            type=address_data['type'],
            name=address_data['name'],
            street=address_data['street'],
            number=address_data['number'],
            complement=address_data.get('complement'),
            neighborhood=address_data['neighborhood'],
            city=address_data['city'],
            state=address_data['state'],
            zip_code=address_data['zip_code'],
            is_default=address_data.get('is_default', False)
        )
        
        db.session.add(address)
        db.session.commit()
        
        return jsonify({'message': 'Endereço cadastrado com sucesso'}), 201
    except:
        return jsonify({'error': 'Token inválido'}), 401

# Rotas de Formas de Pagamento
@app.route('/api/payment-methods', methods=['GET'])
def get_payment_methods():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        payment_methods = [{
            'id': pm.id,
            'type': pm.type,
            'card_number': pm.card_number[-4:],
            'card_name': pm.card_name,
            'card_expiry': pm.card_expiry,
            'is_default': pm.is_default,
            'brand': pm.brand
        } for pm in user.payment_methods]
        
        return jsonify(payment_methods)
    except:
        return jsonify({'error': 'Token inválido'}), 401

@app.route('/api/payment-methods', methods=['POST'])
def create_payment_method():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        payment_data = request.get_json()
        
        payment_method = PaymentMethod(
            user_id=user.id,
            type=payment_data['type'],
            card_number=payment_data['card_number'],
            card_name=payment_data['card_name'],
            card_expiry=payment_data['card_expiry'],
            is_default=payment_data.get('is_default', False),
            brand=payment_data.get('brand', 'other')
        )
        
        db.session.add(payment_method)
        db.session.commit()
        
        return jsonify({'message': 'Forma de pagamento cadastrada com sucesso'}), 201
    except:
        return jsonify({'error': 'Token inválido'}), 401

# Rotas de Pedidos
@app.route('/api/orders', methods=['GET'])
def get_orders():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        
        orders = [{
            'id': order.id,
            'date': order.date.strftime('%d/%m/%Y'),
            'status': order.status,
            'subtotal': order.subtotal,
            'shipping': order.shipping,
            'total': order.total,
            'tracking_code': order.tracking_code,
            'items': [{
                'id': item.id,
                'name': item.name,
                'price': item.price,
                'quantity': item.quantity,
                'size': item.size,
                'color': item.color,
                'image': item.image
            } for item in order.items]
        } for order in user.orders]
        
        return jsonify(orders)
    except:
        return jsonify({'error': 'Token inválido'}), 401

@app.route('/api/orders', methods=['POST'])
def create_order():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        order_data = request.get_json()
        
        order = Order(
            user_id=user.id,
            status='pending',
            subtotal=order_data['subtotal'],
            shipping=order_data['shipping'],
            total=order_data['total']
        )
        
        db.session.add(order)
        db.session.commit()
        
        for item in order_data['items']:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item['product_id'],
                name=item['name'],
                price=item['price'],
                quantity=item['quantity'],
                size=item['size'],
                color=item['color'],
                image=item['image']
            )
            db.session.add(order_item)
        
        db.session.commit()
        
        return jsonify({'message': 'Pedido criado com sucesso', 'order_id': order.id}), 201
    except:
        return jsonify({'error': 'Token inválido'}), 401

# Rota de Segurança
@app.route('/api/user/security', methods=['PUT'])
def update_security():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token não fornecido'}), 401
    
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        security_data = request.get_json()
        
        if 'current_password' in security_data and 'new_password' in security_data:
            if not check_password_hash(user.password, security_data['current_password']):
                return jsonify({'error': 'Senha atual incorreta'}), 400
            
            user.password = generate_password_hash(security_data['new_password'])
        
        db.session.commit()
        return jsonify({'message': 'Configurações de segurança atualizadas com sucesso'})
    except:
        return jsonify({'error': 'Token inválido'}), 401

# Rota para o catálogo
@app.route('/catalog')
def catalog():
    categoria = request.args.get('categoria')
    if categoria:
        produtos_filtrados = [p for p in PRODUTOS if p['category'] == categoria]
    else:
        produtos_filtrados = PRODUTOS
    return render_template('catalog.html', products=produtos_filtrados)

# Rota para o lookbook
@app.route('/lookbook')
def lookbook():
    return render_template('lookbook.html', images=LOOKBOOK_IMAGES)

# Rota para a página do produto
@app.route('/product/<int:product_id>')
def product(product_id):
    product = next((p for p in PRODUTOS if p['id'] == product_id), None)
    if product is None:
        return redirect(url_for('catalog'))
    return render_template('product.html', product=product)

# Rota para envio de e-mail
@app.route('/api/contact', methods=['POST'])
def send_contact_email():
    data = request.get_json()
    
    try:
        msg = Message(
            subject=f'Contato via Site - {data["subject"]}',
            sender=data['email'],
            recipients=['reachthepodiumbrand@gmail.com'],
            body=f'''
Nome: {data['name']}
E-mail: {data['email']}
Assunto: {data['subject']}

Mensagem:
{data['message']}
            '''
        )
        mail.send(msg)
        return jsonify({'message': 'E-mail enviado com sucesso!'}), 200
    except Exception as e:
        return jsonify({'error': 'Erro ao enviar e-mail'}), 500

# Rota para o carrinho
@app.route('/carrinho')
def cart():
    return render_template('cart.html')

@app.route('/new-in')
def new_in():
    return render_template('new_in.html', products=PRODUTOS)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 
    
 
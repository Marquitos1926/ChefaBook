from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, send_from_directory
import bcrypt
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from functools import wraps
from pymongo import MongoClient
from gridfs import GridFS
from bson.objectid import ObjectId
import re

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY') or 'sua-chave-secreta-aqui'

# Configurações
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MONGO_URI'] = os.environ.get('MONGO_URI') or 'mongodb+srv://juliocardoso:ttAJxnWdq6VteFCD@cluster0.fynj6mg.mongodb.net/chefabook?retryWrites=true&w=majority&appName=Cluster0'

# Conexão com MongoDB
client = MongoClient(app.config['MONGO_URI'])
db = client.get_database('chefabook')
fs = GridFS(db)
usuarios_col = db['usuarios']
receitas_col = db['receitas']
feedbacks_col = db['feedbacks']

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Por favor, faça login para acessar esta página.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('user_admin'):
            flash("Acesso restrito a administradores.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Credenciais do Administrador
ADMIN_CREDENTIALS = {
    "email": "admin@email.com",
    "password": "senha123"
}

# Funções auxiliares
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validar_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def validar_telefone(telefone):
    telefone_limpo = re.sub(r'\D', '', telefone)
    return len(telefone_limpo) >= 10 and len(telefone_limpo) <= 11

# Rotas principais
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('user_id') == "admin":
        return redirect(url_for('painel_admin'))
    return render_template('dashboard.html')

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '').strip()

        if email == ADMIN_CREDENTIALS["email"]:
            flash("Use a página de login administrativo", "info")
            return redirect(url_for('login_admin'))

        if not email or not validar_email(email):
            flash("Por favor, insira um e-mail válido", "error")
            return render_template('login.html')
        
        if not senha:
            flash("Por favor, insira sua senha", "error")
            return render_template('login.html')

        try:
            usuario = usuarios_col.find_one({'email': email})
            
            if not usuario:
                flash("E-mail não encontrado. Verifique ou cadastre-se.", "error")
            else:
                if bcrypt.checkpw(senha.encode('utf-8'), usuario['senha']):
                    session['user_id'] = str(usuario['_id'])
                    session['user_nome'] = usuario['nome']
                    session['user_admin'] = False
                    session['last_login'] = datetime.now().strftime("%d/%m/%Y %H:%M")
                    flash("Login realizado com sucesso!", "success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("Senha incorreta. Tente novamente.", "error")
                
        except Exception as e:
            flash(f"Erro no login: {str(e)}", "error")
    
    return render_template('login.html')

@app.route("/login_admin", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        

        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            session['user_id'] = "admin"  # ID especial para admin
            session['user_admin'] = True
            session['user_nome'] = "Administrador"
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))
        
        flash("Credenciais inválidas!", "error")
        return redirect(url_for("login_admin"))

    return render_template("login_admin.html")

@app.route('/logout')
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "success")
    return redirect(url_for('login'))

# Painel Admin
@app.route("/painel_admin")
@admin_required
def painel_admin():
    try:
        # Estatísticas
        total_usuarios = usuarios_col.count_documents({})
        total_receitas = receitas_col.count_documents({})
        total_feedbacks = feedbacks_col.count_documents({})
        feedbacks_nao_lidos = feedbacks_col.count_documents({'lido': False})
        
        # Últimos usuários cadastrados
        usuarios = list(usuarios_col.find().sort("data_cadastro", -1).limit(10))
        
        # Últimas receitas cadastradas com informações do usuário
        receitas_com_usuario = []
        for receita in receitas_col.find().sort("data_cadastro", -1).limit(10):
            usuario = usuarios_col.find_one(
                {'_id': ObjectId(receita['user_id'])},
                {'nome': 1, 'email': 1}
            ) if 'user_id' in receita else None
            
            receitas_com_usuario.append({
                '_id': receita['_id'],
                'titulo': receita.get('titulo', 'Sem título'),
                'categoria': receita.get('categoria', 'Sem categoria'),
                'usuario_nome': usuario['nome'] if usuario else 'Usuário não encontrado',
                'usuario_email': usuario['email'] if usuario else 'N/A',
                'data_cadastro': receita.get('data_cadastro', datetime.now())
            })

        # Últimos feedbacks recebidos
        feedbacks = list(feedbacks_col.find().sort("data", -1).limit(10))

        return render_template(
            "painel_admin.html",
            usuarios=usuarios,
            receitas=receitas_com_usuario,
            feedbacks=feedbacks,
            total_usuarios=total_usuarios,
            total_receitas=total_receitas,
            total_feedbacks=total_feedbacks,
            feedbacks_nao_lidos=feedbacks_nao_lidos
        )
        
    except Exception as e:
        flash(f"Erro ao acessar painel administrativo: {str(e)}", "error")
        return redirect(url_for("login_admin"))


# Rotas de usuários
@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if request.method == 'POST':
        try:
            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip().lower()
            telefone = request.form.get('telefone', '').strip()
            senha = request.form.get('senha', '').strip()
            confirmar_senha = request.form.get('confirmar_senha', '').strip()

            if not nome or not re.match(r'^[a-zA-ZÀ-ÿ\s\'-]+$', nome):
                flash("Nome inválido. Deve conter apenas letras e espaços", "error")
                return render_template('cadastrar_usuario.html')

            if not email or not validar_email(email):
                flash("Por favor, insira um e-mail válido.", "error")
                return render_template('cadastrar_usuario.html')

            if not validar_telefone(telefone):
                flash("Telefone inválido. Insira DDD + número (10 ou 11 dígitos).", "error")
                return render_template('cadastrar_usuario.html')

            telefone_limpo = re.sub(r'\D', '', telefone)
            if usuarios_col.find_one({'telefone': telefone_limpo}):
                flash("Este telefone já está cadastrado.", "error")
                return render_template('cadastrar_usuario.html')

            if len(senha) < 6:
                flash("A senha deve ter pelo menos 6 caracteres", "error")
                return render_template('cadastrar_usuario.html')

            if senha != confirmar_senha:
                flash("As senhas não coincidem.", "error")
                return render_template('cadastrar_usuario.html')

            if usuarios_col.find_one({'email': email}):
                flash("Este e-mail já está cadastrado.", "error")
                return render_template('cadastrar_usuario.html')

            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

            usuario = {
                'nome': nome,
                'email': email,
                'telefone': telefone_limpo,
                'senha': hashed_senha,
                'admin': False,
                'data_cadastro': datetime.now(),
                'ativo': True
            }
            
            usuarios_col.insert_one(usuario)
            flash("Cadastro realizado com sucesso! Faça login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Erro no cadastro: {str(e)}", "error")
            return render_template('cadastrar_usuario.html')

    return render_template('cadastrar_usuario.html')


# Rotas de receitas
@app.route('/cadastrar_receita', methods=['GET', 'POST'])
@login_required
def cadastrar_receita():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        categoria = request.form.get('categoria', '').strip()
        ingredientes = request.form.get('ingredientes', '').strip()
        preparo = request.form.get('preparo', '').strip()
        user_id = session['user_id']
        
        if not titulo or not categoria or not ingredientes or not preparo:
            flash("Todos os campos textuais são obrigatórios", "error")
            return redirect(request.url)
        
        imagem_id = None
        file = request.files.get('imagem')
        
        # Processa a imagem apenas se foi enviada
        if file and file.filename != '':
            if allowed_file(file.filename):
                try:
                    imagem_id = fs.put(file, filename=secure_filename(file.filename))
                except Exception as e:
                    flash(f"Erro ao processar imagem: {str(e)}", "error")
                    return redirect(request.url)
            else:
                flash("Tipo de arquivo não permitido. Use PNG, JPG ou JPEG.", "error")
                return redirect(request.url)
        
        # Cria a receita com ou sem imagem
        try:
            receita = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo,
                'user_id': user_id,
                'data_cadastro': datetime.now()
            }
            
            if imagem_id:
                receita['imagem_id'] = imagem_id
                
            receitas_col.insert_one(receita)
            
            flash("Receita cadastrada com sucesso!", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f"Erro ao cadastrar receita: {str(e)}", "error")

    return render_template('cadastrar_receitas.html')

@app.route('/visualizar_receitas')
@login_required
def visualizar_receitas():
    try:
        receitas = []
        for receita in receitas_col.find({'user_id': session['user_id']}):
            receitas.append({
                'id': str(receita['_id']),
                'titulo': receita['titulo'],
                'categoria': receita['categoria'],
                'ingredientes': receita['ingredientes'],
                'preparo': receita['preparo'],
                'user_id': receita['user_id'],
                'tem_imagem': 'imagem_id' in receita
            })

        return render_template('visualizar_receitas.html', receitas=receitas)
        
    except Exception as e:
        flash(f"Erro ao carregar receitas: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/imagem_receita/<receita_id>')
@login_required
def imagem_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if receita and 'imagem_id' in receita:
            imagem = fs.get(receita['imagem_id'])
            response = make_response(imagem.read())
            response.headers.set('Content-Type', 'image/jpeg')
            return response
        
    except Exception as e:
        print(f"Erro ao carregar imagem: {str(e)}")
    
    return send_from_directory(app.static_folder, 'images/sem-imagem.jpg')

@app.route('/editar_receita/<receita_id>', methods=['GET', 'POST'])
@login_required
def editar_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para editá-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            categoria = request.form.get('categoria', '').strip()
            ingredientes = request.form.get('ingredientes', '').strip()
            preparo = request.form.get('preparo', '').strip()
            
            update_data = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo
            }
            
            if 'imagem' in request.files:
                file = request.files['imagem']
                if file and file.filename != '' and allowed_file(file.filename):
                    if 'imagem_id' in receita:
                        fs.delete(receita['imagem_id'])
                    update_data['imagem_id'] = fs.put(file, filename=secure_filename(file.filename))

            receitas_col.update_one(
                {'_id': ObjectId(receita_id)},
                {'$set': update_data}
            )
            
            flash("Receita atualizada com sucesso!", "success")
            return redirect(url_for('visualizar_receitas'))
        
        return render_template('editar_receita.html', receita=receita)
        
    except Exception as e:
        flash(f"Erro ao editar receita: {e}", "error")
        return redirect(url_for('visualizar_receitas'))

@app.route('/excluir_receita/<receita_id>', methods=['POST'])
@login_required
def excluir_receita(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id), 'user_id': session['user_id']})
        
        if not receita:
            flash("Receita não encontrada ou você não tem permissão para excluí-la", "error")
            return redirect(url_for('visualizar_receitas'))
        
        if 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso!", "success")
        
    except Exception as e:
        flash(f"Erro ao excluir receita: {e}", "error")
    
    return redirect(url_for('visualizar_receitas'))

# Admin - Gerenciamento de Usuários
@app.route("/editar_usuario_admin/<usuario_id>", methods=["GET", "POST"])
@admin_required
def editar_usuario_admin(usuario_id):
    try:
        usuario = usuarios_col.find_one({'_id': ObjectId(usuario_id)})
        
        if not usuario:
            flash("Usuário não encontrado.", "error")
            return redirect(url_for("painel_admin"))

        if request.method == "POST":
            nome = request.form.get("nome", "").strip()
            email = request.form.get("email", "").strip().lower()
            telefone = request.form.get("telefone", "").strip()

            if not nome or not email:
                flash("Nome e e-mail são obrigatórios.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            if not validar_email(email):
                flash("E-mail inválido.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            if not validar_telefone(telefone):
                flash("Telefone inválido.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            telefone_limpo = re.sub(r'\D', '', telefone)

            if usuarios_col.find_one({'email': email, '_id': {'$ne': ObjectId(usuario_id)}}):
                flash("Este e-mail já está em uso.", "error")
                return redirect(url_for("editar_usuario_admin", usuario_id=usuario_id))

            update_data = {
                'nome': nome,
                'email': email,
                'telefone': telefone_limpo,
                'data_atualizacao': datetime.now()
            }

            usuarios_col.update_one(
                {'_id': ObjectId(usuario_id)},
                {'$set': update_data}
            )

            flash("Usuário atualizado com sucesso!", "success")
            return redirect(url_for("painel_admin"))

        return render_template("editar_usuario_admin.html", usuario=usuario)
        
    except Exception as e:
        flash(f"Erro ao editar usuário: {str(e)}", "error")
        return redirect(url_for("painel_admin"))

@app.route("/excluir_usuario/<usuario_id>", methods=["POST"])
@admin_required
def excluir_usuario(usuario_id):
    try:
        # Excluir receitas do usuário
        receitas_col.delete_many({'user_id': usuario_id})
        
        # Excluir usuário
        usuarios_col.delete_one({'_id': ObjectId(usuario_id)})
        
        flash("Usuário e suas receitas foram excluídos.", "success")
    except Exception as e:
        flash(f"Erro ao excluir usuário: {str(e)}", "error")
    
    return redirect(url_for("painel_admin"))

# Admin - Gerenciamento de Receitas
@app.route("/editar_receita_admin/<receita_id>", methods=["GET", "POST"])
@admin_required
def editar_receita_admin(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id)})
        
        if not receita:
            flash("Receita não encontrada.", "error")
            return redirect(url_for("painel_admin"))

        usuario = usuarios_col.find_one(
            {'_id': ObjectId(receita['user_id'])},
            {'nome': 1, 'email': 1}
        ) if 'user_id' in receita else None

        if request.method == "POST":
            titulo = request.form.get("titulo", "").strip()
            categoria = request.form.get("categoria", "").strip()
            ingredientes = request.form.get("ingredientes", "").strip()
            preparo = request.form.get("preparo", "").strip()

            if not titulo or not categoria or not ingredientes or not preparo:
                flash("Todos os campos são obrigatórios.", "error")
                return redirect(url_for("editar_receita_admin", receita_id=receita_id))

            update_data = {
                'titulo': titulo,
                'categoria': categoria,
                'ingredientes': ingredientes,
                'preparo': preparo,
                'data_atualizacao': datetime.now()
            }

            if 'imagem' in request.files:
                file = request.files['imagem']
                if file and file.filename != '' and allowed_file(file.filename):
                    if 'imagem_id' in receita:
                        fs.delete(receita['imagem_id'])
                    update_data['imagem_id'] = fs.put(file, filename=secure_filename(file.filename))

            receitas_col.update_one(
                {'_id': ObjectId(receita_id)},
                {'$set': update_data}
            )

            flash("Receita atualizada com sucesso!", "success")
            return redirect(url_for("painel_admin"))

        return render_template(
            "editar_receita_admin.html",
            receita=receita,
            usuario_nome=usuario['nome'] if usuario else 'Usuário não encontrado'
        )
        
    except Exception as e:
        flash(f"Erro ao editar receita: {str(e)}", "error")
        return redirect(url_for("painel_admin"))

@app.route("/excluir_receita_admin/<receita_id>", methods=["POST"])
@admin_required
def excluir_receita_admin(receita_id):
    try:
        receita = receitas_col.find_one({'_id': ObjectId(receita_id)})
        
        if receita and 'imagem_id' in receita:
            fs.delete(receita['imagem_id'])
            
        receitas_col.delete_one({'_id': ObjectId(receita_id)})
        flash("Receita excluída com sucesso.", "success")
    except Exception as e:
        flash(f"Erro ao excluir receita: {str(e)}", "error")
    
    return redirect(url_for("painel_admin"))




















































@app.route('/enviar_feedback', methods=['GET', 'POST'])
@login_required
def enviar_feedback():
    if request.method == 'POST':
        try:
            # Obter dados do formulário
            tipo = request.form.get('tipo', '').strip()
            mensagem = request.form.get('mensagem', '').strip()
            avaliacao = int(request.form.get('avaliacao', 0))
            
            # Validação básica
            if not mensagem or len(mensagem) < 10:
                flash("Por favor, escreva uma mensagem mais detalhada (mínimo 10 caracteres)", "error")
                return redirect(url_for('enviar_feedback'))
            
            if avaliacao < 1 or avaliacao > 5:
                flash("Por favor, selecione uma avaliação entre 1 e 5 estrelas", "error")
                return redirect(url_for('enviar_feedback'))
            
            # Criar documento do feedback
            feedback = {
                'user_id': session['user_id'],
                'user_nome': session['user_nome'],
                'tipo': tipo,
                'mensagem': mensagem,
                'avaliacao': avaliacao,
                'data': datetime.now(),
                'lido': False
            }
            
            # Inserir no MongoDB
            feedbacks_col.insert_one(feedback)
            
            flash("Obrigado pelo seu feedback! Valorizamos sua opinião.", "success")
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f"Erro ao enviar feedback: {str(e)}", "error")
            return redirect(url_for('enviar_feedback'))
    
    # Se for GET, mostrar o formulário
    return render_template('enviar_feedback.html')




@app.route('/admin/feedbacks')
@admin_required
def visualizar_feedbacks():
    try:
        # Obter todos os feedbacks, ordenados por data (mais recentes primeiro)
        feedbacks = list(feedbacks_col.find().sort("data", -1))
        
        return render_template('painel_admin.html', 
                           feedbacks=feedbacks,
                           total_feedbacks=feedbacks_col.count_documents({}),
                           feedbacks_nao_lidos=feedbacks_col.count_documents({'lido': False}))
        
    except Exception as e:
        flash(f"Erro ao carregar feedbacks: {str(e)}", "error")
        return redirect(url_for('painel_admin'))






@app.route('/admin/marcar_lido/<feedback_id>', methods=['POST'])
@admin_required
def marcar_feedback_lido(feedback_id):
    try:
        feedbacks_col.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$set': {'lido': True}}
        )
        flash("Feedback marcado como lido", "success")
    except Exception as e:
        flash(f"Erro ao atualizar feedback: {str(e)}", "error")
    
    return redirect(url_for('painel_admin'))





# Rotas de erro
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
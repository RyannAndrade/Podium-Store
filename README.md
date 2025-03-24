# Podium - Sistema de Gerenciamento de Perfil

Sistema para gerenciamento de perfil de usuário com suporte a múltiplos endereços e formas de pagamento.

## Requisitos

- Python 3.8 ou superior
- PostgreSQL (opcional, pode usar SQLite)

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/sufgang.git
cd podium
```

2. Crie e ative um ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente:
Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:
```
SECRET_KEY=sua_chave_secreta_aqui
DATABASE_URL=sqlite:///podium.db  # ou sua URL do PostgreSQL
```

5. Inicialize o banco de dados:
```bash
python init_db.py
```

## Uso

1. Inicie o servidor:
```bash
python app.py
```

2. Acesse o sistema em seu navegador:
```
http://localhost:5000
```

## Funcionalidades

- Gerenciamento de informações pessoais
- Cadastro e gerenciamento de múltiplos endereços
- Cadastro e gerenciamento de cartões de crédito/débito
- Alteração de senha
- Interface responsiva com Tailwind CSS

## Estrutura do Projeto

```
sufgang/
├── app.py              # Aplicação principal
├── models.py           # Modelos do banco de dados
├── init_db.py          # Script de inicialização do banco
├── requirements.txt    # Dependências do projeto
├── .env               # Variáveis de ambiente
└── templates/         # Templates HTML
    ├── base.html      # Template base
    ├── index.html     # Página inicial
    ├── login.html     # Página de login
    ├── register.html  # Página de registro
    └── profile.html   # Página de perfil
```

## Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

# PODIUM - E-commerce de Streetwear

Sistema de e-commerce para venda de produtos streetwear com gerenciamento de perfil de usuário, múltiplos endereços e formas de pagamento.

## Requisitos

- Python 3.8 ou superior
- PostgreSQL (opcional, pode usar SQLite)

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/RyannAndrade/podium-store.git
cd podium-store
```

2. Crie e ative um ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente:
Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:
```
SECRET_KEY=sua_chave_secreta_aqui
DATABASE_URL=sqlite:///podium.db  # ou sua URL do PostgreSQL
CLOUDINARY_CLOUD_NAME=seu_cloud_name
CLOUDINARY_API_KEY=sua_api_key
CLOUDINARY_API_SECRET=seu_api_secret
MAIL_PASSWORD=sua_senha_email
```

5. Inicialize o banco de dados:
```bash
python init_db.py
```

## Uso

1. Inicie o servidor:
```bash
python app.py
```

2. Acesse o sistema em seu navegador:
```
http://localhost:5000
```

## Funcionalidades

- Gerenciamento de informações pessoais
- Cadastro e gerenciamento de múltiplos endereços
- Cadastro e gerenciamento de cartões de crédito/débito
- Alteração de senha
- Interface responsiva
- Integração com Cloudinary para imagens
- Sistema de e-mail para contato
- Carrinho de compras
- Catálogo de produtos
- Lookbook

## Estrutura do Projeto

```
podium-store/
├── app.py              # Aplicação principal
├── models.py           # Modelos do banco de dados
├── init_db.py          # Script de inicialização do banco
├── requirements.txt    # Dependências do projeto
├── .env               # Variáveis de ambiente
├── static/            # Arquivos estáticos
│   ├── css/          # Arquivos CSS
│   ├── js/           # Arquivos JavaScript
│   └── images/       # Imagens
└── templates/         # Templates HTML
    ├── base.html      # Template base
    ├── index.html     # Página inicial
    ├── login.html     # Página de login
    ├── register.html  # Página de registro
    ├── profile.html   # Página de perfil
    ├── catalog.html   # Página do catálogo
    ├── cart.html      # Página do carrinho
    └── contact.html   # Página de contato
```

## Deploy

### Heroku

1. Instale o Heroku CLI e faça login:
```bash
heroku login
```

2. Crie um novo app no Heroku:
```bash
heroku create podium-store
```

3. Configure as variáveis de ambiente:
```bash
heroku config:set $(cat .env | grep -v '^#' | xargs)
```

4. Adicione os add-ons necessários:
```bash
heroku addons:create heroku-postgresql:hobby-dev
heroku addons:create cloudinary:starter
```

5. Faça o deploy:
```bash
git push heroku main
```

### Configuração do SSL com Cloudflare

1. Cadastre-se no Cloudflare
2. Adicione seu domínio
3. Atualize os nameservers do seu domínio
4. Ative o SSL Full
5. Configure as regras de Page Rules

## Segurança

- SSL/TLS ativo
- Headers de segurança configurados
- Rate limiting implementado
- Proteção contra CSRF
- Sanitização de inputs
- Validação de dados
- Backups regulares

## Contato

Para suporte: reachthepodiumbrand@gmail.com

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.

## Manutenção

- Backup diário do banco de dados
- Monitoramento com New Relic
- Logs centralizados com Papertrail
- Alertas de uptime com UptimeRobot

## Configuração do S3

1. Crie um bucket no Amazon S3
2. Configure as permissões CORS
3. Crie um usuário IAM com acesso ao bucket
4. Atualize as variáveis de ambiente

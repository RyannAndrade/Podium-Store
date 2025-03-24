from app import app, db
from models import User, Address, PaymentMethod

def init_db():
    with app.app_context():
        # Criar todas as tabelas
        db.create_all()
        print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_db() 
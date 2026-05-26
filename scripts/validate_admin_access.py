#!/usr/bin/env python3
"""
Valida o problema de acesso com usuário admin@example.com
Diagnostica se o usuário existe, está ativo, e se a senha está correta.
"""
import sys
import os

# Adiciona o backend ao path
sys.path.insert(0, "/app")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from app.models.models import User
from app.core.config import settings
from app.core.security import verify_password, get_password_hash

def main():
    print("=" * 80)
    print("VALIDAÇÃO DE ACESSO - admin@example.com")
    print("=" * 80)
    
    # Verifica configurações
    print("\n📋 CONFIGURAÇÕES:")
    print(f"  Admin Email (esperado): {settings.admin_email}")
    print(f"  Admin Password (esperado): {settings.admin_password}")
    print(f"  Database URL: {settings.database_url}")
    
    # Tenta conectar ao banco
    print("\n🔌 CONECTANDO AO BANCO DE DADOS...")
    try:
        engine = create_engine(settings.database_url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("  ✅ Conexão bem-sucedida!")
    except Exception as e:
        print(f"  ❌ Erro ao conectar: {e}")
        return False
    
    # Busca o usuário
    print(f"\n👤 PROCURANDO USUÁRIO '{settings.admin_email}'...")
    db = Session(bind=engine)
    try:
        user = db.query(User).filter(User.email == settings.admin_email).first()
        
        if not user:
            print(f"  ❌ USUÁRIO NÃO ENCONTRADO!")
            print(f"     O usuário admin precisa ser criado.")
            print(f"     Solução: Reinicie o backend (será criado automaticamente no startup)")
            return False
        
        print(f"  ✅ Usuário encontrado!")
        print(f"     ID: {user.id}")
        print(f"     Email: {user.email}")
        print(f"     Ativo: {user.is_active}")
        print(f"     Admin: {user.is_admin}")
        
        # Verifica se está ativo
        if not user.is_active:
            print(f"  ❌ USUÁRIO INATIVO!")
            print(f"     O usuário está marcado como inativo.")
            print(f"     Solução: Ative o usuário no banco de dados")
            return False
        
        # Verifica se é admin
        if not user.is_admin:
            print(f"  ⚠️  USUÁRIO NÃO É ADMIN!")
            print(f"     O usuário existe mas não tem privilégios de admin.")
            print(f"     Solução: Atualize o usuário para is_admin=True")
            return False
        
        # Testa a senha
        print(f"\n🔐 VALIDANDO SENHA...")
        if verify_password(settings.admin_password, user.password_hash):
            print(f"  ✅ SENHA CORRETA!")
            print(f"\n✅ TUDO OK! O usuário deveria conseguir fazer login com:")
            print(f"   Email: {settings.admin_email}")
            print(f"   Senha: {settings.admin_password}")
            return True
        else:
            print(f"  ❌ SENHA INCORRETA!")
            print(f"     A senha armazenada não corresponde à esperada.")
            print(f"     Hash esperado para '{settings.admin_password}':")
            expected_hash = get_password_hash(settings.admin_password)
            print(f"     {expected_hash}")
            print(f"     Hash armazenado:")
            print(f"     {user.password_hash}")
            print(f"\n     Solução: Reinicie o backend ou execute:")
            print(f"     UPDATE users SET password_hash = '{expected_hash}'")
            print(f"     WHERE email = '{settings.admin_email}'")
            return False
            
    except Exception as e:
        print(f"  ❌ Erro ao buscar usuário: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

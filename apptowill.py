```text
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)


# ==============================
# CONFIGURAÇÕES
# ==============================

BANCO = "usuarios.db"

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "chave-temporaria-apenas-local"
)


# ==============================
# BANCO DE DADOS
# ==============================

def conectar_banco():
    conexao = sqlite3.connect(BANCO)

    conexao.row_factory = sqlite3.Row

    return conexao


def criar_banco():

    with conectar_banco() as conexao:

        conexao.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                senha TEXT NOT NULL
            )
        """)

        conexao.commit()


# ==============================
# PÁGINA INICIAL
# ==============================

@app.route("/")
def inicio():

    return render_template("index.html")


# ==============================
# CADASTRO DE USUÁRIO
# ==============================

@app.route("/cadastrar", methods=["POST"])
def cadastrar():

    nome = request.form.get(
        "nome",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    senha = request.form.get(
        "senha",
        ""
    )

    confirmar_senha = request.form.get(
        "confirmar_senha",
        ""
    )


    # Verificar campos

    if not nome or not email or not senha:

        flash(
            "Preencha todos os campos.",
            "erro"
        )

        return redirect(
            url_for("inicio")
        )


    # Verificar tamanho da senha

    if len(senha) < 6:

        flash(
            "A senha precisa ter pelo menos 6 caracteres.",
            "erro"
        )

        return redirect(
            url_for("inicio")
        )


    # Confirmar senha

    if confirmar_senha and senha != confirmar_senha:

        flash(
            "As senhas não são iguais.",
            "erro"
        )

        return redirect(
            url_for("inicio")
        )


    # Criar hash da senha

    senha_hash = generate_password_hash(
        senha
    )


    try:

        with conectar_banco() as conexao:

            conexao.execute(
                """
                INSERT INTO usuarios
                (nome, email, senha)
                VALUES (?, ?, ?)
                """,
                (
                    nome,
                    email,
                    senha_hash
                )
            )

            conexao.commit()


        flash(
            f"Cadastro realizado com sucesso, {nome}! Agora você pode entrar.",
            "sucesso"
        )

    except sqlite3.IntegrityError:

        flash(
            "Esse e-mail já está cadastrado.",
            "erro"
        )


    return redirect(
        url_for("inicio")
    )


# ==============================
# LOGIN
# ==============================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email_ou_usuario = request.form.get(
            "usuario",
            ""
        ).strip()

        senha = request.form.get(
            "senha",
            ""
        )


        # =================================
        # LOGIN DO ADMINISTRADOR
        # =================================

        admin_usuario = os.environ.get(
            "ADMIN_USUARIO"
        )

        admin_senha_hash = os.environ.get(
            "ADMIN_SENHA_HASH"
        )


        if (
            admin_usuario
            and admin_senha_hash
            and email_ou_usuario == admin_usuario
        ):

            try:

                senha_correta = check_password_hash(
                    admin_senha_hash,
                    senha
                )

            except Exception:

                senha_correta = False


            if senha_correta:

                session.clear()

                session["admin_logado"] = True

                session["tipo_usuario"] = "admin"

                return redirect(
                    url_for("admin")
                )


        # =================================
        # LOGIN DO USUÁRIO NORMAL
        # =================================

        with conectar_banco() as conexao:

            usuario = conexao.execute(
                """
                SELECT id, nome, email, senha
                FROM usuarios
                WHERE email = ?
                """,
                (
                    email_ou_usuario.lower(),
                )
            ).fetchone()


        if usuario:

            try:

                senha_correta = check_password_hash(
                    usuario["senha"],
                    senha
                )

            except Exception:

                senha_correta = False


            if senha_correta:

                session.clear()

                session["usuario_id"] = usuario["id"]

                session["usuario_nome"] = usuario["nome"]

                session["usuario_email"] = usuario["email"]

                session["tipo_usuario"] = "usuario"


                flash(
                    f"Bem-vindo, {usuario['nome']}!",
                    "sucesso"
                )


                return redirect(
                    url_for("usuario")
                )


        # =================================
        # LOGIN INCORRETO
        # =================================

        flash(
            "E-mail/usuário ou senha incorretos.",
            "erro"
        )


    return render_template(
        "login.html"
    )


# ==============================
# ÁREA DO USUÁRIO
# ==============================

@app.route("/usuario")
def usuario():

    if session.get("tipo_usuario") != "usuario":

        flash(
            "Você precisa fazer login para acessar sua conta.",
            "erro"
        )

        return redirect(
            url_for("login")
        )


    nome = session.get(
        "usuario_nome"
    )

    email = session.get(
        "usuario_email"
    )


    return render_template(
        "usuario.html",
        nome=nome,
        email=email
    )


# ==============================
# ÁREA ADMINISTRATIVA
# ==============================

@app.route("/admin")
def admin():

    # Somente administrador pode entrar

    if session.get("tipo_usuario") != "admin":

        flash(
            "Você precisa ser administrador para acessar esta área.",
            "erro"
        )

        return redirect(
            url_for("login")
        )


    with conectar_banco() as conexao:

        usuarios = conexao.execute(
            """
            SELECT id, nome, email
            FROM usuarios
            ORDER BY id DESC
            """
        ).fetchall()


    return render_template(
        "admin.html",
        usuarios=usuarios
    )


# ==============================
# LOGOUT
# ==============================

@app.route("/logout")
def logout():

    session.clear()


    flash(
        "Você saiu da sua conta.",
        "sucesso"
    )


    return redirect(
        url_for("inicio")
    )


# ==============================
# CRIAR BANCO
# ==============================

criar_banco()


# ==============================
# INICIAR APLICAÇÃO
# ==============================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )
```

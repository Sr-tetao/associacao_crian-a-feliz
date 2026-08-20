from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

BANCO = "usuarios.db"

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "chave-temporaria-apenas-local"
)


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


@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/cadastrar", methods=["POST"])
def cadastrar():

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    senha = request.form.get("senha", "")

    if not nome or not email or not senha:
        flash("Preencha todos os campos.", "erro")
        return redirect(url_for("inicio"))

    if len(senha) < 6:
        flash(
            "A senha precisa ter pelo menos 6 caracteres.",
            "erro"
        )
        return redirect(url_for("inicio"))

    senha_hash = generate_password_hash(senha)

    try:
        with conectar_banco() as conexao:
            conexao.execute(
                """
                INSERT INTO usuarios
                (nome, email, senha)
                VALUES (?, ?, ?)
                """,
                (nome, email, senha_hash)
            )

        flash(
            f"Cadastro realizado com sucesso, {nome}!",
            "sucesso"
        )

    except sqlite3.IntegrityError:
        flash(
            "Esse e-mail já está cadastrado.",
            "erro"
        )

    return redirect(url_for("inicio"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        usuario = request.form.get(
            "usuario",
            ""
        ).strip()

        senha = request.form.get(
            "senha",
            ""
        )

        admin_usuario = os.environ.get(
            "ADMIN_USUARIO"
        )

        admin_senha_hash = os.environ.get(
            "ADMIN_SENHA_HASH"
        )

        if (
            admin_usuario
            and admin_senha_hash
            and usuario == admin_usuario
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

                return redirect(
                    url_for("admin")
                )

        flash(
            "Usuário ou senha incorretos.",
            "erro"
        )

    return render_template("login.html")


@app.route("/admin")
def admin():

    if not session.get("admin_logado"):

        flash(
            "Você precisa fazer login para acessar a área administrativa.",
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


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Você saiu da área administrativa.",
        "sucesso"
    )

    return redirect(
        url_for("login")
    )


# Criar o banco também quando o Gunicorn iniciar
criar_banco()


if __name__ == "__main__":
    app.run(
        debug=True
    )

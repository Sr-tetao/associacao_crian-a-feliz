from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash
import os

app = Flask(__name__)

BANCO = "usuarios.db"

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "chave-temporaria"
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

    # Verifica os campos
    if not nome or not email or not senha:
        flash("Preencha todos os campos.", "erro")
        return redirect(url_for("inicio"))

    # Verifica tamanho mínimo da senha
    if len(senha) < 6:
        flash("A senha precisa ter pelo menos 6 caracteres.", "erro")
        return redirect(url_for("inicio"))

    # Cria o hash da senha
    senha_hash = generate_password_hash(senha)

    try:
        with conectar_banco() as conexao:

            conexao.execute(
                """
                INSERT INTO usuarios (nome, email, senha)
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

if __name__ == "__main__":
    criar_banco()
    app.run(
        debug=True
    )

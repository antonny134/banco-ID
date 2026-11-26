import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import unicodedata
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import uvicorn as uvicon
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent


def carregar_env(caminho: Path) -> dict:
    valores = {}
    try:
        linhas = caminho.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return valores
    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        valores[chave.strip()] = valor.strip().strip('"').strip("'")
    return valores


_ENV = carregar_env(BASE_DIR / ".env")


def cfg(chave: str, padrao: str) -> str:
    return os.environ.get(chave, _ENV.get(chave, padrao))


HOST = cfg("HOST", "127.0.0.1")
PORT = int(cfg("PORT", "8000"))
API_BASE_URL = cfg("API_BASE_URL", f"http://{HOST}:{PORT}")
MAX_MB = float(cfg("MAX_UPLOAD_MB", "10"))
MAX_BYTES = int(MAX_MB * 1024 * 1024)
DURACAO_SESSAO = int(cfg("SESSION_DURATION_DAYS", "30")) * 24 * 3600
MAX_PDFS_POR_USUARIO = int(cfg("MAX_PDFS_POR_USUARIO", "100"))
ORIGENS_PERMITIDAS = [
    o.strip() for o in cfg("ALLOWED_ORIGINS", API_BASE_URL).split(",") if o.strip()
]
PDFS_DIR = BASE_DIR / "pdfs"
DADOS_DIR = BASE_DIR / "dados"
PDFS_DIR.mkdir(exist_ok=True)
DADOS_DIR.mkdir(exist_ok=True)

USUARIOS_JSON = DADOS_DIR / "usuarios.json"  # contas (senha só em hash)
SESSOES_JSON = DADOS_DIR / "sessoes.json"  # tokens de login (só o hash)
PDFS_JSON = DADOS_DIR / "pdfs.json"  # dono e estado de cada PDF
REACOES_JSON = DADOS_DIR / "reacoes.json"  # votos por PDF e conta

ITERACOES_HASH = 200_000
trava = threading.RLock()

# sem /docs e /openapi.json publicos
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_origins=ORIGENS_PERMITIDAS,
)



@app.middleware("http")
async def cabecalhos_de_seguranca(request: Request, chamada):
    # recusa upload gigante antes de processar o corpo
    if request.method == "POST" and request.url.path == "/pdfs":
        tamanho = request.headers.get("content-length", "")
        if tamanho.isdigit() and int(tamanho) > MAX_BYTES + 1024 * 1024:
            return JSONResponse(
                {"detail": f"Arquivo maior que {MAX_MB:g} MB"}, status_code=413
            )
    resposta = await chamada(request)
    resposta.headers.setdefault("X-Content-Type-Options", "nosniff")
    resposta.headers.setdefault("X-Frame-Options", "DENY")
    resposta.headers.setdefault("Referrer-Policy", "same-origin")
    return resposta


app.mount("/paginas", StaticFiles(directory=BASE_DIR / "paginas"), name="paginas")


# ---------- Modelos ----------
class Cadastro(BaseModel):
    nome: str = Field(min_length=2, max_length=40)
    senha: str = Field(min_length=6, max_length=128)


class Login(BaseModel):
    nome: str = Field(min_length=1, max_length=40)
    senha: str = Field(min_length=1, max_length=128)


class Reacao(BaseModel):
    valor: Literal["curtir", "nao_curtir"]


# ---------- Utilidades ----------
def agora_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ler_json(caminho: Path, padrao):
    try:
        return json.loads(caminho.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return padrao


def salvar_json(caminho: Path, dados) -> None:
    temporario = caminho.with_suffix(".tmp")
    temporario.write_text(
        json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporario.replace(caminho)


def normalizar_nome(nome: str) -> str:
    # NFKC junta variantes de aparencia igual (ex.: letras de largura total)
    return " ".join(unicodedata.normalize("NFKC", nome).split())


def nome_tem_caractere_invalido(nome: str) -> bool:
    # bloqueia caracteres de controle/invisiveis (ex.: inversao de texto RTL)
    return any(unicodedata.category(c).startswith("C") for c in nome)


def chave_usuario(nome: str) -> str:
    return normalizar_nome(nome).casefold()


# ---------- Limite de tentativas (anti forca-bruta) ----------
_eventos: dict = {}
_trava_limite = threading.Lock()


def ip_cliente(request: Request) -> str:
    # nao confia em X-Forwarded-For (o cliente pode forjar)
    return request.client.host if request.client else "?"


def contar_eventos(chave: str, janela: int) -> int:
    agora = time.time()
    with _trava_limite:
        fila = _eventos.get(chave)
        if not fila:
            return 0
        while fila and fila[0] <= agora - janela:
            fila.popleft()
        if not fila:
            del _eventos[chave]
            return 0
        return len(fila)


def registrar_evento(chave: str) -> None:
    with _trava_limite:
        if len(_eventos) > 20_000:  # evita crescer sem limite
            _eventos.clear()
        _eventos.setdefault(chave, deque()).append(time.time())


def limpar_eventos(chave: str) -> None:
    with _trava_limite:
        _eventos.pop(chave, None)


def exigir_limite(chave: str, limite: int, janela: int, mensagem: str) -> None:
    if contar_eventos(chave, janela) >= limite:
        raise HTTPException(429, mensagem)


def gerar_hash(senha: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt, ITERACOES_HASH
    ).hex()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def garantir_perfil_ids() -> dict:
    """Garante que contas antigas também tenham um identificador público estável."""
    with trava:
        usuarios = ler_json(USUARIOS_JSON, {})
        alterado = False
        for chave, dados in usuarios.items():
            if not dados.get("perfil_id"):
                dados["perfil_id"] = uuid.uuid4().hex
                alterado = True
        if alterado:
            salvar_json(USUARIOS_JSON, usuarios)
    return usuarios


# ---------- Autenticação ----------
def usuario_atual(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Faça login para continuar.")
    h = hash_token(authorization[7:].strip())
    sessao = ler_json(SESSOES_JSON, {}).get(h)
    usuarios = garantir_perfil_ids()
    if (
        not sessao
        or sessao.get("expira", 0) < time.time()
        or sessao["usuario"] not in usuarios
    ):
        raise HTTPException(401, "Sessão inválida ou expirada.")
    chave = sessao["usuario"]
    dados = usuarios[chave]
    return {
        "chave": chave,
        "nome": dados["nome"],
        "perfil_id": dados["perfil_id"],
        "token_hash": h,
    }


def usuario_opcional(
    authorization: Optional[str] = Header(default=None),
) -> Optional[dict]:
    if authorization is None:
        return None
    return usuario_atual(authorization)


@app.post("/cadastro", status_code=201)
def cadastrar(corpo: Cadastro, request: Request):
    ip = ip_cliente(request)
    exigir_limite(
        f"cadastro:{ip}", 10, 3600, "Muitos cadastros. Tente novamente mais tarde."
    )
    registrar_evento(f"cadastro:{ip}")
    nome = normalizar_nome(corpo.nome)
    if len(nome) < 2:
        raise HTTPException(400, "O nome deve ter pelo menos 2 caracteres.")
    if nome_tem_caractere_invalido(nome):
        raise HTTPException(400, "O nome tem caracteres inválidos.")
    chave = chave_usuario(nome)
    salt = secrets.token_bytes(16)
    hash_senha = gerar_hash(corpo.senha, salt)
    with trava:
        usuarios = ler_json(USUARIOS_JSON, {})
        if chave in usuarios:
            raise HTTPException(409, "Este usuário já está cadastrado.")
        usuarios[chave] = {
            "nome": nome,
            "perfil_id": uuid.uuid4().hex,
            "salt": salt.hex(),
            "hash": hash_senha,
            "criado": agora_iso(),
        }
        salvar_json(USUARIOS_JSON, usuarios)
    return {"nome": nome}


@app.post("/login")
def entrar(corpo: Login, request: Request):
    ip = ip_cliente(request)
    chave_nome = chave_usuario(corpo.nome)
    k_conta, k_ip = f"login:{ip}:{chave_nome}", f"login-ip:{ip}"
    msg = "Muitas tentativas. Aguarde alguns minutos."
    exigir_limite(k_conta, 5, 900, msg)  # 5 erros / 15 min por IP+conta
    exigir_limite(k_ip, 30, 900, msg)  # 30 erros / 15 min por IP
    usuario = garantir_perfil_ids().get(chave_nome)
    salt = bytes.fromhex(usuario["salt"]) if usuario else b"\0" * 16
    calculado = gerar_hash(corpo.senha, salt)  # sempre calcula (evita medir tempo)
    if not usuario or not hmac.compare_digest(calculado, usuario["hash"]):
        registrar_evento(k_conta)
        registrar_evento(k_ip)
        raise HTTPException(401, "Nome ou senha incorretos.")
    limpar_eventos(k_conta)

    token = secrets.token_urlsafe(32)
    agora = time.time()
    with trava:
        sessoes = ler_json(SESSOES_JSON, {})
        sessoes = {h: s for h, s in sessoes.items() if s.get("expira", 0) > agora}
        sessoes[hash_token(token)] = {
            "usuario": chave_usuario(usuario["nome"]),
            "expira": agora + DURACAO_SESSAO,
        }
        salvar_json(SESSOES_JSON, sessoes)
    return {"token": token, "nome": usuario["nome"]}


@app.post("/logout")
def sair(usuario: dict = Depends(usuario_atual)):
    with trava:
        sessoes = ler_json(SESSOES_JSON, {})
        if sessoes.pop(usuario["token_hash"], None) is not None:
            salvar_json(SESSOES_JSON, sessoes)
    return {"ok": True}


@app.get("/eu")
def quem_sou_eu(usuario: dict = Depends(usuario_atual)):
    return {
        "nome": usuario["nome"],
        "perfil_id": usuario["perfil_id"],
        "url_perfil": f"/perfil/{usuario['perfil_id']}",
    }


# ---------- PDFs ----------
def carregar_pdf(pdf_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", pdf_id):
        raise HTTPException(400, "ID inválido")
    meta = ler_json(PDFS_JSON, {}).get(pdf_id)
    caminho = PDFS_DIR / f"{pdf_id}.pdf"
    if not meta or not caminho.exists():
        raise HTTPException(404, "PDF não encontrado")
    return meta, caminho


def pdf_do_usuario(pdf_id: str, usuario: dict):
    meta, caminho = carregar_pdf(pdf_id)
    if meta["dono"] != usuario["chave"]:
        # 404 (e não 403) para não revelar que o PDF de outra pessoa existe
        raise HTTPException(404, "PDF não encontrado")
    return meta, caminho


def enviar_arquivo(caminho: Path, meta: dict) -> FileResponse:
    return FileResponse(
        caminho,
        media_type="application/pdf",
        filename=meta["nome"],
        content_disposition_type="inline",
    )


def resumo_reacoes(votos: dict, chave_usuario_atual: Optional[str] = None) -> dict:
    return {
        "curtidas": sum(1 for voto in votos.values() if voto == "curtir"),
        "nao_curtidas": sum(
            1 for voto in votos.values() if voto == "nao_curtir"
        ),
        "reacao_usuario": votos.get(chave_usuario_atual),
    }


def item_publico(
    pdf_id: str,
    meta: dict,
    usuarios: dict,
    reacoes: dict,
    chave_usuario_atual: Optional[str],
) -> dict:
    dono = usuarios.get(meta["dono"], {})
    return {
        "id": pdf_id,
        "nome": meta["nome"],
        "autor": dono.get("nome", "Anônimo"),
        "perfil_id": dono.get("perfil_id"),
        "data": meta.get("data_compartilhado") or meta["data"],
        **resumo_reacoes(reacoes.get(pdf_id, {}), chave_usuario_atual),
    }


def listar_publicos(
    filtro_dono: Optional[str] = None, usuario: Optional[dict] = None
) -> list:
    pdfs = ler_json(PDFS_JSON, {})
    usuarios = ler_json(USUARIOS_JSON, {})
    reacoes = ler_json(REACOES_JSON, {})
    itens = [
        item_publico(
            pdf_id,
            meta,
            usuarios,
            reacoes,
            usuario["chave"] if usuario else None,
        )
        for pdf_id, meta in pdfs.items()
        if meta.get("compartilhado")
        and (filtro_dono is None or meta["dono"] == filtro_dono)
        and (PDFS_DIR / f"{pdf_id}.pdf").exists()
    ]
    itens.sort(key=lambda item: item["data"], reverse=True)
    return itens


@app.get("/")
def inicio():
    # vai para a pagina inicial
    return FileResponse(BASE_DIR / "index.html")


@app.get("/config.js")
def config_js():
    # so valores publicos do .env vao para o navegador
    corpo = "window.APP_CONFIG = " + json.dumps({"API_BASE_URL": API_BASE_URL}) + ";\n"
    return Response(
        corpo,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/pdfs")
async def enviar_pdf(
    arquivo: UploadFile = File(...), usuario: dict = Depends(usuario_atual)
):
    nome = Path(arquivo.filename or "").name
    if not nome.lower().endswith(".pdf"):
        raise HTTPException(400, "Envie um arquivo .pdf")

    ja_enviados = sum(
        1 for m in ler_json(PDFS_JSON, {}).values() if m.get("dono") == usuario["chave"]
    )
    if ja_enviados >= MAX_PDFS_POR_USUARIO:
        raise HTTPException(409, f"Limite de {MAX_PDFS_POR_USUARIO} PDFs atingido.")

    conteudo = bytearray()
    while bloco := await arquivo.read(1024 * 1024):  # le aos poucos
        conteudo += bloco
        if len(conteudo) > MAX_BYTES:
            raise HTTPException(413, f"Arquivo maior que {MAX_MB:g} MB")
    conteudo = bytes(conteudo)
    if not conteudo.startswith(b"%PDF"):
        raise HTTPException(400, "O arquivo não é um PDF válido")

    nome_seguro = re.sub(r"[^\w.\- ]", "_", nome)
    pdf_id = uuid.uuid4().hex
    caminho_final = PDFS_DIR / f"{pdf_id}.pdf"
    caminho_temporario = PDFS_DIR / f".{pdf_id}.tmp"
    caminho_temporario.write_bytes(conteudo)
    caminho_temporario.replace(caminho_final)

    with trava:
        pdfs = ler_json(PDFS_JSON, {})
        pdfs[pdf_id] = {
            "dono": usuario["chave"],
            "nome": nome_seguro,
            "compartilhado": False,
            "data": agora_iso(),
            "data_compartilhado": None,
        }
        salvar_json(PDFS_JSON, pdfs)
    return {"id": pdf_id, "nome": nome_seguro, "compartilhado": False}


@app.get("/pdfs")
def listar_meus_pdfs(usuario: dict = Depends(usuario_atual)):
    pdfs = ler_json(PDFS_JSON, {})
    meus = [
        {
            "id": pdf_id,
            "nome": meta["nome"],
            "compartilhado": bool(meta.get("compartilhado")),
            "data": meta["data"],
        }
        for pdf_id, meta in pdfs.items()
        if meta["dono"] == usuario["chave"]
        and (PDFS_DIR / f"{pdf_id}.pdf").exists()
    ]
    meus.sort(key=lambda item: item["data"], reverse=True)
    return meus


@app.get("/pdfs/{pdf_id}")
def abrir_meu_pdf(pdf_id: str, usuario: dict = Depends(usuario_atual)):
    meta, caminho = pdf_do_usuario(pdf_id, usuario)
    return enviar_arquivo(caminho, meta)


@app.delete("/pdfs/{pdf_id}")
def apagar_pdf(pdf_id: str, usuario: dict = Depends(usuario_atual)):
    _, caminho = pdf_do_usuario(pdf_id, usuario)
    caminho.unlink(missing_ok=True)
    with trava:
        pdfs = ler_json(PDFS_JSON, {})
        if pdfs.pop(pdf_id, None) is not None:
            salvar_json(PDFS_JSON, pdfs)
        reacoes = ler_json(REACOES_JSON, {})
        if reacoes.pop(pdf_id, None) is not None:
            salvar_json(REACOES_JSON, reacoes)
    return {"ok": True}


# ---------- Compartilhamento ----------
def definir_compartilhado(pdf_id: str, usuario: dict, valor: bool) -> None:
    pdf_do_usuario(pdf_id, usuario)  # confere se existe e se é do usuário
    with trava:
        pdfs = ler_json(PDFS_JSON, {})
        if pdf_id not in pdfs:
            raise HTTPException(404, "PDF não encontrado")
        pdfs[pdf_id]["compartilhado"] = valor
        pdfs[pdf_id]["data_compartilhado"] = agora_iso() if valor else None
        salvar_json(PDFS_JSON, pdfs)


@app.post("/pdfs/{pdf_id}/compartilhar")
def compartilhar_pdf(pdf_id: str, usuario: dict = Depends(usuario_atual)):
    definir_compartilhado(pdf_id, usuario, True)
    return {"ok": True}


@app.delete("/pdfs/{pdf_id}/compartilhar")
def descompartilhar_pdf(pdf_id: str, usuario: dict = Depends(usuario_atual)):
    definir_compartilhado(pdf_id, usuario, False)
    return {"ok": True}


# ---------- Área pública (só o que foi compartilhado) ----------
@app.get("/publico/{pdf_id}")
def abrir_pdf_publico(pdf_id: str):
    meta, caminho = carregar_pdf(pdf_id)
    if not meta.get("compartilhado"):
        raise HTTPException(404, "PDF não encontrado")
    return enviar_arquivo(caminho, meta)


@app.get("/compartilhados")
def listar_compartilhados(
    usuario: Optional[dict] = Depends(usuario_opcional),
):
    return listar_publicos(usuario=usuario)


@app.post("/publico/{pdf_id}/reacao")
def registrar_reacao(
    pdf_id: str,
    corpo: Reacao,
    usuario: dict = Depends(usuario_atual),
):
    carregar_pdf(pdf_id)
    with trava:
        pdfs = ler_json(PDFS_JSON, {})
        meta = pdfs.get(pdf_id)
        if not meta or not meta.get("compartilhado"):
            raise HTTPException(404, "PDF não encontrado")

        reacoes = ler_json(REACOES_JSON, {})
        votos = reacoes.setdefault(pdf_id, {})
        if votos.get(usuario["chave"]) == corpo.valor:
            votos.pop(usuario["chave"])
        else:
            votos[usuario["chave"]] = corpo.valor

        if not votos:
            reacoes.pop(pdf_id, None)
        salvar_json(REACOES_JSON, reacoes)
        return resumo_reacoes(votos, usuario["chave"])


@app.get("/usuarios/{nome}/compartilhados")
def compartilhados_do_usuario(nome: str):
    chave = chave_usuario(nome)
    usuario = garantir_perfil_ids().get(chave)
    if not usuario:
        raise HTTPException(404, "Usuário não encontrado.")
    return {
        "usuario": usuario["nome"],
        "perfil_id": usuario["perfil_id"],
        "pdfs": listar_publicos(chave),
    }


@app.get("/perfil/{perfil_id}/compartilhados")
def compartilhados_por_perfil(perfil_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", perfil_id):
        raise HTTPException(404, "Perfil não encontrado.")
    usuarios = garantir_perfil_ids()
    dono = next(
        (
            (chave, dados)
            for chave, dados in usuarios.items()
            if dados.get("perfil_id") == perfil_id
        ),
        None,
    )
    if not dono:
        raise HTTPException(404, "Perfil não encontrado.")
    chave, usuario = dono
    return {
        "usuario": usuario["nome"],
        "perfil_id": perfil_id,
        "pdfs": listar_publicos(chave),
    }


@app.get("/perfil/{perfil_id}")
def abrir_perfil_publico(perfil_id: str):
    if not re.fullmatch(r"[a-f0-9]{32}", perfil_id):
        raise HTTPException(404, "Perfil não encontrado.")
    usuarios = garantir_perfil_ids()
    if not any(dados.get("perfil_id") == perfil_id for dados in usuarios.values()):
        raise HTTPException(404, "Perfil não encontrado.")
    return FileResponse(BASE_DIR / "paginas" / "perfil.html")


if __name__ == "__main__":
    uvicon.run(app, host=HOST, port=PORT)
import streamlit as st
import pandas as pd
import hashlib
import hmac
import secrets
import string
import io
import re
import base64
import datetime
import os
import unicodedata
from PIL import Image

# ==========================================
# 0. CONFIGURAÇÃO (set_page_config precisa ser o primeiro comando Streamlit)
# ==========================================
st.set_page_config(page_title="TucanoPay - Anonimizador", page_icon="🛡️", layout="wide")

# Chave secreta do HMAC. Ordem de busca:
#   1) variável de ambiente ANON_KEY  (export ANON_KEY="string-longa-e-aleatoria")
#   2) st.secrets["ANON_KEY"]         (.streamlit/secrets.toml local ou "Secrets" no Streamlit Cloud)
#   3) modo demonstração: chave aleatória por sessão (hashes mudam a cada sessão)
# Nunca versione essa chave no Git.
try:
    CHAVE = os.environ.get("ANON_KEY") or st.secrets["ANON_KEY"]
except Exception:
    CHAVE = None

MODO_DEMO = not CHAVE
if MODO_DEMO:
    if "chave_temp" not in st.session_state:
        st.session_state["chave_temp"] = secrets.token_hex(32)
    CHAVE = st.session_state["chave_temp"]
    st.warning("⚠️ Modo demonstração: chave temporária. Os hashes mudam a cada sessão e "
               "não podem ser comparados entre execuções.")

# ==========================================
# 1. FUNÇÕES DE ANONIMIZAÇÃO
# ==========================================
def anon_hash(df, columns):
    """HMAC-SHA256 com chave secreta. Mesmo valor -> mesmo hash (permite cruzar bases)."""
    chave = CHAVE.encode("utf-8")
    for col in columns:
        mapa = {
            v: hmac.new(chave, str(v).strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()
            for v in df[col].dropna().unique()
        }
        df[col] = df[col].map(mapa)
    return df


def _mascarar(x, visible):
    if pd.isna(x):
        return x
    x = str(x)
    # Só mostra o início se o valor for longo; o tamanho da máscara é fixo (não vaza o comprimento)
    return (x[:visible] if len(x) > visible * 3 else "") + "********"


def anon_mask(df, columns, visible=3):
    for col in columns:
        df[col] = df[col].map(lambda x: _mascarar(x, visible))
    return df


def anon_random(df, columns):
    """Código aleatório criptograficamente seguro. Mesmo valor -> mesmo código."""
    alfabeto = string.ascii_letters + string.digits
    for col in columns:
        mapa = {
            v: "".join(secrets.choice(alfabeto) for _ in range(10))
            for v in df[col].dropna().unique()
        }
        df[col] = df[col].map(mapa)
    return df


# A ordem importa: padrões mais específicos (CNPJ, CPF, cartão) antes dos mais genéricos.
_PADROES_TEXTO = [
    (r'\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b', '[CNPJ REMOVIDO]'),
    (r'\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b', '[CPF REMOVIDO]'),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', '[CARTÃO REMOVIDO]'),
    (r'\(\d{2}\)\s\d{4,5}-\d{4}', '[TELEFONE REMOVIDO]'),
    (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL REMOVIDO]'),
    (r'\b\d{5}-\d{3}\b', '[CEP REMOVIDO]'),
    (r'(?i)\b(?:rua|avenida|av\.|travessa|alameda)\s+(?:\w+\s*){1,4}(?:,\s*\d+)?', '[ENDEREÇO REMOVIDO]'),
    (r'(?i)\b(?:conta|c\.c\.|cc|ag[êe]ncia|ag\.?)\b(?:[\s\w:º.-]{0,30}?)\b\d{4,12}[-\s]*[\dXx]?\b', '[CONTA REMOVIDA]'),
    (r'(?i)\b(?:ap|apto|apartamento|casa|sala|bloco)\.?\s*(?:n?[º°]?\s*)?\d+[A-Za-z]?\b', '[UNIDADE REMOVIDA]'),
    (r'\b([Ee]sposa|[Mm]arido|[Ff]ilh[oa]|[Mm][ãa]e|[Pp]ai|[Ii]rm[ãa]o?|[Tt]i[oa]|[Pp]rim[oa]|[Ss]r\.?|[Ss]ra\.?|[Ss]enhor[a]?|[Nn]ome [ée]|[Aa]tendente|[Cc]onsultor[a]?)\s*[,:]?\s+[A-ZÀ-Ÿ][a-zà-ÿ]+(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ]+)*', r'\1 [NOME REMOVIDO]'),
]
PADROES = [(re.compile(p), r) for p, r in _PADROES_TEXTO]


def anon_regex(df, columns):
    for col in columns:
        s = df[col].astype("string")
        for rx, sub in PADROES:
            s = s.str.replace(rx, sub, regex=True)
        df[col] = s.astype(object).where(s.notna(), None)
    return df


def anon_dataset(df, config):
    if config["hash"]:
        df = anon_hash(df, config["hash"])
    if config["mask"]:
        df = anon_mask(df, config["mask"])
    if config["random"]:
        df = anon_random(df, config["random"])
    if config["regex"]:
        df = anon_regex(df, config["regex"])
    return df


def parse_linhas(texto, total):
    """Converte '1, 3, 5-10' (numeração a partir de 1, sem contar o cabeçalho)
    em índices base 0. Retorna (indices_ordenados, tokens_invalidos, tokens_fora_do_intervalo)."""
    indices, invalidos, fora = set(), [], []
    for parte in re.split(r"[,;]", texto or ""):
        parte = parte.strip()
        if not parte:
            continue
        m = re.fullmatch(r"(\d+)\s*(?:-\s*(\d+))?", parte)
        if not m:
            invalidos.append(parte)
            continue
        ini = int(m.group(1))
        fim = int(m.group(2) or ini)
        if ini > fim:
            ini, fim = fim, ini
        if ini < 1 or fim > total:
            fora.append(parte)
        ini, fim = max(ini, 1), min(fim, total)
        indices.update(range(ini - 1, fim))
    return sorted(indices), invalidos, fora


def excluir_colunas_linhas(df, colunas, linhas):
    """Remove colunas (por nome) e linhas (por posição base 0)."""
    if colunas:
        df = df.drop(columns=colunas)
    if linhas:
        df = df.drop(index=df.index[linhas])
    return df.reset_index(drop=True)


def limpar_celulas(df, celulas):
    """Esvazia células específicas. `celulas` é uma lista de (coluna, [posições de linha base 0]).
    Deve rodar antes de excluir linhas, pois as posições valem para a planilha original."""
    for col, idxs in celulas:
        if col in df.columns and idxs:
            df[col] = df[col].astype(object)  # evita converter inteiros em float ao inserir vazio
            df.loc[df.index[idxs], col] = None
    return df


def neutralizar_formulas(df):
    """Evita injeção de fórmula: células de texto começando com = + - @ viram texto no Excel."""
    perigosos = ("=", "+", "-", "@", "\t", "\r")
    # Números puros com sinal (ex.: telefone +5511999998888, valor -10.5) não são fórmulas: ficam como estão
    numero_puro = re.compile(r"[+-]?\d+(?:[.,]\d+)?")
    for col in df.columns:
        if pd.api.types.is_object_dtype(df[col]) or pd.api.types.is_string_dtype(df[col]):
            df[col] = df[col].map(
                lambda x: "'" + x if isinstance(x, str) and x.startswith(perigosos)
                and not numero_puro.fullmatch(x) else x
            )
    return df


def prever(df, n=5):
    """Pré-visualização com numeração de linhas a partir de 1 (a mesma usada em 'Excluir linhas')."""
    p = df.head(n).copy()
    p.index = p.index + 1
    return p


# ==========================================
# 2. LEITURA E IMAGEM (COM CACHE)
# ==========================================
@st.cache_data(ttl=600, max_entries=2, show_spinner="Lendo arquivo...")
def carregar(nome, conteudo, cols_texto=()):
    # Colunas tratadas são lidas como texto para preservar zeros à esquerda (ex.: CPF)
    dtype = {c: str for c in cols_texto} or None
    buf = io.BytesIO(conteudo)
    if nome.lower().endswith(".csv"):
        return pd.read_csv(buf, dtype=dtype)
    return pd.read_excel(buf, dtype=dtype)


@st.cache_data
def imagem_base64(caminho):
    img = Image.open(caminho).convert("RGBA")
    img.thumbnail((700, 700))
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


# ==========================================
# 2b. DIAGNÓSTICO DE PADRONIZAÇÃO
# ==========================================
_NULOS_DISFARCADOS = {"n/a", "na", "null", "none", "nan", "nulo", "vazio", "-", "--",
                      "sem informação", "sem informacao", "não informado", "nao informado"}


def _sem_acento(t):
    return "".join(c for c in unicodedata.normalize("NFKD", t) if not unicodedata.combining(c))


def _forma(s):
    """Reduz cada valor ao seu 'formato': dígitos -> 9, maiúsculas -> A, minúsculas -> a
    (sequências repetidas viram um só símbolo). Ex.: '123.456.789-00' -> '9.9.9-9'."""
    return (s.str.replace(r"\d+", "9", regex=True)
             .str.replace(r"[A-ZÀ-Ý]+", "A", regex=True)
             .str.replace(r"[a-zà-ÿ]+", "a", regex=True))


def _ex(valores, n=3):
    return " | ".join(repr(str(v)[:40]) for v in list(valores)[:n])


def _cpf_valido(d):
    """d: 11 dígitos sem pontuação. Confere os 2 dígitos verificadores."""
    if len(d) != 11 or not d.isdigit() or d == d[0] * 11:
        return False
    for n in (9, 10):
        soma = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (soma * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def _dv_cnpj(base):
    """Dígitos verificadores do CNPJ (numérico ou alfanumérico: valor do caractere = código ASCII - 48)."""
    pesos = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    def calc(chars, p):
        r = sum((ord(c) - 48) * w for c, w in zip(chars, p)) % 11
        return "0" if r < 2 else str(11 - r)

    d1 = calc(base, pesos)
    return d1 + calc(base + d1, [6] + pesos)


def _cnpj_valido(d):
    """d: 14 caracteres sem pontuação, em maiúsculas."""
    if not re.fullmatch(r"[0-9A-Z]{12}\d{2}", d) or d == d[0] * 14:
        return False
    return d[12:] == _dv_cnpj(d[:12])


def _documento_valido(d):
    return _cpf_valido(d) if len(d) == 11 else (_cnpj_valido(d) if len(d) == 14 else False)


# Número: 1234 | 12,5 | 12.5 | 1.234,56 | 1,234.56 (sinal opcional). Data: 2024-01-31 | 31/01/2024 | 31-01-24,
# com hora opcional.
_RX_NUM = r"[+-]?(?:\d{1,3}(?:\.\d{3})+(?:,\d+)?|\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:[.,]\d+)?)"
_RX_DATA = (r"(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})"
            r"(?:[ T]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?")


# ---- Correções automáticas (aplicadas antes da anonimização) ----
def _limpa_espacos(x):
    return " ".join(x.split()) if isinstance(x, str) else x


def _para_nulo(x):
    if isinstance(x, str) and (x.strip() == "" or x.strip().lower() in _NULOS_DISFARCADOS):
        return None
    return x


def _padroniza_doc(x):
    if pd.isna(x):
        return x
    
    # Se o Pandas leu como float numérico (ex: 12345678901.0), pegamos só a base
    if isinstance(x, float) and x.is_integer():
        x = str(int(x))
    else:
        x = str(x).strip()
        
    # Prevenção extra caso sobre um ".0" de alguma outra conversão
    x = re.sub(r"\.0$", "", x)
    
    d = re.sub(r"[.\-/\s]", "", x).upper()
    
    if re.fullmatch(r"\d+", d):
        if len(d) <= 11:
            return d.zfill(11)
        if len(d) <= 14:
            return d.zfill(14)
        return x
        
    if re.fullmatch(r"[0-9A-Z]{12}\d{2}", d):
        return d
    return x


def _padroniza_cep(x):
    """CEP: 8 dígitos, sem hífen, recompondo zero à esquerda (1310100 -> 01310100)."""
    if not isinstance(x, str) or not re.fullmatch(r"[\d\-.\s]+", x.strip()):
        return x
    d = re.sub(r"\D", "", x)
    return d.zfill(8) if d and len(d) <= 8 else x


def _padroniza_id(x):
    """Código/ID: texto sem espaços; remove o '.0' que sobra quando o ID passou por decimal (123.0 -> 123)."""
    if not isinstance(x, str):
        return x
    return re.sub(r"^(\d+)\.0+$", r"\1", re.sub(r"\s+", "", x))


_RX_DATA_ISO = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})")
_RX_DATA_BR = re.compile(r"(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})")
_RX_HORA = re.compile(r"[ T](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?")


def _padroniza_data(x):
    if pd.isna(x):
        return x
        
    # Intercepta objetos Timestamp nativos do Pandas/Excel antes que sejam ignorados
    if hasattr(x, "strftime"):
        tem_hora = getattr(x, 'hour', 0) or getattr(x, 'minute', 0) or getattr(x, 'second', 0)
        hora = f" {x.hour:02d}:{x.minute:02d}" + (f":{x.second:02d}" if getattr(x, 'second', 0) else "") if tem_hora else ""
        return f"{x.year:04d}-{x.month:02d}-{x.day:02d}{hora}"
        
    x = str(x).strip()
    x = re.sub(r"\.0$", "", x) # Prevenção contra anos interpretados como float (ex: "2024.0")
    
    m = _RX_DATA_ISO.match(x)
    if m:
        a, mes, dia = (int(g) for g in m.groups())
    else:
        m = _RX_DATA_BR.match(x)
        if not m:
            return x
        dia, mes, ano = int(m.group(1)), int(m.group(2)), m.group(3)
        a = int(ano) + (0 if len(ano) == 4 else (2000 if int(ano) < 30 else 1900))
        
    try:
        datetime.date(a, mes, dia)
    except ValueError:
        return x
    
    hora = ""
    resto = x[m.end():]
    if resto:
        hm = _RX_HORA.fullmatch(resto)
        if not hm:
            return x
        hh, mi = int(hm.group(1)), int(hm.group(2))
        ss = int(hm.group(3)) if hm.group(3) else None
        if hh > 23 or mi > 59 or (ss is not None and ss > 59):
            return x
        if not (hh == 0 and mi == 0 and not ss):
            hora = f" {hh:02d}:{mi:02d}" + (f":{ss:02d}" if ss is not None else "")
            
    return f"{a:04d}-{mes:02d}-{dia:02d}{hora}"

def _padroniza_tel(x):
    """Telefone para E.164 (+5511999998888). Com '+' ou prefixo 00, aceita qualquer país (8 a 15 dígitos).
    Sem prefixo, assume Brasil: DDD + 8 ou 9 dígitos (aceita o zero de tronco: 011...). O que não se encaixar
    fica como está."""
    if not isinstance(x, str):
        return x
    s = x.strip()
    d = re.sub(r"\D", "", s)
    if not d or not re.fullmatch(r"[\d\s().+\-]+", s):
        return x
    if s.startswith("+"):
        return "+" + d if 8 <= len(d) <= 15 else x
    if d.startswith("00"):
        d = d[2:]
        return "+" + d if 8 <= len(d) <= 15 else x
    if d.startswith("55") and len(d) in (12, 13) and d[2] != "0":
        return "+" + d
    if d.startswith("0") and len(d) in (11, 12):
        d = d[1:]
    if len(d) in (10, 11) and d[0] != "0" and d[1] != "0":
        return "+55" + d
    return x


_RX_MOEDA = re.compile(r"(?i)R\$|US\$|BRL|USD|EUR|[$€£]|\s")


def _padroniza_valor(x):
    """Valor monetário para número com ponto decimal, sem símbolo e sem milhar ('R$ 1.234,56' -> '1234.56').
    Com vírgula e ponto, o último é o decimal. Com um só separador seguido de exatamente 3 dígitos
    (1.234 ou 1,234), é tratado como milhar; nos demais casos, como decimal. '(10,50)' vira negativo.
    O que não for valor reconhecível fica como está."""
    if not isinstance(x, str):
        return x
    s = x.strip()
    neg = s.startswith("(") and s.endswith(")")
    if neg:
        s = s[1:-1]
    s = _RX_MOEDA.sub("", s)
    if s[:1] == "-":
        neg, s = True, s[1:]
    elif s[:1] == "+":
        s = s[1:]
    if not re.fullmatch(r"[\d.,]+", s) or not re.search(r"\d", s):
        return x
    if "." in s and "," in s:
        dec_sep = "," if s.rfind(",") > s.rfind(".") else "."
        mil = "." if dec_sep == "," else ","
        if s.count(dec_sep) != 1:
            return x
        inteiro, dec = s.split(dec_sep)
        if not re.fullmatch(r"\d{1,3}(?:" + re.escape(mil) + r"\d{3})*", inteiro):
            return x
        inteiro = inteiro.replace(mil, "")
    else:
        sep = "." if "." in s else ("," if "," in s else None)
        if sep is None:
            inteiro, dec = s, ""
        else:
            partes = s.split(sep)
            if len(partes) > 2:  # vários separadores iguais: só pode ser milhar
                if not (1 <= len(partes[0]) <= 3 and all(len(p) == 3 for p in partes[1:])):
                    return x
                inteiro, dec = "".join(partes), ""
            else:
                a, b = partes
                if len(b) == 3 and 1 <= len(a) <= 3 and not a.startswith("0"):
                    inteiro, dec = a + b, ""
                else:
                    inteiro, dec = a or "0", b
    if not inteiro.isdigit() or (dec and not dec.isdigit()):
        return x
    return ("-" if neg else "") + inteiro + ("." + dec if dec else "")


def _minuscula(x):
    return x.lower() if isinstance(x, str) else x


def _maiuscula(x):
    return x.upper() if isinstance(x, str) else x


def corrigir_dados(df, r):
    """r: {"espacos", "nulos": bool; "ids", "docs", "ceps", "datas", "tels", "valores",
    "minusculas", "maiusculas": listas de colunas}."""
    if r["espacos"] or r["nulos"]:
        for col in df.columns:
            if pd.api.types.is_object_dtype(df[col]) or pd.api.types.is_string_dtype(df[col]):
                if r["espacos"]:
                    df[col] = df[col].map(_limpa_espacos)
                if r["nulos"]:
                    df[col] = df[col].map(_para_nulo)
    for chave, fn in (("ids", _padroniza_id), ("docs", _padroniza_doc), ("ceps", _padroniza_cep),
                      ("datas", _padroniza_data), ("tels", _padroniza_tel),
                      ("minusculas", _minuscula), ("maiusculas", _maiuscula)):
        for col in r[chave]:
            if col in df.columns:
                df[col] = df[col].map(fn)
    for col in r["valores"]:
        if col in df.columns:
            df[col] = df[col].map(_padroniza_valor)
            try:  # se todos os valores são válidos, a coluna vira numérica (Excel reconhece como número)
                df[col] = pd.to_numeric(df[col])
            except (ValueError, TypeError):
                pass
    return df


def _diagnosticar_coluna(serie):
    """Retorna (contagens, problemas). Cada problema: (descrição, qtd, exemplos, sugestão)."""
    branco = serie.notna() & (serie.astype(str).str.strip() == "")
    txt = serie[serie.notna() & ~branco].astype(str)
    info = {"preenchidos": len(txt), "vazios": int(serie.isna().sum() + branco.sum()),
            "espacos": 0, "nulos": 0, "variacoes": 0, "formatos": None, "tamanho": 0,
            "tipo": "—", "fora_tipo": 0, "padrao": 0}
    prob = []
    if txt.empty:
        return info, prob

    # 1) Espaços extras
    m = (txt != txt.str.strip()) | txt.str.contains(r"\s{2,}", regex=True)
    if m.any():
        info["espacos"] = int(m.sum())
        prob.append(("Espaços extras (nas pontas ou duplicados)", info["espacos"],
                     _ex(txt[m].unique()), "Remova os espaços extras antes de anonimizar."))

    # 2) Nulos disfarçados (N/A, -, null...)
    m = txt.str.strip().str.lower().isin(_NULOS_DISFARCADOS)
    if m.any():
        info["nulos"] = int(m.sum())
        prob.append(("Nulos disfarçados (ex.: N/A, -, null)", info["nulos"],
                     _ex(txt[m].unique()), "Troque por célula vazia para tratar todos os ausentes do mesmo jeito."))

    # 3) Coluna de documento (CPF ou CNPJ, inclusive o alfanumérico)? Compara tamanho e formato
    limpo_doc = txt.str.upper().str.replace(r"[.\-/\s]", "", regex=True)
    tam = limpo_doc.str.len()
    forma_doc = txt.str.fullmatch(r"[0-9A-Za-z.\-/\s]+") & (
        limpo_doc.str.fullmatch(r"\d+") | limpo_doc.str.fullmatch(r"[0-9A-Z]{12}\d{2}"))
    dominante = int(tam[forma_doc].mode().iloc[0]) if forma_doc.any() else 0
    ok_doc = forma_doc & (tam == dominante)
    eh_doc = bool(forma_doc.mean() >= 0.6 and dominante in (11, 14) and ok_doc.mean() >= 0.6)
    if eh_doc:
        m = ~ok_doc
        if m.any():
            info["tamanho"] = int(m.sum())
            prob.append((f"Fora do padrão de documento da coluna ({dominante} caracteres)",
                         info["tamanho"], _ex(txt[m].unique()),
                         "Pode haver zeros à esquerda perdidos, números incompletos ou texto indevido."))
        # Conformidade com o padrão recomendado: guardar sem pontuação
        com_pont = txt.str.contains(r"[.\-/\s]", regex=True)
        if com_pont.any():
            n = int(com_pont.sum())
            info["padrao"] = max(info["padrao"], n)
            prob.append(("Documento com pontuação ou espaços (padrão recomendado: sem pontuação)", n,
                         _ex(txt[com_pont].unique()),
                         "Use 'Padronizar CPF/CNPJ (sem pontuação)' na barra lateral. A máscara "
                         "(000.000.000-00) deve ficar só na exibição."))
        # Dígitos verificadores
        mapa_valido = {v: _documento_valido(v) for v in limpo_doc.unique()}
        invalido = forma_doc & ~limpo_doc.map(mapa_valido).astype(bool)
        if invalido.any():
            n = int(invalido.sum())
            info["padrao"] = max(info["padrao"], n)
            prob.append(("Documento com dígito verificador inválido", n, _ex(txt[invalido].unique()),
                         "Confira se são números reais: valores fictícios, de teste ou digitados "
                         "errado não passam na validação."))

    # 3b) Tipo de dado predominante (número, data ou texto) e valores que destoam dele
    tipo_pred = "Documento (CPF/CNPJ)" if eh_doc else "Texto"
    if not eh_doc:
        limpo = txt.str.strip()
        base_num = limpo.str.replace(r"^(?:R\$|\$)\s*", "", regex=True)
        es_data = limpo.str.fullmatch(_RX_DATA)
        es_num = base_num.str.fullmatch(_RX_NUM) & ~es_data
        tipos = pd.Series("texto", index=txt.index)
        tipos[es_num] = "número"
        tipos[es_data] = "data"
        vc_t = tipos.value_counts()
        dom = vc_t.index[0]
        if vc_t.iloc[0] / len(txt) >= 0.8:
            tipo_pred = {"número": "Número", "data": "Data", "texto": "Texto"}[dom]
        else:
            tipo_pred = "Misto"  # sem tipo predominante (ex.: códigos alfanuméricos); não é acusado como erro

        if tipo_pred in ("Número", "Data"):
            m = tipos != dom
            if m.any():
                info["fora_tipo"] = int(m.sum())
                prob.append((f"Valores que não são do tipo predominante da coluna ({tipo_pred})",
                             info["fora_tipo"], _ex(txt[m].unique()),
                             "Corrija ou esvazie esses valores; eles podem quebrar cálculos e ordenações."))

        if tipo_pred == "Número":
            nums = base_num[es_num]
            virg = nums.str.contains(r",\d{1,2}$", regex=True)
            ponto = nums.str.contains(r"\.\d{1,2}$", regex=True)
            if virg.any() and ponto.any():
                info["formatos"] = 2
                prob.append(("Separador decimal misturado (vírgula e ponto)",
                             int(min(virg.sum(), ponto.sum())),
                             _ex(list(nums[virg].unique()[:2]) + list(nums[ponto].unique()[:2]), 4),
                             "Use um único separador decimal em toda a coluna."))

        if tipo_pred == "Data":
            partes = (limpo[es_data].str.split(r"[ T]", n=1, regex=True).str[0]
                      .str.replace(r"\d", "9", regex=True))
            vc_d = partes.value_counts()
            info["formatos"] = len(vc_d)
            if len(vc_d) > 1:
                detalhe = "; ".join(
                    f"{f} ({n}x, ex.: {repr(txt[es_data][partes == f].iloc[0][:40])})"
                    for f, n in vc_d.items())
                prob.append(("Formatos de data diferentes na mesma coluna", int(vc_d.iloc[1:].sum()),
                             detalhe, "Use um único formato de data (ex.: AAAA-MM-DD)."))
            nao_iso = ~limpo[es_data].str.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T].*)?")
            if nao_iso.any():
                n = int(nao_iso.sum())
                info["padrao"] = max(info["padrao"], n)
                prob.append(("Datas fora do padrão ISO 8601 (AAAA-MM-DD)", n,
                             _ex(txt[es_data][nao_iso].unique()),
                             "Use 'Padronizar datas (AAAA-MM-DD)' na barra lateral. Datas como 01/11/2026 "
                             "são lidas como DIA/MÊS/ANO."))

    # 3c) Colunas de e-mail, CEP e telefone (identificadas pelo conteúdo) e conformidade com o padrão
    if not eh_doc and tipo_pred in ("Texto", "Misto"):
        t = txt.str.strip()
        dig_t = t.str.replace(r"\D", "", regex=True).str.len()
        if t.str.contains("@", regex=False).mean() >= 0.6:
            tipo_pred = "E-mail"
            invalido = ~t.str.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+")
            if invalido.any():
                n = int(invalido.sum())
                info["padrao"] = max(info["padrao"], n)
                prob.append(("E-mails com formato inválido", n, _ex(txt[invalido].unique()),
                             "Confira se falta @, domínio ou se há espaços no meio."))
            maiusc = ~invalido & (t != t.str.lower())
            if maiusc.any():
                n = int(maiusc.sum())
                info["padrao"] = max(info["padrao"], n)
                prob.append(("E-mails com letras maiúsculas (padrão recomendado: minúsculas)", n,
                             _ex(txt[maiusc].unique()), "Use 'Converter para minúsculas' na barra lateral."))
        elif t.str.fullmatch(r"\d{5}-?\d{3}").mean() >= 0.6 and t.str.contains("-", regex=False).any():
            tipo_pred = "CEP"
            fora = ~t.str.fullmatch(r"\d{8}")
            if fora.any():
                n = int(fora.sum())
                info["padrao"] = max(info["padrao"], n)
                prob.append(("CEP fora do padrão (8 dígitos, sem hífen)", n, _ex(txt[fora].unique()),
                             "Use 'Padronizar CEP (8 dígitos)' na barra lateral."))
        elif (t.str.fullmatch(r"\+?[\d\s().\-]{8,20}") & dig_t.between(8, 15)).mean() >= 0.6 \
                and t.str.contains(r"[()\s+\-]", regex=True).any():
            tipo_pred = "Telefone"
            fora = ~t.str.fullmatch(r"\+\d{8,15}")
            if fora.any():
                n = int(fora.sum())
                info["padrao"] = max(info["padrao"], n)
                prob.append(("Telefone fora do padrão E.164 (+5511999998888)", n, _ex(txt[fora].unique()),
                             "Use 'Padronizar telefone (E.164)' na barra lateral."))
    info["tipo"] = tipo_pred

    # 4) Variações de escrita do mesmo valor (caixa, acentos, espaços; em documentos, pontuação)
    uniq = pd.Series(txt.unique())
    if eh_doc:
        chaves = uniq.str.upper().str.replace(r"[.\-/\s]", "", regex=True)
    else:
        chaves = uniq.map(lambda v: _sem_acento(" ".join(v.split())).casefold())
    grupos = uniq.groupby(chaves).agg(list)
    grupos = grupos[grupos.map(len) > 1]
    if len(grupos):
        info["variacoes"] = len(grupos)
        exemplos = " || ".join(" ≈ ".join(repr(x[:40]) for x in g[:3]) for g in list(grupos)[:2])
        prob.append(("Mesmo valor escrito de formas diferentes", len(grupos), exemplos,
                     "Padronize antes de anonimizar: a RANDOMIZAÇÃO (e o HASH, se a diferença for além de "
                     "maiúsculas/espaços nas pontas) gera códigos distintos para o mesmo dado."))

    # 5) Formatos misturados (só em colunas com dígitos ou e-mails, para não acusar texto livre)
    if tipo_pred not in ("Número", "Data", "Misto", "E-mail", "CEP", "Telefone") and txt.str.contains(r"\d|@", regex=True).mean() >= 0.5:
        formas = _forma(txt.str.strip())
        vc = formas.value_counts()
        if len(vc) <= 6:
            info["formatos"] = len(vc)
        if 2 <= len(vc) <= 6:
            detalhe = "; ".join(
                f"{f} ({n}x, ex.: {repr(txt[formas == f].iloc[0][:40])})" for f, n in vc.items())
            prob.append(("Formatos diferentes na mesma coluna", int(vc.iloc[1:].sum()), detalhe,
                         "Use um único formato (ex.: só dígitos); formatos diferentes geram "
                         "hashes/códigos diferentes para o mesmo dado."))
    return info, prob


@st.cache_data(ttl=600, max_entries=2, show_spinner=False)
def diagnosticar(nome, conteudo):
    """Lê tudo como texto (como será feito nas colunas tratadas) e verifica cada coluna."""
    buf = io.BytesIO(conteudo)
    # keep_default_na=False: sem isso o pandas já troca "N/A", "null" etc. por vazio e o problema some
    leitor = pd.read_csv if nome.lower().endswith(".csv") else pd.read_excel
    base = leitor(buf, dtype=str, keep_default_na=False)
    linhas, detalhes = [], {}
    for col in base.columns:
        info, prob = _diagnosticar_coluna(base[col])
        if info["preenchidos"] == 0:
            situacao = "— Coluna vazia"
        else:
            situacao = "⚠️ Atenção" if prob else "✅ Padronizada"
        linhas.append({
            "Coluna": str(col), "Tipo predominante": info["tipo"],
            "Preenchidos": info["preenchidos"], "Vazios": info["vazios"],
            "Espaços extras": info["espacos"], "Nulos disfarçados": info["nulos"],
            "Variações de escrita": info["variacoes"], "Formatos distintos": info["formatos"],
            "Documento fora do padrão": info["tamanho"], "Fora do tipo": info["fora_tipo"],
            "Fora do padrão recomendado": info["padrao"],
            "Situação": situacao,
        })
        if prob:
            detalhes[str(col)] = pd.DataFrame(prob, columns=["Problema", "Qtd.", "Exemplos", "Sugestão"])
    resumo = pd.DataFrame(linhas)
    resumo["Formatos distintos"] = pd.array(resumo["Formatos distintos"].tolist(), dtype="Int64")
    return resumo, detalhes


# ==========================================
# 3. INTERFACE
# ==========================================
def adicionar_fundo_local(opacidade=0.15):
    nomes = ["logo_tucanopay.png", "logo_tucanopay.jpg", "logo_tucanopay.jpeg",
             "logo_tucano.png", "logo_tucano.jpg"]
    pasta_script = os.path.dirname(os.path.abspath(__file__))
    caminho_imagem = next(
        (os.path.join(pasta_script, n) for n in nomes
         if os.path.exists(os.path.join(pasta_script, n))),
        None,
    )
    if not caminho_imagem:
        st.sidebar.warning("⚠️ Imagem do tucano não encontrada na pasta do script.")
        return

    codigo_imagem = imagem_base64(caminho_imagem)

    css = f"""
    <style>
    .stApp {{
        isolation: isolate;
    }}
    .stApp::before {{
        content: "";
        position: fixed;
        top: 0; right: 0; bottom: 0; left: 0;
        background-image: url("data:image/png;base64,{codigo_imagem}");
        background-repeat: no-repeat;
        background-position: center center;
        background-size: 500px auto;
        opacity: {opacidade};
        pointer-events: none;
        z-index: -1;
    }}
    /* Com a barra lateral aberta, centraliza na área principal (21rem = largura padrão) */
    .stApp:has([data-testid="stSidebar"][aria-expanded="true"])::before {{
        left: 21rem;
    }}
    @media (max-width: 768px) {{
        .stApp:has([data-testid="stSidebar"][aria-expanded="true"])::before {{
            left: 0;
        }}
    }}
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"],
    [data-testid="stHeader"] {{
        background: transparent !important;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def aviso_proxima_aba(nome_aba):
    """Banner grande e pulsante avisando que o resultado está na outra aba."""
    st.markdown(
        f"""
        <style>
        @keyframes pulsar {{
            0%   {{ box-shadow: 0 0 0 0 rgba(46, 160, 67, 0.65); }}
            70%  {{ box-shadow: 0 0 0 18px rgba(46, 160, 67, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(46, 160, 67, 0); }}
        }}
        @keyframes quicar {{
            0%, 100% {{ transform: translateY(0); }}
            50%      {{ transform: translateY(8px); }}
        }}
        .aviso-pronto {{
            background: linear-gradient(135deg, #1f8a3b, #2ea043);
            color: #ffffff;
            border-radius: 14px;
            padding: 22px 28px;
            margin: 8px 0 18px 0;
            text-align: center;
            animation: pulsar 1.8s ease-out 3;
        }}
        .aviso-pronto .titulo {{
            font-size: 1.6rem;
            font-weight: 800;
            margin-bottom: 6px;
        }}
        .aviso-pronto .texto {{
            font-size: 1.1rem;
        }}
        .aviso-pronto .texto b {{
            background: rgba(255, 255, 255, 0.22);
            padding: 2px 10px;
            border-radius: 6px;
        }}
        .aviso-pronto .seta {{
            display: block;
            font-size: 2rem;
            margin-top: 8px;
            animation: quicar 1s ease-in-out infinite;
        }}
        </style>
        <div class="aviso-pronto">
            <div class="titulo">✅ Anonimização concluída!</div>
            <div class="texto">
                Agora clique na aba <b>{nome_aba}</b> logo abaixo
                para conferir o resultado e baixar o arquivo.
            </div>
            <span class="seta">👇</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


adicionar_fundo_local()

st.title("🛡️ Anonimizador de Dados TucanoPay")
st.markdown("Ferramenta interna para ofuscação de dados sensíveis (LGPD).")
st.divider()

NOME_ABA_ANON = "Planilha Anonimizada"

df = None
conteudo = None
processar = False
erro_linhas = False
col_excluir, linhas_excluir, celulas_limpar = [], [], []
fix_espacos, fix_nulos = False, False
fix_lower, fix_upper, fix_doc, fix_data, fix_cep, fix_ids = [], [], [], [], [], []
fix_tel, fix_valor = [], []
col_hash, col_mask, col_rand, col_regex = [], [], [], []

with st.sidebar:
    st.header("⚙️ Configurações")
    uploaded_file = st.file_uploader(
        "1. Envie seu arquivo",
        type=["csv", "xlsx"],
        help="Formatos aceitos: CSV ou XLSX. Tamanho máximo: 200 MB por arquivo.",
    )

    if uploaded_file:
        st.success("Arquivo carregado!")
        st.markdown("---")

        conteudo = uploaded_file.getvalue()
        try:
            df = carregar(uploaded_file.name, conteudo)
        except Exception:
            st.error("Não foi possível ler o arquivo. Verifique se é um CSV ou XLSX válido.")
            st.stop()

        cols = list(df.columns)

        st.subheader("2. Excluir Colunas e Linhas")
        col_excluir = st.multiselect(
            "🗑️ EXCLUIR COLUNAS", cols,
            help="As colunas escolhidas serão removidas da planilha final.",
        )
        txt_linhas = st.text_input(
            "🗑️ EXCLUIR LINHAS",
            placeholder="Ex.: 1, 3, 5-10",
            help="Informe os números das linhas (a partir de 1, sem contar o cabeçalho), "
                 "separados por vírgula. Use hífen para intervalos. "
                 "A numeração é a mesma mostrada na aba 'Planilha Original'.",
        )
        linhas_excluir, invalidos, fora = parse_linhas(txt_linhas, len(df))
        if invalidos:
            erro_linhas = True
            st.error("Trecho(s) inválido(s): " + ", ".join(invalidos) +
                     ". Use o formato 1, 3, 5-10.")
        else:
            if fora:
                st.warning(f"Fora do intervalo (1 a {len(df)}), ajustado: " + ", ".join(fora))
            if linhas_excluir:
                st.caption(f"{len(linhas_excluir)} linha(s) serão excluídas.")

        # --- Células específicas (coluna + linha) ---
        st.markdown("**🧽 EXCLUIR CÉLULAS ESPECÍFICAS**")
        if st.session_state.get("celulas_arquivo") != uploaded_file.name:
            st.session_state["celulas_arquivo"] = uploaded_file.name
            st.session_state["celulas"] = []
            st.session_state["cel_msg"] = ""

        n_linhas = len(df)

        def _add_celula():
            col = st.session_state.get("cel_col")
            txt = (st.session_state.get("cel_lin") or "").strip()
            idxs, inv, _ = parse_linhas(txt, n_linhas)
            if col is None or inv or not idxs:
                st.session_state["cel_msg"] = "Informe uma linha válida, ex.: 2 ou 4-6."
                return
            st.session_state["celulas"].append((col, txt))
            st.session_state["cel_lin"] = ""
            st.session_state["cel_msg"] = ""

        def _rm_celula(i):
            if 0 <= i < len(st.session_state["celulas"]):
                st.session_state["celulas"].pop(i)

        st.selectbox("Coluna da célula", [c for c in cols if c not in col_excluir], key="cel_col")
        st.text_input("Linha(s) da célula", placeholder="Ex.: 2 ou 4-6", key="cel_lin",
                      help="Mesma numeração de 'Excluir linhas'. O conteúdo da célula fica vazio; "
                           "a linha e a coluna continuam na planilha.")
        st.button("➕ Adicionar célula(s)", on_click=_add_celula, use_container_width=True)
        if st.session_state.get("cel_msg"):
            st.error(st.session_state["cel_msg"])

        for i, (c, t) in enumerate(st.session_state["celulas"]):
            a, b = st.columns([5, 1])
            a.caption(f"{c} → linha(s) {t}")
            b.button("✖", key=f"cel_rm_{i}", on_click=_rm_celula, args=(i,))

        celulas_limpar = [
            (c, parse_linhas(t, n_linhas)[0])
            for c, t in st.session_state["celulas"] if c not in col_excluir
        ]

        st.markdown("---")
        # Colunas já excluídas não fazem sentido nas regras de mascaramento
        cols_disp = [c for c in cols if c not in col_excluir]

        st.subheader("3. Correções Automáticas")
        st.caption("Aplicadas antes da anonimização. Use a aba 🔍 Diagnóstico para ver o que precisa de ajuste.")
        fix_espacos = st.checkbox(
            "Remover espaços extras", help="Tira espaços no início/fim e duplicados no meio, em todas as colunas de texto.")
        fix_nulos = st.checkbox(
            "Trocar nulos disfarçados por vazio",
            help="Converte N/A, null, -, 'não informado' e células só com espaços em célula vazia, "
                 "em todas as colunas de texto. Atenção: um valor legítimo como 'NA' também seria apagado.")
        fix_doc = st.multiselect(
            "Padronizar CPF/CNPJ (sem pontuação)", cols_disp,
            help="Remove . - / e recompõe zeros à esquerda: só dígitos até 11 vira CPF (11), "
                 "de 12 a 14 vira CNPJ (14). CNPJ alfanumérico (14 caracteres, 2 últimos dígitos) é "
                 "mantido, em maiúsculas. Outros valores não são alterados.")
        fix_data = st.multiselect(
            "Padronizar datas (AAAA-MM-DD)", cols_disp,
            help="Converte para o formato ISO 8601. Datas com barra, ponto ou traço (31/01/2024) são lidas "
                 "como DIA/MÊS/ANO. Ano de 2 dígitos: 00-29 = 2000s, 30-99 = 1900s. A hora é mantida "
                 "(exceto 00:00). O que não for data válida fica como está.")
        fix_cep = st.multiselect(
            "Padronizar CEP (8 dígitos)", cols_disp,
            help="Remove o hífen e recompõe o zero à esquerda (01310-100 ou 1310100 viram 01310100).")
        fix_tel = st.multiselect(
            "Padronizar telefone (E.164)", cols_disp,
            help="Converte para +5511999998888. Com '+' ou 00 aceita qualquer país; sem prefixo, assume "
                 "Brasil (DDD + 8 ou 9 dígitos). O que não se encaixar fica como está.")
        fix_valor = st.multiselect(
            "Padronizar valores (ponto decimal)", cols_disp,
            help="'R$ 1.234,56' vira 1234.56 (sem símbolo nem milhar). Com vírgula e ponto, o último é o "
                 "decimal; um só separador com 3 dígitos depois (1.234) é lido como milhar. '(10,50)' vira "
                 "-10.50. Se todos os valores forem válidos, a coluna vira numérica.")
        fix_ids = st.multiselect(
            "Códigos/IDs (texto, sem espaços)", cols_disp,
            help="Lê a coluna como texto (preserva zeros à esquerda), remove espaços e tira o '.0' final "
                 "de IDs numéricos (123.0 vira 123).")
        fix_lower = st.multiselect(
            "Converter para minúsculas", cols_disp, help="Útil para e-mails. Não use em nomes.")
        fix_upper = st.multiselect(
            "Converter para MAIÚSCULAS", cols_disp, help="Útil para códigos. Não use em nomes.")

        st.markdown("---")
        st.subheader("4. Regras de Mascaramento")
        col_hash = st.multiselect("🔒 HASH (E-mails, IDs)", cols_disp)
        col_mask = st.multiselect("👁️ MÁSCARA (CPFs, Nomes)", cols_disp)
        col_rand = st.multiselect("🎲 RANDOMIZAÇÃO", cols_disp)
        col_regex = st.multiselect("📝 OCULTAR DADOS EM TEXTOS", cols_disp)

        st.markdown("---")
        processar = st.button("Aplicar Anonimização", type="primary", use_container_width=True)

config = {"hash": col_hash, "mask": col_mask, "random": col_rand, "regex": col_regex}
regras = {"espacos": fix_espacos, "nulos": fix_nulos, "minusculas": fix_lower, "maiusculas": fix_upper,
          "docs": fix_doc, "datas": fix_data, "ceps": fix_cep, "ids": fix_ids,
          "tels": fix_tel, "valores": fix_valor}

# Processamento (guarda o resultado no session_state para sobreviver aos reruns, ex.: ao baixar)
acabou_de_processar = False
if uploaded_file and processar:
    # Colunas tratadas são lidas como texto (preserva zeros à esquerda)
    selecionadas = tuple(sorted(set(
        col_hash + col_mask + col_rand + col_regex
        + fix_lower + fix_upper + fix_doc + fix_data + fix_cep + fix_ids + fix_tel + fix_valor)))
    if erro_linhas:
        st.sidebar.error("Corrija o campo 'Excluir linhas' antes de continuar.")
    elif not (selecionadas or col_excluir or linhas_excluir or celulas_limpar or fix_espacos or fix_nulos):
        st.sidebar.warning("Selecione ao menos uma coluna para anonimizar, algo para excluir ou "
                           "uma correção. Nada foi alterado.")
    elif len(col_excluir) >= len(df.columns):
        st.sidebar.error("Você marcou todas as colunas para exclusão. Mantenha ao menos uma.")
    else:
        todas = col_hash + col_mask + col_rand + col_regex
        if len(todas) != len(set(todas)):
            st.sidebar.warning("Há colunas em mais de uma regra; elas serão tratadas em sequência.")
        df_full = carregar(uploaded_file.name, conteudo, selecionadas)
        # 1º esvazia células e exclui colunas/linhas (posições de linha valem para a planilha original);
        # 2º anonimiza
        df_full = limpar_celulas(df_full, celulas_limpar)
        df_full = excluir_colunas_linhas(df_full, col_excluir, linhas_excluir)
        df_full = corrigir_dados(df_full, regras)
        df_anon = neutralizar_formulas(anon_dataset(df_full.copy(), config))

        xlsx = io.BytesIO()
        df_anon.to_excel(xlsx, index=False, engine="openpyxl")

        correcoes = []
        if fix_espacos:
            correcoes.append("espaços extras removidos")
        if fix_nulos:
            correcoes.append("nulos padronizados")
        for lista, texto in ((fix_doc, "CPF/CNPJ"), (fix_data, "datas"), (fix_cep, "CEP"),
                             (fix_ids, "códigos/IDs"), (fix_tel, "telefone"),
                             (fix_valor, "valores monetários"), (fix_lower, "minúsculas"),
                             (fix_upper, "MAIÚSCULAS")):
            if lista:
                correcoes.append(f"{texto} em {len(lista)} coluna(s)")

        st.session_state["resultado"] = {
            "arquivo": uploaded_file.name,
            "df": df_anon,
            "xlsx": xlsx.getvalue(),
            "csv": df_anon.to_csv(index=False, sep=";").encode("utf-8-sig"),
            "resumo": (f"{len(col_excluir)} coluna(s) e {len(linhas_excluir)} linha(s) excluída(s); "
                       f"{sum(len(i) for _, i in celulas_limpar)} célula(s) esvaziada(s)."
                       + (" Correções: " + ", ".join(correcoes) + "." if correcoes else "")),
        }
        acabou_de_processar = True
        st.sidebar.success(f"✅ Concluído! Vá para a aba '{NOME_ABA_ANON}'.")
        st.toast(f"Processamento concluído! Abra a aba '{NOME_ABA_ANON}'.", icon="👉")

if uploaded_file and df is not None:
    res = st.session_state.get("resultado")
    pronto = bool(res and res["arquivo"] == uploaded_file.name)

    # Aviso grande, logo acima das abas, só no momento em que o processamento termina
    if acabou_de_processar:
        aviso_proxima_aba(f"✅ {NOME_ABA_ANON}")

    aba1, aba2, aba3 = st.tabs([
        "Planilha Original",
        f"✅ {NOME_ABA_ANON}" if pronto else NOME_ABA_ANON,
        "🔍 Diagnóstico",
    ])

    with aba1:
        st.info("Pré-visualização dos dados carregados antes do tratamento. "
                "A numeração à esquerda é a usada em 'Excluir linhas'.")
        st.dataframe(prever(df), use_container_width=True)

    with aba2:
        if pronto:
            st.success("✅ Dados processados com sucesso! " + res["resumo"])
            st.dataframe(prever(res["df"]), use_container_width=True)

            st.markdown("### 📥 Escolha o formato para baixar:")
            c1, c2 = st.columns(2)
            c1.download_button(
                "⬇️ Baixar em Excel (.xlsx)", res["xlsx"], "TucanoPay_Anonimizada.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary", use_container_width=True, on_click="ignore",
            )
            c2.download_button(
                "⬇️ Baixar em CSV (.csv)", res["csv"], "TucanoPay_Anonimizada.csv",
                mime="text/csv", type="primary", use_container_width=True, on_click="ignore",
            )
        else:
            st.info("Escolha as colunas e clique em 'Aplicar Anonimização'.")

    with aba3:
        st.info("Verifica, coluna por coluna, se os dados da planilha original estão padronizados "
                "(espaços, caixa/acentos, formatos, nulos disfarçados, dígitos de CPF/CNPJ) e se os "
                "tipos estão corretos (número, data ou texto). Também confere se seguem o padrão recomendado "
                "(CPF/CNPJ sem pontuação e com dígito verificador válido, data ISO, e-mail em minúsculas, "
                "CEP de 8 dígitos, telefone E.164). Rode antes de anonimizar; o que for "
                "simples de corrigir pode ser tratado em '3. Correções Automáticas' na barra lateral. "
                "Os exemplos mostram valores reais da planilha original.")
        if st.button("🔍 Executar diagnóstico", key="btn_diag"):
            with st.spinner("Analisando as colunas..."):
                resumo, detalhes = diagnosticar(uploaded_file.name, conteudo)
            st.session_state["diagnostico"] = {
                "arquivo": uploaded_file.name, "resumo": resumo, "detalhes": detalhes,
            }

        diag = st.session_state.get("diagnostico")
        if diag and diag["arquivo"] == uploaded_file.name:
            resumo, detalhes = diag["resumo"], diag["detalhes"]
            n_atencao = int((resumo["Situação"] == "⚠️ Atenção").sum())
            if n_atencao == 0:
                st.success("✅ Nenhum problema de padronização encontrado nas colunas preenchidas.")
            else:
                st.warning(f"⚠️ {n_atencao} de {len(resumo)} coluna(s) precisam de atenção. "
                           "Veja os detalhes abaixo.")
            st.dataframe(resumo, use_container_width=True, hide_index=True)
            for col, det in detalhes.items():
                with st.expander(f"⚠️ {col}"):
                # st.table força a quebra de linha do texto; hide(axis="index") remove os números 0, 1, 2 da lateral
                    st.table(det.style.hide(axis="index"))
        else:
            st.caption("Clique em 'Executar diagnóstico' para analisar a planilha.")
else:
    st.info("👈 Por favor, faça o upload de um arquivo na barra lateral para começar.")
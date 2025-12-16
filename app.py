import os
import time
import hmac
import json
import uuid
import hashlib
import urllib.parse
import unicodedata
import re
import subprocess
from typing import Dict, Any, List, Optional, Tuple

import requests
import pandas as pd
import streamlit as st
from difflib import SequenceMatcher
from supabase import create_client, Client


# ==========================
# Configurações Gerais
# ==========================
# Conforme a documentação da Shopee Open Platform v2, o host base não inclui
# o caminho "/api/v2"; esse prefixo faz parte do path de cada endpoint.
# Mantemos apenas o domínio aqui para evitar URLs do tipo
# ".../api/v2/api/v2/product/...", que resultam em HTTP 404.
#
# Por padrão usamos o host de produção do Brasil (Open Platform BR). A Shopee
# mantém hosts diferentes por região (ex.: Brasil vs Global vs China).
# Para lojas fora do BR, ajuste o host pela interface (campo "API Base URL").
#
# Referência (docs v2): URLs variam por região, ex.:
# - Brasil: https://openplatform.shopee.com.br/api/v2/...
# - Global: https://partner.shopeemobile.com/api/v2/...
BASE_URL = "https://openplatform.shopee.com.br"
GLOBAL_BASE_URL = "https://partner.shopeemobile.com"
SANDBOX_BASE_URL = "https://openplatform.sandbox.test-stable.shopee.sg"
GROUPS_FILE = "groups.json"
TOKENS_FILE = "tokens.json"
CREDS_FILE = "razaiestoque.txt"


def _get_secret_or_env(*keys: str) -> Optional[str]:
    """Lê configuração em ordem: st.secrets -> env.

    Evita quebrar import/exec fora do Streamlit: se `st.secrets` não estiver
    disponível, apenas ignora e tenta env.
    """
    for k in keys:
        # 1) Streamlit secrets
        try:
            # st.secrets funciona como mapping
            v = st.secrets.get(k)  # type: ignore[attr-defined]
        except Exception:
            v = None
        if v is not None:
            s = str(v).strip()
            if s:
                return s

        # 2) Environment
        v2 = os.getenv(k)
        if v2:
            s2 = str(v2).strip()
            if s2:
                return s2
    return None


def _groups_remote_config() -> Dict[str, str]:
    """Configuração do backend remoto para grupos.

    Ative definindo `GROUPS_REMOTE_URL` (em `st.secrets` ou env).
    Opcional:
    - GROUPS_REMOTE_TOKEN (Bearer)
    - GROUPS_REMOTE_READ_METHOD (GET por padrão)
    - GROUPS_REMOTE_WRITE_METHOD (PUT por padrão)
    - GROUPS_REMOTE_TIMEOUT (segundos, default 15)
    """
    url = _get_secret_or_env("GROUPS_REMOTE_URL")
    if not url:
        return {}

    cfg: Dict[str, str] = {
        "url": url,
        "token": _get_secret_or_env("GROUPS_REMOTE_TOKEN") or "",
        "read_method": (_get_secret_or_env("GROUPS_REMOTE_READ_METHOD") or "GET").upper(),
        "write_method": (_get_secret_or_env("GROUPS_REMOTE_WRITE_METHOD") or "PUT").upper(),
        "timeout": _get_secret_or_env("GROUPS_REMOTE_TIMEOUT") or "15",
    }
    return cfg


def _parse_groups_payload(data: Any) -> List[Dict[str, Any]]:
    # Suporte tanto para lista direta quanto para {"groups": [...]}.
    if isinstance(data, dict) and "groups" in data:
        return data.get("groups") or []
    if isinstance(data, list):
        return data
    return []


def _remote_load_groups() -> List[Dict[str, Any]]:
    cfg = _groups_remote_config()
    if not cfg:
        return []

    headers: Dict[str, str] = {"Accept": "application/json"}
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"

    method = cfg.get("read_method", "GET")
    timeout = float(cfg.get("timeout") or 15)

    try:
        if method == "GET":
            resp = requests.get(cfg["url"], headers=headers, timeout=timeout)
        elif method == "POST":
            resp = requests.post(cfg["url"], headers=headers, timeout=timeout)
        else:
            raise RuntimeError(f"GROUPS_REMOTE_READ_METHOD inválido: {method}")

        # Permite URL vazia (sem registro) começar como lista vazia
        if resp.status_code == 404:
            return []

        resp.raise_for_status()
        payload = resp.json()
        return _parse_groups_payload(payload)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Falha ao carregar groups do backend remoto: {exc}")


def _remote_save_groups(groups: List[Dict[str, Any]]) -> None:
    cfg = _groups_remote_config()
    if not cfg:
        raise RuntimeError("Backend remoto de grupos não configurado")

    headers: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"

    method = cfg.get("write_method", "PUT")
    timeout = float(cfg.get("timeout") or 15)
    payload = {"groups": groups}

    try:
        if method == "PUT":
            resp = requests.put(cfg["url"], headers=headers, json=payload, timeout=timeout)
        elif method == "POST":
            resp = requests.post(cfg["url"], headers=headers, json=payload, timeout=timeout)
        else:
            raise RuntimeError(f"GROUPS_REMOTE_WRITE_METHOD inválido: {method}")
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Falha ao salvar groups no backend remoto: {exc}")


# ==========================
# Utilidades de Persistência Local (JSON)
# ==========================

def _get_supabase_client() -> Optional[Client]:
    """Retorna cliente Supabase se configurado (Secrets, Env ou Hardcoded fallback)."""
    url = st.secrets.get("SUPABASE_URL") or os.environ.get("SUPABASE_URL")
    key = st.secrets.get("SUPABASE_KEY") or os.environ.get("SUPABASE_KEY")
    
    # Fallback com as credenciais fornecidas (idealmente mover para st.secrets em prod)
    if not url:
        url = "https://kptxikvuwuyqhpszcaup.supabase.co"
    if not key:
        key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtwdHhpa3Z1d3V5cWhwc3pjYXVwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjU4OTgwMDgsImV4cCI6MjA4MTQ3NDAwOH0.SeawBT8uein7ZIzAj-ZlfBaVJuH1mkGij3cEW5WvmgA"

    if url and key:
        try:
            return create_client(url, key)
        except Exception:
            return None
    return None


def load_groups() -> List[Dict[str, Any]]:
    """Carrega grupos de produtos (Supabase > Local)."""
    # 1. Tenta Supabase
    sb = _get_supabase_client()
    if sb:
        try:
            response = sb.table("razai_storage").select("value").eq("key", "groups").execute()
            if response.data and len(response.data) > 0:
                data = response.data[0]["value"]
                return _parse_groups_payload(data)
        except Exception:
            # Silenciosamente falha para local se der erro (ex: offline)
            pass

    # Se configurado, usa backend remoto (legacy)
    if _groups_remote_config():
        return _remote_load_groups()

    if not os.path.exists(GROUPS_FILE):
        return []

    try:
        with open(GROUPS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    return _parse_groups_payload(data)


def save_groups(groups: List[Dict[str, Any]]) -> None:
    """Salva grupos de produtos (Supabase + Local)."""
    payload = {"groups": groups}

    # 1. Tenta Supabase (Upsert)
    sb = _get_supabase_client()
    if sb:
        try:
            data = {"key": "groups", "value": payload}
            sb.table("razai_storage").upsert(data).execute()
        except Exception as e:
            print(f"Erro ao salvar no Supabase: {e}")

    # Se configurado, salva no backend remoto (legacy)
    if _groups_remote_config():
        _remote_save_groups(groups)
        return

    # 2. Salva Local
    with open(GROUPS_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_tokens() -> Dict[str, Any]:
    """Carrega tokens persistidos (tokens.json)."""
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_tokens(tokens: Dict[str, Any]) -> None:
    """Salva tokens em tokens.json."""
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)


def git_persist_data() -> str:
    """Salva groups.json e tokens.json no repositório Git local (commit + push)."""
    files_to_add = []
    if os.path.exists(GROUPS_FILE):
        files_to_add.append(GROUPS_FILE)
    if os.path.exists(TOKENS_FILE):
        files_to_add.append(TOKENS_FILE)

    if not files_to_add:
        return "Nenhum arquivo de dados encontrado para salvar."

    try:
        # 1. Add (force para garantir)
        cmd = ["git", "add", "-f"] + files_to_add
        subprocess.run(cmd, check=True, capture_output=True)
        
        # 2. Check status
        status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
        if not status.stdout.strip():
            return "Nenhuma alteração pendente nos dados."

        # 3. Commit
        subprocess.run(["git", "commit", "-m", "Update data (groups/tokens) via App"], check=True, capture_output=True)
        
        # 4. Push
        subprocess.run(["git", "push"], check=True, capture_output=True)
        
        return "Sucesso: Dados salvos e enviados ao Git!"
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode() if e.stderr else str(e)
        return f"Erro no Git: {err_msg}"
    except Exception as exc:
        return f"Erro inesperado ao salvar no Git: {exc}"


def git_pull_data() -> str:
    """Atualiza o repositório local com as mudanças do remoto (git pull)."""
    try:
        subprocess.run(["git", "pull"], check=True, capture_output=True)
        return "Sucesso: Repositório atualizado do GitHub!"
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode() if e.stderr else str(e)
        return f"Erro no Git Pull: {err_msg}"
    except Exception as exc:
        return f"Erro inesperado ao atualizar do Git: {exc}"


def _validate_imported_groups_payload(payload: Any) -> List[Dict[str, Any]]:
    """Valida minimamente um payload de importação de grupos.

    Aceita:
    - lista direta de grupos
    - {"groups": [...]}.

    Mantém compatibilidade e evita travar por campos extras.
    """
    groups = _parse_groups_payload(payload)
    if not isinstance(groups, list):
        raise ValueError("Payload inválido: groups não é lista")

    out: List[Dict[str, Any]] = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        items = g.get("items")
        if items is None:
            # grupos antigos/alternativos: sem items não ajuda no app
            continue
        if not isinstance(items, list):
            continue

        # Campos obrigatórios mínimos
        master_name = str(g.get("master_name") or "").strip()
        group_id = str(g.get("group_id") or "").strip()
        if not master_name:
            continue
        if not group_id:
            # Se vier sem id, cria um novo para manter consistência
            g = dict(g)
            g["group_id"] = str(uuid.uuid4())

        out.append(g)

    return out


def refresh_group_names_from_models_cache(
    groups: List[Dict[str, Any]],
    models_cache: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """Atualiza item_name/model_name dentro dos grupos com base no cache atual.

    Mantém o vínculo por IDs (item_id + model_id). Retorna (groups_atualizados, qtd_itens_atualizados).
    """
    index: Dict[Tuple[int, Optional[int]], Dict[str, str]] = {}
    for m in models_cache:
        try:
            iid = int(m.get("item_id"))
        except Exception:
            continue
        mid = m.get("model_id")
        index[(iid, mid)] = {
            "item_name": str(m.get("item_name") or ""),
            "model_name": str(m.get("model_name") or ""),
        }

    updated_count = 0
    new_groups: List[Dict[str, Any]] = []
    for g in groups:
        g2 = dict(g)
        items = list(g2.get("items") or [])
        new_items: List[Dict[str, Any]] = []
        changed = False

        for it in items:
            if not isinstance(it, dict):
                continue
            it2 = dict(it)
            try:
                iid = int(it2.get("item_id"))
            except Exception:
                new_items.append(it2)
                continue
            mid = it2.get("model_id")
            rec = index.get((iid, mid))
            if rec:
                old_item = str(it2.get("item_name") or "")
                old_model = str(it2.get("model_name") or "")
                if rec.get("item_name") and rec["item_name"] != old_item:
                    it2["item_name"] = rec["item_name"]
                    changed = True
                    updated_count += 1
                if rec.get("model_name") != old_model:
                    it2["model_name"] = rec["model_name"]
                    changed = True
                    updated_count += 1
            new_items.append(it2)

        g2["items"] = new_items

        # Recalcula shopee_item_ids/model_ids para manter consistência
        try:
            g2["shopee_item_ids"] = sorted({int(i.get("item_id")) for i in new_items if i.get("item_id") is not None})
        except Exception:
            pass
        try:
            g2["shopee_model_ids"] = sorted(
                {
                    int(i.get("model_id"))
                    for i in new_items
                    if i.get("model_id") is not None
                }
            )
        except Exception:
            pass

        new_groups.append(g2 if changed else g)

    return new_groups, updated_count


def load_test_credentials_from_file() -> Dict[str, Any]:
    """Lê credenciais (Sandbox e Live) do arquivo de texto local.

    O arquivo `razaiestoque.txt` é tratado **somente para leitura**, nunca é
    modificado. Usamos campos conhecidos para preencher automaticamente a sidebar.

    Campos reconhecidos:
    - Sandbox/Test: Test API Partner Key, Test Partner_id, Shop ID, AccessTokenTest
    - Live/Produção: Live API Partner Key, Live Partner_id, Shop Live ID, redirect com shop_id
    """
    if not os.path.exists(CREDS_FILE):
        return {}

    def _value_after_colon(text: str) -> Optional[str]:
        # Aceita ":" e "：" (dois pontos full-width, comum em cópias)
        for sep in (":", "："):
            if sep in text:
                return text.split(sep, 1)[1].strip()
        return None

    test_partner_key: Optional[str] = None
    test_partner_id: Optional[str] = None
    test_shop_id: Optional[str] = None
    test_access_token: Optional[str] = None

    live_partner_key: Optional[str] = None
    live_partner_id: Optional[str] = None
    live_shop_id: Optional[str] = None

    try:
        with open(CREDS_FILE, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                lower = line.lower()

                # Sandbox/Test
                if lower.startswith("test api partner key"):
                    test_partner_key = _value_after_colon(line) or test_partner_key
                elif lower.startswith("test partner_id") or lower.startswith("test partner id"):
                    test_partner_id = _value_after_colon(line) or test_partner_id
                elif lower.startswith("shop id"):
                    # No arquivo atual, "Shop ID" refere-se ao sandbox.
                    test_shop_id = _value_after_colon(line) or test_shop_id
                elif lower.startswith("accesstokentest"):
                    test_access_token = _value_after_colon(line) or test_access_token
                elif lower.startswith("test access token"):
                    test_access_token = _value_after_colon(line) or test_access_token

                # Live/Produção
                elif lower.startswith("live api partner key"):
                    live_partner_key = _value_after_colon(line) or live_partner_key
                elif lower.startswith("live partner_id") or lower.startswith("live partner id"):
                    live_partner_id = _value_after_colon(line) or live_partner_id
                elif lower.startswith("shop live id"):
                    value = (_value_after_colon(line) or "").strip()
                    if value:
                        live_shop_id = value
                elif "shop_id=" in lower and lower.startswith("http"):
                    # Ex.: https://.../?code=...&shop_id=803215808
                    try:
                        parsed = urllib.parse.urlparse(line)
                        qs = urllib.parse.parse_qs(parsed.query)
                        sid = (qs.get("shop_id") or [None])[0]
                        if sid:
                            live_shop_id = str(sid)
                    except Exception:
                        # Melhor esforço; ignorar se falhar parsing
                        pass
    except Exception:
        # Se algo der errado na leitura/parsing, apenas retornamos vazio
        return {}

    creds: Dict[str, Any] = {}

    if test_partner_key:
        creds["test_partner_key"] = test_partner_key
    if test_partner_id:
        creds["test_partner_id"] = test_partner_id
    if test_shop_id:
        creds["test_shop_id"] = test_shop_id
    if test_access_token:
        creds["test_access_token"] = test_access_token

    if live_partner_key:
        creds["live_partner_key"] = live_partner_key
    if live_partner_id:
        creds["live_partner_id"] = live_partner_id
    if live_shop_id:
        creds["live_shop_id"] = live_shop_id

    return creds


def load_credentials_from_env() -> Dict[str, Any]:
    """Lê credenciais (opcionais) de variáveis de ambiente.

    Útil para produção/Streamlit Cloud (ex.: st.secrets -> env) sem salvar nada em disco.

    Variáveis suportadas:
    - SHOPEE_PARTNER_ID
    - SHOPEE_PARTNER_KEY
    - SHOPEE_SHOP_ID
    - SHOPEE_ACCESS_TOKEN
    - SHOPEE_REFRESH_TOKEN
    - SHOPEE_REDIRECT_URL
    - SHOPEE_API_BASE_URL
    """
    mapping = {
        "partner_id": "SHOPEE_PARTNER_ID",
        "partner_key": "SHOPEE_PARTNER_KEY",
        "shop_id": "SHOPEE_SHOP_ID",
        "access_token": "SHOPEE_ACCESS_TOKEN",
        "refresh_token": "SHOPEE_REFRESH_TOKEN",
        "redirect_url": "SHOPEE_REDIRECT_URL",
        "api_base_url": "SHOPEE_API_BASE_URL",
    }
    creds: Dict[str, Any] = {}
    for key, env_name in mapping.items():
        value = os.getenv(env_name)
        if value:
            creds[key] = value
    return creds


def load_credentials_from_streamlit_secrets() -> Dict[str, Any]:
    """Lê credenciais (opcionais) do Streamlit Cloud via `st.secrets`.

    O Streamlit Cloud recomenda armazenar segredos em `st.secrets`.
    Aceita tanto as chaves no formato SHOPEE_* quanto chaves simples.

    Exemplos (Secrets):
    - SHOPEE_PARTNER_ID = "..."
    - SHOPEE_PARTNER_KEY = "..."
    - SHOPEE_SHOP_ID = "..."
    - SHOPEE_ACCESS_TOKEN = "..."  (opcional; preferível obter via OAuth)
    - SHOPEE_REFRESH_TOKEN = "..." (recomendado; permite login sem reautorizar)
    - SHOPEE_REDIRECT_URL = "https://razaiestoque.streamlit.app/" (precisa bater com o Redirect URL do Open Platform)
    - SHOPEE_API_BASE_URL = "https://openplatform.shopee.com.br"
    """
    try:
        secrets = st.secrets  # type: ignore[attr-defined]
    except Exception:
        return {}

    def _get(*keys: str) -> Optional[str]:
        for k in keys:
            try:
                v = secrets.get(k)  # type: ignore[call-arg]
            except Exception:
                v = None
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s
        return None

    creds: Dict[str, Any] = {}
    partner_id = _get("SHOPEE_PARTNER_ID", "partner_id")
    partner_key = _get("SHOPEE_PARTNER_KEY", "partner_key")
    shop_id = _get("SHOPEE_SHOP_ID", "shop_id")
    access_token = _get("SHOPEE_ACCESS_TOKEN", "access_token")
    refresh_token = _get("SHOPEE_REFRESH_TOKEN", "refresh_token")
    redirect_url = _get("SHOPEE_REDIRECT_URL", "redirect_url", "redirect_uri")
    api_base_url = _get("SHOPEE_API_BASE_URL", "api_base_url")

    if partner_id:
        creds["partner_id"] = partner_id
    if partner_key:
        creds["partner_key"] = partner_key
    if shop_id:
        creds["shop_id"] = shop_id
    if access_token:
        creds["access_token"] = access_token
    if refresh_token:
        creds["refresh_token"] = refresh_token
    if redirect_url:
        creds["redirect_url"] = redirect_url
    if api_base_url:
        creds["api_base_url"] = api_base_url

    return creds


# ==========================
# Cliente da API Shopee V2
# ==========================

class ShopeeClient:
    """Cliente mínimo para Shopee Open Platform API v2.

    Baseado na documentação oficial (Shopee Open Platform Developer Guide, seção
    "API Authorization" e "Product > Update Stock").

    - Autenticação v2 (user-level):
      sign_base_string = partner_id + path + timestamp + access_token + shop_id
      sign = HMAC-SHA256(partner_key, sign_base_string).hexdigest()

    - Query padrão: partner_id, timestamp, sign, shop_id, access_token
    """

    def __init__(
        self,
        partner_id: int,
        partner_key: str,
        shop_id: int,
        access_token: str,
        base_url: str = BASE_URL,
    ) -> None:
        self.partner_id = int(partner_id)
        self.partner_key = partner_key
        self.shop_id = int(shop_id)
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")

    def _sign(self, path: str, timestamp: int) -> str:
        """Gera assinatura HMAC-SHA256 conforme documentação Shopee v2.

        path deve ser somente o caminho absoluto da API, ex:
        "/api/v2/product/get_item_list".
        """
        base_string = f"{self.partner_id}{path}{timestamp}{self.access_token}{self.shop_id}"
        digest = hmac.new(
            self.partner_key.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return digest

    def _sign_partner_only(self, path: str, timestamp: int) -> str:
        """Assinatura HMAC-SHA256 para endpoints de auth (sem access_token/shop_id).

        Conforme docs v2 do token:
        sign_base_string = partner_id + path + timestamp
        """
        base_string = f"{self.partner_id}{path}{timestamp}"
        digest = hmac.new(
            self.partner_key.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return digest

    def _make_partner_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Requisição assinada apenas com partner_id (usada em OAuth/token)."""
        if params is None:
            params = {}

        ts = int(time.time())
        sign = self._sign_partner_only(path, ts)
        params.update({"partner_id": self.partner_id, "timestamp": ts, "sign": sign})

        url = f"{self.base_url}{path}"
        method = method.upper()

        try:
            if method == "GET":
                resp = requests.get(url, params=params, timeout=timeout)
            else:
                headers = {"Content-Type": "application/json"}
                resp = requests.post(
                    url,
                    params=params,
                    json=body or {},
                    headers=headers,
                    timeout=timeout,
                )
        except requests.RequestException as exc:
            raise RuntimeError(f"Erro de conexão com Shopee: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            raise RuntimeError(f"Resposta inválida da Shopee (não JSON): {resp.text[:200]}")

        if resp.status_code != 200:
            raise RuntimeError(
                f"HTTP {resp.status_code} da Shopee: {data.get('error')} - {data.get('message')} | response={data}"
            )

        if data.get("error") not in (None, ""):
            raise RuntimeError(
                f"Erro na API Shopee: {data.get('error')} - {data.get('message')} | response={data}"
            )

        return data

    # ---------- OAuth / Token ----------

    def build_authorize_url(self, redirect_url: str) -> str:
        """Gera URL de autorização (Authorize Live Partner) para obter `code`.

        Esse passo é o que gera o `code` (uso único) e redireciona para o `redirect_url`
        com `?code=...&shop_id=...`.

        Observação: o nome do parâmetro de callback no authorize é `redirect` (v2).
        """
        path = "/api/v2/shop/auth_partner"
        ts = int(time.time())
        sign = self._sign_partner_only(path, ts)
        params = {
            "partner_id": self.partner_id,
            "timestamp": ts,
            "sign": sign,
            "redirect": str(redirect_url).strip(),
        }
        return f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_token(self, code: str, shop_id: int, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Troca `code` por access_token/refresh_token (v2.public.get_access_token)."""
        path = "/api/v2/auth/token/get"
        body = {"partner_id": self.partner_id, "code": str(code), "shop_id": int(shop_id)}
        if redirect_uri:
            body["redirect_uri"] = str(redirect_uri)
        return self._make_partner_request("POST", path, body=body)

    def refresh_access_token(self, refresh_token: str, shop_id: int) -> Dict[str, Any]:
        """Renova access_token usando refresh_token (v2.public.refresh_access_token)."""
        path = "/api/v2/auth/access_token/get"
        body = {
            "partner_id": self.partner_id,
            "refresh_token": str(refresh_token),
            "shop_id": int(shop_id),
        }
        return self._make_partner_request("POST", path, body=body)

    def _make_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Executa requisição HTTP assinada à Shopee, com tratamento básico de erro."""
        if params is None:
            params = {}

        ts = int(time.time())
        sign = self._sign(path, ts)

        # Parâmetros obrigatórios de autenticação (conforme docs Shopee v2)
        auth_params = {
            "partner_id": self.partner_id,
            "timestamp": ts,
            "sign": sign,
            "shop_id": self.shop_id,
            "access_token": self.access_token,
        }
        params.update(auth_params)

        url = f"{self.base_url}{path}"
        method = method.upper()

        try:
            if method == "GET":
                resp = requests.get(url, params=params, timeout=timeout)
            else:
                headers = {"Content-Type": "application/json"}
                resp = requests.post(
                    url,
                    params=params,
                    json=body or {},
                    headers=headers,
                    timeout=timeout,
                )
        except requests.RequestException as exc:
            raise RuntimeError(f"Erro de conexão com Shopee: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            raise RuntimeError(f"Resposta inválida da Shopee (não JSON): {resp.text[:200]}")

        # Conforme docs, campos comuns: error, message
        if resp.status_code != 200:
            raise RuntimeError(
                f"HTTP {resp.status_code} da Shopee: {data.get('error')} - {data.get('message')} | response={data}"
            )

        if data.get("error") not in (None, ""):
            raise RuntimeError(
                f"Erro na API Shopee: {data.get('error')} - {data.get('message')} | response={data}"
            )

        return data

    def preflight_read_check(self, sample_item_id: Optional[int] = None) -> Dict[str, Any]:
        """Faz um teste de requisição (somente leitura) antes de operações sensíveis.

        Objetivo: detectar cedo problemas de credencial/host/permissão e também
        entender se a API está devolvendo estoque nos campos esperados.

        Retorna um resumo com:
        - sample_item_id
        - item_base_info_keys
        - model_keys (primeiro model)
        - stock_fields_found (quais campos de estoque aparecem)
        """
        # 1) Descobrir um item para testar
        if sample_item_id is None:
            items = self.get_item_list()
            if not items:
                raise RuntimeError("Preflight: get_item_list retornou vazio")
            try:
                sample_item_id = int(items[0].get("item_id"))
            except Exception:
                raise RuntimeError("Preflight: item_id inválido no get_item_list")

        def _to_int_or_none(v: Any) -> Optional[int]:
            if v is None:
                return None
            try:
                return int(v)
            except Exception:
                try:
                    return int(float(v))
                except Exception:
                    return None

        def _sum_seller_stock_locations(v: Any) -> Optional[int]:
            """Soma seller_stock/shopee_stock quando vem como lista por location.

            Cada entry costuma ter: {location_id, stock, if_saleable?}
            """
            if not isinstance(v, list):
                return None
            total = 0
            found = False
            for row in v:
                if not isinstance(row, dict):
                    continue
                if row.get("if_saleable") is False:
                    continue
                stock_val = _to_int_or_none(row.get("stock"))
                if stock_val is None:
                    continue
                total += stock_val
                found = True
            return total if found else None

        # 2) Base info (título + possivelmente estoque)
        base_list = self.get_item_base_info([int(sample_item_id)])
        bi = base_list[0] if base_list else {}
        bi_keys = sorted(list(bi.keys())) if isinstance(bi, dict) else []

        # Caminho correto (docs): response > stock_info_v2 > seller_stock[] > stock
        seller_stock_total: Optional[int] = None
        seller_stock_count: Optional[int] = None
        if isinstance(bi, dict):
            stock_info_v2 = bi.get("stock_info_v2")
            if isinstance(stock_info_v2, dict):
                seller_stock = stock_info_v2.get("seller_stock")
                if isinstance(seller_stock, list):
                    seller_stock_count = len(seller_stock)
                    seller_stock_total = _sum_seller_stock_locations(seller_stock)

        # 3) Model list (possivelmente estoque)
        model_data = self.get_model_list(int(sample_item_id))
        models = model_data.get("model", [])
        first_model = models[0] if models else {}
        model_keys = sorted(list(first_model.keys())) if isinstance(first_model, dict) else []

        # 4) Descobrir campos que parecem estoque
        stock_fields_found: List[str] = []
        candidates = [
            ("base", bi),
            ("model", first_model),
        ]
        for prefix, obj in candidates:
            if not isinstance(obj, dict):
                continue
            for k in (
                "normal_stock",
                "stock",
                "seller_stock",
                "shopee_stock",
                "stock_info",
                "stock_info_v2",
                "inventory",
            ):
                if k in obj:
                    stock_fields_found.append(f"{prefix}.{k}")

            # Detecção explícita do caminho esperado: stock_info_v2.seller_stock[].stock
            if isinstance(obj.get("stock_info_v2"), dict):
                siv2 = obj.get("stock_info_v2")
                if isinstance(siv2, dict) and "seller_stock" in siv2:
                    stock_fields_found.append(f"{prefix}.stock_info_v2.seller_stock")

        return {
            "sample_item_id": int(sample_item_id),
            "item_base_info_keys": bi_keys,
            "model_keys": model_keys,
            "stock_fields_found": stock_fields_found,
            "base_stock_info_v2_seller_stock_count": seller_stock_count,
            "base_stock_info_v2_seller_stock_total": seller_stock_total,
            "model_count": len(models) if isinstance(models, list) else None,
        }

    # ---------- Endpoints de produto ----------

    def get_item_list(self, item_status: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Lista itens da loja usando /api/v2/product/get_item_list com paginação.

        Ver docs: Product > Get Item List (Shopee Open Platform v2).
        """
        if item_status is None:
            # Status típicos: NORMAL, UNLIST, BANNED; ajustável conforme necessidade
            item_status = ["NORMAL", "UNLIST"]

        # Path completo incluindo "/api/v2" conforme docs de Product > Get Item List
        path = "/api/v2/product/get_item_list"
        offset = 0
        page_size = 100
        has_more = True
        items: List[Dict[str, Any]] = []

        while has_more:
            params = {
                "item_status": item_status,
                "offset": offset,
                "page_size": page_size,
            }
            data = self._make_request("GET", path, params=params)
            resp_items = data.get("response", {}).get("item", []) or []
            items.extend(resp_items)

            has_more = data.get("response", {}).get("has_more", False)
            offset = data.get("response", {}).get("next_offset", 0)

            if not has_more:
                break

        return items

    def get_item_base_info(self, item_ids: List[int]) -> List[Dict[str, Any]]:
        """Busca informações base (incluindo título do anúncio) em lote.

        Na prática, `get_item_list` pode retornar apenas IDs/status. Para exibir nomes
        e permitir busca por título, usamos `get_item_base_info`.
        """
        path = "/api/v2/product/get_item_base_info"
        if not item_ids:
            return []

        # Limite do lote varia por região; 50 costuma ser seguro.
        batch_size = 50
        results: List[Dict[str, Any]] = []
        for i in range(0, len(item_ids), batch_size):
            batch = item_ids[i : i + batch_size]
            params = {"item_id_list": ",".join(str(int(x)) for x in batch)}
            data = self._make_request("GET", path, params=params)

            resp = data.get("response", {}) or {}
            items = resp.get("item_list") or resp.get("item") or []
            if isinstance(items, list):
                results.extend(items)

        return results

    def get_model_list(self, item_id: int) -> Dict[str, Any]:
        """Retorna a lista de modelos (variações) para um item.

        Ver docs: Product > Get Model List (Shopee Open Platform v2).
        Retorna o objeto 'response' completo, contendo 'model' e 'tier_variation'.
        """
        # Path completo incluindo "/api/v2" conforme docs de Get Model List
        path = "/api/v2/product/get_model_list"
        params = {"item_id": int(item_id)}
        data = self._make_request("GET", path, params=params)
        return data.get("response", {}) or {}

    def update_stock(
        self,
        item_id: int,
        model_ids: Optional[List[Optional[int]]],
        new_stock: int,
    ) -> Dict[str, Any]:
        """Atualiza estoque de um item/model(s) usando /api/v2/product/update_stock.

        - Se model_ids for None ou contiver apenas None, aplica estoque no nível do item.
        - Caso contrário, envia stock_list para cada model_id.

        Observação (docs v2): esta API atualiza o **seller_stock**.
        """
        # Path completo incluindo "/api/v2" conforme docs de Update Stock
        path = "/api/v2/product/update_stock"
        body: Dict[str, Any] = {"item_id": int(item_id)}

        # Sem variações (estoque no nível do item)
        if not model_ids or all(m is None for m in model_ids):
            body["stock"] = new_stock
        else:
            # Para variações, stock_list exige seller_stock como LISTA de objetos.
            # Erro anterior: json: cannot unmarshal number into Go struct field ... type []*StockByLocation
            stock_list = [
                {
                    "model_id": int(mid),
                    "seller_stock": [{"stock": int(new_stock)}]
                }
                for mid in model_ids
                if mid is not None
            ]
            body["stock_list"] = stock_list

        data = self._make_request("POST", path, body=body)
        return data


# ==========================
# Funções auxiliares (dados locais / filtro)
# ==========================

def build_models_cache(client: ShopeeClient) -> List[Dict[str, Any]]:
    """Baixa itens e modelos da Shopee e constrói uma lista achatada de variações.

    Cada registro retornado terá estrutura aproximada:
    {
        "item_id": int,
        "model_id": Optional[int],
        "item_name": str,
        "model_name": str,
        "display_name": str,  # item + variação
        "normal_stock": Optional[int],
    }
    """
    items = client.get_item_list()

    item_ids: List[int] = []
    for it in items:
        if it.get("item_id") is None:
            continue
        try:
            item_ids.append(int(it.get("item_id")))
        except Exception:
            continue

    base_info_list = client.get_item_base_info(item_ids)
    base_by_id: Dict[int, Dict[str, Any]] = {}
    for bi in base_info_list:
        try:
            iid = int(bi.get("item_id"))
        except Exception:
            continue
        base_by_id[iid] = bi

    def _to_int_or_none(v: Any) -> Optional[int]:
        if v is None:
            return None
        try:
            # Algumas respostas podem trazer como string
            return int(v)
        except Exception:
            try:
                return int(float(v))
            except Exception:
                return None

    def _sum_location_stock(v: Any) -> Optional[int]:
        """Soma estoque quando Shopee retorna listas por location.

        Formato típico (docs):
          seller_stock: [{location_id: str, stock: int, if_saleable: bool?}, ...]
          shopee_stock: [{location_id: str, stock: int}, ...]

        Regra: soma `stock` de entradas `if_saleable=True` quando presente.
        """
        if not isinstance(v, list):
            return None
        total = 0
        found = False
        for row in v:
            if not isinstance(row, dict):
                continue
            if row.get("if_saleable") is False:
                continue
            stock_val = _to_int_or_none(row.get("stock"))
            if stock_val is None:
                continue
            total += stock_val
            found = True
        return total if found else None

    def _stock_value_from_any(v: Any) -> Optional[int]:
        iv = _to_int_or_none(v)
        if iv is not None:
            return iv
        summed = _sum_location_stock(v)
        if summed is not None:
            return summed
        # Alguns payloads podem trazer dict com chaves internas
        if isinstance(v, dict):
            for kk in ("seller_stock", "normal_stock", "stock", "shopee_stock"):
                if kk in v:
                    iv2 = _to_int_or_none(v.get(kk))
                    if iv2 is not None:
                        return iv2
                    summed2 = _sum_location_stock(v.get(kk))
                    if summed2 is not None:
                        return summed2
        return None

    def _extract_stock_from_base_info(bi: Dict[str, Any]) -> Tuple[Optional[int], Dict[int, Optional[int]]]:
        """Tenta extrair estoque do item e por model_id a partir do get_item_base_info.

        A Shopee pode variar campos por região/versão; fazemos melhor esforço.
        Retorna (item_stock, {model_id: stock}).
        """
        item_stock: Optional[int] = None
        model_stock: Dict[int, Optional[int]] = {}

        # 1) Tenta extrair estoque do item (nível superior)
        for k in ("stock", "normal_stock", "seller_stock", "shopee_stock"):
            if k in bi:
                item_stock = _stock_value_from_any(bi.get(k))
                if item_stock is not None:
                    break
        
        # 2) Se não achou, tenta em estruturas aninhadas (ex: stock_info_v2)
        if item_stock is None:
            for nk in ("stock_info", "stock_info_v2", "inventory", "item_stock_info"):
                nv = bi.get(nk)
                if isinstance(nv, dict):
                    for k in ("stock", "normal_stock", "seller_stock", "shopee_stock"):
                        val = _stock_value_from_any(nv.get(k))
                        if val is not None:
                            item_stock = val
                            break
                if item_stock is not None:
                    break

        # Listas possíveis de modelos no base_info
        candidate_lists: List[Any] = []
        for lk in ("model_list", "models", "model"):
            v = bi.get(lk)
            if isinstance(v, list):
                candidate_lists.append(v)

        # Estruturas aninhadas comuns
        for nk in ("stock_info", "stock_info_v2", "inventory", "item_stock_info"):
            nv = bi.get(nk)
            if isinstance(nv, dict):
                for lk in ("model", "model_list", "models"):
                    v = nv.get(lk)
                    if isinstance(v, list):
                        candidate_lists.append(v)

        for lst in candidate_lists:
            for m in lst or []:
                if not isinstance(m, dict):
                    continue
                mid = m.get("model_id")
                if mid is None:
                    continue
                try:
                    mid_int = int(mid)
                except Exception:
                    continue
                for k in ("normal_stock", "stock", "seller_stock", "shopee_stock"):
                    if k in m:
                        model_stock[mid_int] = _stock_value_from_any(m.get(k))
                        break
                # Estruturas aninhadas por model
                for nk in ("stock_info", "stock_info_v2", "inventory"):
                    nv = m.get(nk)
                    if isinstance(nv, dict):
                        for k in ("normal_stock", "stock", "seller_stock", "shopee_stock"):
                            iv = _stock_value_from_any(nv.get(k))
                            if iv is not None:
                                model_stock[mid_int] = iv
                                break

        return item_stock, model_stock

    def _item_title(bi: Dict[str, Any]) -> str:
        for k in ("item_name", "name", "title"):
            v = bi.get(k)
            if v:
                return str(v)
        return ""

    def _extract_model_stock(model: Dict[str, Any]) -> Optional[int]:
        # Campos mais comuns
        for k in ("normal_stock", "stock", "seller_stock"):
            if k in model:
                iv = _stock_value_from_any(model.get(k))
                if iv is not None:
                    return iv

        # Alguns payloads podem aninhar info de estoque
        for k in ("stock_info", "stock_info_v2", "inventory"):
            nested = model.get(k)
            if isinstance(nested, dict):
                for kk in ("normal_stock", "stock", "seller_stock"):
                    iv = _stock_value_from_any(nested.get(kk))
                    if iv is not None:
                        return iv
        return None

    models_cache: List[Dict[str, Any]] = []

    for item in items:
        if item.get("item_id") is None:
            continue
        item_id = int(item.get("item_id"))
        bi = base_by_id.get(item_id, {})
        bi_item_stock, bi_model_stock = _extract_stock_from_base_info(bi)

        item_name = _item_title(bi) or str(item.get("item_name") or "")
        fabric_key = extract_fabric_from_title(item_name)
        fabric_label = _titleize_words(fabric_key) if fabric_key else ""

        has_model = bi.get("has_model")
        if has_model is None:
            has_model = item.get("has_model", False)
        has_model = bool(has_model)

        if has_model:
            model_data = client.get_model_list(item_id)
            models = model_data.get("model", [])
            tier_variation = model_data.get("tier_variation", [])

            # Tenta identificar qual tier é "Cor"
            color_tier_idx = -1
            for idx, tv in enumerate(tier_variation):
                tv_name = str(tv.get("name", "")).strip().lower()
                if tv_name in ("cor", "color", "colour", "colors", "colours"):
                    color_tier_idx = idx
                    break

            for m in models:
                model_id = m.get("model_id")
                model_name = m.get("model_name", "")
                normal_stock = _extract_model_stock(m)
                if normal_stock is None and model_id is not None:
                    try:
                        normal_stock = bi_model_stock.get(int(model_id))
                    except Exception:
                        pass
                display_name = f"{item_name} - {model_name}" if model_name else item_name

                # 1) Tenta extrair cor via tier_variation (mais preciso)
                color_key = ""
                if color_tier_idx >= 0:
                    t_indexes = m.get("tier_index")
                    if isinstance(t_indexes, list) and len(t_indexes) > color_tier_idx:
                        opt_idx = t_indexes[color_tier_idx]
                        try:
                            opts = tier_variation[color_tier_idx].get("option_list", [])
                            if isinstance(opts, list) and len(opts) > opt_idx:
                                color_key = str(opts[opt_idx].get("option", "")).strip()
                        except Exception:
                            pass

                # 2) Fallback: regex no nome do modelo
                if not color_key:
                    color_key = extract_color_from_model(str(model_name or ""), item_name)
                color_label = _titleize_words(color_key) if color_key else ""
                short_display_name = (
                    f"{fabric_label} - {color_label}".strip(" -")
                    if fabric_label or color_label
                    else (model_name or item_name)
                )
                models_cache.append(
                    {
                        "item_id": item_id,
                        "model_id": model_id,
                        "item_name": item_name,
                        "model_name": model_name,
                        "display_name": display_name,
                        "fabric_key": fabric_key,
                        "fabric_label": fabric_label,
                        "color_key": color_key,
                        "color_label": color_label,
                        "short_display_name": short_display_name,
                        "normal_stock": normal_stock,
                    }
                )
        else:
            # Item sem variações: tratamos como um "modelo único" com model_id=None
            normal_stock = (
                _to_int_or_none(bi.get("stock"))
                or _to_int_or_none(bi.get("normal_stock"))
                or _to_int_or_none(item.get("stock"))
                or _to_int_or_none(item.get("normal_stock"))
            )
            if normal_stock is None:
                normal_stock = bi_item_stock
            display_name = item_name

            # Sem model_name, então o curto fica basicamente o tecido
            short_display_name = fabric_label or item_name
            models_cache.append(
                {
                    "item_id": item_id,
                    "model_id": None,
                    "item_name": item_name,
                    "model_name": "",
                    "display_name": display_name,
                    "fabric_key": fabric_key,
                    "fabric_label": fabric_label,
                    "color_key": "",
                    "color_label": "",
                    "short_display_name": short_display_name,
                    "normal_stock": normal_stock,
                }
            )

    return models_cache


def filter_ungrouped_models(
    models: List[Dict[str, Any]], groups: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Remove da lista de models aqueles que já pertencem a algum grupo salvo."""
    grouped_pairs: set[Tuple[int, Optional[int]]] = set()
    for g in groups:
        for it in g.get("items", []):
            grouped_pairs.add((int(it.get("item_id")), it.get("model_id")))

    ungrouped = [
        m
        for m in models
        if (int(m.get("item_id")), m.get("model_id")) not in grouped_pairs
    ]
    return ungrouped


def search_models(
    models: List[Dict[str, Any]], query: str, min_ratio: float = 0.3
) -> List[Dict[str, Any]]:
    """Filtra models pelo texto (contains) + ranking de similaridade (difflib).

    - Primeiro aplica filtro case-insensitive por substring.
    - Depois ordena por similaridade com SequenceMatcher.
    """
    if not query:
        return models

    def _norm(s: str) -> str:
        s = (s or "").strip().lower()
        s = unicodedata.normalize("NFKD", s)
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        return " ".join(s.split())

    q = _norm(query)
    filtered: List[Tuple[float, Dict[str, Any]]] = []

    for m in models:
        text = _norm(f"{m.get('item_name', '')} {m.get('model_name', '')}")
        if not text:
            continue

        if q in text:
            ratio = 1.0
        else:
            ratio = SequenceMatcher(None, q, text).ratio()

        if ratio >= min_ratio:
            filtered.append((ratio, m))

    filtered.sort(key=lambda t: t[0], reverse=True)
    return [m for _, m in filtered]


def _norm_text(s: str) -> str:
    s = (s or "").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return " ".join(s.split())


def _titleize_words(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    small = {"de", "da", "do", "das", "dos", "e"}
    parts = []
    for w in s.split():
        lw = w.lower()
        if lw in small:
            parts.append(lw)
        else:
            parts.append(lw.capitalize())
    out = " ".join(parts)
    out = out.replace("Offwhite", "Off White")
    return out


def extract_fabric_from_title(title: str) -> str:
    """Extrai um identificador de tecido a partir do título do anúncio.

    Heurística pensada para o padrão da loja:
    - muitos títulos seguem: "Tecido <nome do tecido> RAZAI – ..."
    - alguns fogem (ex.: kits), então tentamos fallback por cortes comuns.

    Retorna texto normalizado (sem acento, lower, espaços colapsados).
    """
    raw = str(title or "").strip()
    if not raw:
        return ""

    # Cortes comuns por separadores de marketing
    # (mantém a parte inicial onde costuma estar o nome do tecido)
    for sep in (" – ", " - ", "–", "—"):
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()

    s = _norm_text(raw)

    # Âncora da loja
    if " razai" in f" {s}":
        s = s.split("razai", 1)[0].strip()

    # Remove prefixos comuns (loop para garantir remoção em cadeia, ex: "Kit 3 Metros Tecido...")
    prefixes = [
        "kit 3 metros ", "kit 2 metros ", "kit 1 metro ",
        "kit ", "tecido ",
        "3 metros ", "2 metros ", "1 metro ",
        "3m ", "2m ", "1m ",
    ]
    while True:
        changed = False
        for p in prefixes:
            if s.startswith(p):
                s = s[len(p):].strip()
                changed = True
                break
        if not changed:
            break

    # Marcadores de corte (normalizados) para limpar sufixos de marketing/medidas
    # Ex: "cetim charmousse 1,50m largura..." -> "cetim charmousse"
    cut_markers = [
        " 1,50m", " 1.50m", " 1,5m", " 1.5m", " 3,00m", " 3m",
        " largura", " larg",
        " + barato", " mais barato",
        " promocao", " oferta",
        " envio imediato", " pronta entrega",
    ]
    for marker in cut_markers:
        if marker in s:
            s = s.split(marker, 1)[0].strip()

    # Remove palavras muito genéricas que atrapalham agrupamento
    junk_words = {
        "tecido",
        "metro",
        "metros",
        "largura",
        "liso",
        "barato",
        "promocao",
        "promocao",
    }
    tokens = [t for t in s.split() if t and t not in junk_words]

    # Remove tokens sem letras (ex.: '+', '|', etc.)
    tokens = [t for t in tokens if any(ch.isalpha() for ch in t)]

    # Remove tokens que são claramente medidas
    cleaned: List[str] = []
    for t in tokens:
        # exemplos: 0,50 1m 2m 3m 1,50m 1.50m
        tt = t.replace(".", ",")
        if tt.endswith("m"):
            num = tt[:-1]
            if num.replace(",", "").isdigit():
                continue
        if tt.replace(",", "").isdigit():
            continue
        cleaned.append(t)

    # Dedup simples (ajuda em títulos do tipo "... cetim ... cetim ...")
    seen: set[str] = set()
    deduped: List[str] = []
    for t in cleaned:
        if t in seen:
            continue
        seen.add(t)
        deduped.append(t)

    s = " ".join(deduped).strip()
    return s


def extract_color_from_model(model_name: str, item_name: str = "") -> str:
    """Extrai a cor (ou rótulo principal) do nome da variação.

    Regras ajustadas:
    1. Normaliza texto.
    2. Corta tudo após ',' ou '('.
    3. Corta tudo após ' x ' (ou ' x' no final).
    4. Remove medidas/junk words.
    5. Mantém no máximo as 3 primeiras palavras.
    """
    raw = str(model_name or "").strip()
    if not raw:
        raw = str(item_name or "").strip()
    if not raw:
        return ""

    s = _norm_text(raw)

    # Regras de corte solicitadas
    if "," in s:
        s = s.split(",", 1)[0]
    if "(" in s:
        s = s.split("(", 1)[0]
    
    # Remove ' x ' ou ' x' no final (evita cortar 'roxo', 'maxi')
    s = re.sub(r"\s+x(?:\s+|$).*", "", s)

    # Remove padrões de metragem explícitos (ex: 2m, 0.50m)
    s = re.sub(r"\b\d+(?:[.,]\d+)?m\b", "", s).strip()

    # Remove separadores restantes que podem ter sobrado (ex: "Azul -")
    for sep in ("|", "/", "-", "–"):
        s = s.replace(sep, " ")

    junk_words = {"por", "metro", "metros", "m", "kit", "unidade", "unid"}

    tokens = []
    for t in s.split():
        tt = t.replace(".", ",")
        # remove medidas numéricas soltas ou com 'm'
        if tt.endswith("m"):
            num = tt[:-1]
            if num.replace(",", "").isdigit():
                continue
        if tt.replace(",", "").isdigit():
            continue
        if tt in junk_words:
            continue
        
        # Remove casos grudados restantes
        t2 = re.sub(r"\b\d+(?:[.,]\d+)?m\b", "", tt).strip(" ,")
        if not t2:
            continue
        tokens.append(t2)

    # Limita a 3 palavras conforme solicitado
    tokens = tokens[:3]

    s = " ".join(tokens).strip()
    return s


def build_suggested_fabric_color_groups(
    models: List[Dict[str, Any]],
    min_group_size: int = 2,
) -> List[Dict[str, Any]]:
    """Sugere agrupamentos automáticos por (tecido, cor).

    Cada sugestão contém:
    - fabric_key, color_key: chaves normalizadas
    - fabric_label, color_label: para exibir
    - model_keys: lista de chaves "item_id:model_id"
    """
    buckets: Dict[Tuple[str, str], List[str]] = {}

    for m in models:
        item_id = m.get("item_id")
        model_id = m.get("model_id")
        key = f"{item_id}:{model_id if model_id is not None else 'none'}"

        fabric_key = extract_fabric_from_title(str(m.get("item_name") or ""))
        color_key = extract_color_from_model(str(m.get("model_name") or ""), str(m.get("item_name") or ""))

        if not fabric_key:
            continue

        buckets.setdefault((fabric_key, color_key), []).append(key)

    out: List[Dict[str, Any]] = []
    for (fabric_key, color_key), keys in buckets.items():
        if len(keys) < int(min_group_size):
            continue
        out.append(
            {
                "fabric_key": fabric_key,
                "color_key": color_key,
                "fabric_label": _titleize_words(fabric_key),
                "color_label": _titleize_words(color_key) if color_key else "(Sem cor)",
                "model_keys": keys,
                "count": len(keys),
            }
        )

    out.sort(key=lambda d: (int(d.get("count") or 0), d.get("fabric_key") or "", d.get("color_key") or ""), reverse=True)
    return out


def suggest_master_name(models: List[Dict[str, Any]]) -> str:
    """Sugere um Nome Mestre baseado em título/variação (heurística simples).

    Objetivo: ajudar a padronizar por "tecido + estampa + cor" sem exigir que
    o usuário digite tudo sempre.
    """
    if not models:
        return ""

    fabrics = [
        "viscolinho",
        "viscose",
        "tricoline",
        "crepe",
        "linho",
        "sarja",
        "jeans",
        "moletom",
        "suede",
        "cetim",
        "tule",
        "malha",
        "ribana",
        "neoprene",
    ]

    colors = [
        "branco",
        "preto",
        "azul",
        "vermelho",
        "amarelo",
        "verde",
        "rosa",
        "roxo",
        "lilas",
        "laranja",
        "bege",
        "nude",
        "marrom",
        "cinza",
        "off white",
        "offwhite",
        "cru",
    ]

    patterns = [
        "liso",
        "estampado",
        "floral",
        "poa",
        "bolinha",
        "xadrez",
        "listrado",
        "animal print",
        "onca",
        "zebra",
        "geometrico",
        "folhagem",
    ]

    # Junta textos e normaliza (sem acento) para facilitar detecção
    texts = [_norm_text(f"{m.get('item_name','')} {m.get('model_name','')}") for m in models]
    full = " ".join(t for t in texts if t)

    def _find_first(candidates: List[str]) -> str:
        for c in candidates:
            if c in full:
                return c
        return ""

    fabric = _find_first(fabrics)
    color = _find_first(colors)
    pattern = _find_first(patterns)

    # Montagem simples e legível
    parts = [p for p in (fabric, pattern, color) if p]
    if not parts:
        # fallback: usa um prefixo do primeiro item
        raw = str(models[0].get("item_name") or "").strip()
        return raw[:60]

    # title-case básico (mantendo palavras pequenas)
    out = " ".join(parts)
    return _titleize_words(out)


# ==========================
# UI com Streamlit
# ==========================

def init_session_state() -> None:
    if "client" not in st.session_state:
        st.session_state["client"] = None
    if "models_cache" not in st.session_state:
        st.session_state["models_cache"] = []
    if "last_sync_ts" not in st.session_state:
        st.session_state["last_sync_ts"] = None
    if "api_base_url" not in st.session_state:
        st.session_state["api_base_url"] = BASE_URL
    if "api_env" not in st.session_state:
        st.session_state["api_env"] = "Produção"
    if "api_region" not in st.session_state:
        st.session_state["api_region"] = "Brasil"
    if "refresh_token" not in st.session_state:
        st.session_state["refresh_token"] = ""
    if "shop_id" not in st.session_state:
        st.session_state["shop_id"] = ""
    if "access_token" not in st.session_state:
        st.session_state["access_token"] = ""
    # Widgets usam chaves separadas para evitar erro ao atualizar tokens após interações.
    if "shop_id_input" not in st.session_state:
        st.session_state["shop_id_input"] = ""
    if "access_token_input" not in st.session_state:
        st.session_state["access_token_input"] = ""
    if "refresh_token_input" not in st.session_state:
        st.session_state["refresh_token_input"] = ""
    if "_sync_token_inputs" not in st.session_state:
        st.session_state["_sync_token_inputs"] = False
    if "_flash_sidebar" not in st.session_state:
        st.session_state["_flash_sidebar"] = ""
    if "last_token_refresh_ts" not in st.session_state:
        st.session_state["last_token_refresh_ts"] = None
    if "_auto_token_bootstrap_done" not in st.session_state:
        st.session_state["_auto_token_bootstrap_done"] = False
    if "_last_oauth_code_exchanged" not in st.session_state:
        st.session_state["_last_oauth_code_exchanged"] = ""
    if "redirect_url" not in st.session_state:
        st.session_state["redirect_url"] = "https://razaiestoque.streamlit.app/"


def sidebar_setup() -> None:
    st.sidebar.header("Configurações Shopee (Setup)")

    # Pré-carrega credenciais (sem salvar em disco):
    # 1) arquivo local somente leitura (sandbox/teste)
    # 2) variáveis de ambiente (ideal para produção)
    # 3) tokens persistidos via Git (tokens.json)
    file_creds = load_test_credentials_from_file()
    secrets_creds = load_credentials_from_streamlit_secrets()
    env_creds = load_credentials_from_env()
    git_tokens = load_tokens()

    # Se o app for aberto com query params (ex.: redirect do OAuth), auto-preenche.
    # Funciona tanto no Streamlit Cloud (redirect para a própria URL do app)
    # quanto localmente, se você abrir: http://localhost:8501/?code=...&shop_id=...
    def _qp_first(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value)

    try:
        qp: Any = st.query_params  # Streamlit novo
        qp_code = _qp_first(qp.get("code"))
        qp_shop_id = _qp_first(qp.get("shop_id"))
    except Exception:
        qp = st.experimental_get_query_params()
        qp_code = _qp_first(qp.get("code"))
        qp_shop_id = _qp_first(qp.get("shop_id"))

    # Importante: o `code` é uso único e expira rápido. Se o usuário reautorizar,
    # ele chega com um NOVO code na URL. Então precisamos atualizar a sessão quando
    # o query param mudar; caso contrário o app tenta trocar um code antigo e falha.
    if qp_code and qp_code != str(st.session_state.get("oauth_code") or ""):
        st.session_state["oauth_code"] = qp_code
    if qp_shop_id and qp_shop_id != str(st.session_state.get("oauth_shop_id") or ""):
        st.session_state["oauth_shop_id"] = qp_shop_id

    # Se acabamos de atualizar tokens (OAuth/refresh), refletir nos inputs ANTES
    # dos widgets serem instanciados.
    if st.session_state.get("_sync_token_inputs"):
        st.session_state["shop_id_input"] = str(st.session_state.get("shop_id") or "")
        st.session_state["access_token_input"] = str(st.session_state.get("access_token") or "")
        st.session_state["refresh_token_input"] = str(st.session_state.get("refresh_token") or "")
        st.session_state["_sync_token_inputs"] = False

    # Se veio shop_id no redirect, isso é Live e ajuda a preencher automaticamente.
    if qp_shop_id and not file_creds.get("live_shop_id"):
        file_creds["live_shop_id"] = qp_shop_id

    preferred_env = st.session_state.get("api_env", "Produção")

    # Ordem de prioridade para preencher campos:
    # 1. Session State (se já editado)
    # 2. Git Tokens (tokens.json)
    # 3. Secrets (st.secrets)
    # 4. Env Vars
    # 5. File Creds (razaiestoque.txt)

    def _resolve(key_session: str, key_git: str, key_secrets: str, key_env: str, key_file: str) -> str:
        # Se já tem na sessão (e não está vazio), usa.
        # Mas cuidado: na primeira execução, sessão pode estar vazia.
        val_sess = str(st.session_state.get(key_session) or "").strip()
        if val_sess:
            return val_sess
        
        # Git Tokens
        val_git = str(git_tokens.get(key_git) or "").strip()
        if val_git:
            return val_git

        # Secrets
        val_sec = str(secrets_creds.get(key_secrets) or "").strip()
        if val_sec:
            return val_sec
        
        # Env
        val_env = str(env_creds.get(key_env) or "").strip()
        if val_env:
            return val_env
        
        # File
        val_file = str(file_creds.get(key_file) or "").strip()
        return val_file

    # Resolve valores iniciais
    if preferred_env == "Produção":
        init_partner_id = _resolve("partner_id", "partner_id", "partner_id", "partner_id", "live_partner_id")
        init_partner_key = _resolve("partner_key", "partner_key", "partner_key", "partner_key", "live_partner_key")
        init_shop_id = _resolve("shop_id", "shop_id", "shop_id", "shop_id", "live_shop_id")
        init_access_token = _resolve("access_token", "access_token", "access_token", "access_token", "")
        init_refresh_token = _resolve("refresh_token", "refresh_token", "refresh_token", "refresh_token", "")
        init_redirect_url = _resolve("redirect_url", "redirect_url", "redirect_url", "redirect_url", "")
        init_api_base_url = _resolve("api_base_url", "api_base_url", "api_base_url", "api_base_url", "")
    else:
        # Sandbox
        init_partner_id = _resolve("partner_id", "test_partner_id", "test_partner_id", "test_partner_id", "test_partner_id")
        init_partner_key = _resolve("partner_key", "test_partner_key", "test_partner_key", "test_partner_key", "test_partner_key")
        init_shop_id = _resolve("shop_id", "test_shop_id", "test_shop_id", "test_shop_id", "test_shop_id")
        init_access_token = _resolve("access_token", "test_access_token", "test_access_token", "test_access_token", "test_access_token")
        init_refresh_token = "" # Sandbox geralmente não usa refresh token complexo no exemplo
        init_redirect_url = "https://razaiestoque.streamlit.app/"
        init_api_base_url = SANDBOX_BASE_URL

    # Atualiza session state se estiver vazio
    if not st.session_state.get("partner_id"): st.session_state["partner_id"] = init_partner_id
    if not st.session_state.get("partner_key"): st.session_state["partner_key"] = init_partner_key
    if not st.session_state.get("shop_id"): st.session_state["shop_id"] = init_shop_id
    if not st.session_state.get("access_token"): st.session_state["access_token"] = init_access_token
    if not st.session_state.get("refresh_token"): st.session_state["refresh_token"] = init_refresh_token
    if not st.session_state.get("redirect_url"): st.session_state["redirect_url"] = init_redirect_url
    if not st.session_state.get("api_base_url"): st.session_state["api_base_url"] = init_api_base_url

    # --- Lógica de Auto-Login (OAuth Code Exchange) ---
    # Se detectamos code/shop_id na URL e ainda não trocamos:
    if (
        qp_code 
        and qp_shop_id 
        and qp_code != st.session_state.get("_last_oauth_code_exchanged")
        and init_partner_id 
        and init_partner_key
    ):
        st.sidebar.info("Detectado retorno do login Shopee. Trocando code por token...")
        try:
            tmp_client = ShopeeClient(
                partner_id=int(init_partner_id),
                partner_key=init_partner_key,
                shop_id=int(qp_shop_id),
                access_token="",
                base_url=init_api_base_url or BASE_URL,
            )
            token_data = tmp_client.exchange_code_for_token(
                code=qp_code,
                shop_id=int(qp_shop_id),
                redirect_uri=init_redirect_url
            )
            
            new_at = str(token_data.get("access_token", "")).strip()
            new_rt = str(token_data.get("refresh_token", "")).strip()
            
            if new_at:
                st.session_state["access_token"] = new_at
                st.session_state["refresh_token"] = new_rt
                st.session_state["shop_id"] = qp_shop_id
                st.session_state["_last_oauth_code_exchanged"] = qp_code
                st.session_state["_sync_token_inputs"] = True
                
                # Salva no tokens.json e faz push
                new_tokens = {
                    "partner_id": init_partner_id,
                    "partner_key": init_partner_key,
                    "shop_id": qp_shop_id,
                    "access_token": new_at,
                    "refresh_token": new_rt,
                    "redirect_url": init_redirect_url,
                    "api_base_url": init_api_base_url
                }
                save_tokens(new_tokens)
                git_persist_data() # Salva no Git automaticamente
                
                st.sidebar.success("Login realizado com sucesso! Tokens salvos no Git.")
                time.sleep(1)
                st.rerun()
        except Exception as exc:
            st.sidebar.error(f"Erro no auto-login: {exc}")

    # --- UI Simplificada ---
    
    # Se temos token válido (ou refresh token), mostramos status conectado
    has_token = bool(st.session_state.get("access_token"))
    has_refresh = bool(st.session_state.get("refresh_token"))
    
    if has_token:
        st.sidebar.success(f"Conectado (Shop ID: {st.session_state.get('shop_id')})")
        if st.sidebar.button("Desconectar / Trocar Conta"):
            st.session_state["access_token"] = ""
            st.session_state["refresh_token"] = ""
            st.session_state["shop_id"] = ""
            # Limpa tokens.json
            save_tokens({})
            git_persist_data()
            st.rerun()
    else:
        st.sidebar.warning("Desconectado")
        # Botão grande de login
        if init_partner_id and init_partner_key and init_redirect_url:
            try:
                tmp_client = ShopeeClient(
                    partner_id=int(init_partner_id),
                    partner_key=init_partner_key,
                    shop_id=0,
                    access_token="",
                    base_url=init_api_base_url or BASE_URL,
                )
                auth_url = tmp_client.build_authorize_url(init_redirect_url)
                st.sidebar.link_button("🔐 Fazer Login na Shopee", auth_url, type="primary")
            except Exception:
                st.sidebar.error("Erro ao gerar link de login. Verifique configurações.")

    # Expander para configurações manuais (escondido por padrão se estiver tudo ok)
    with st.sidebar.expander("Configurações Avançadas / Manuais", expanded=not (has_token or has_refresh)):
        partner_id = st.text_input("Partner ID", value=st.session_state.get("partner_id", ""), key="partner_id_input")
        partner_key = st.text_input("Partner Key", value=st.session_state.get("partner_key", ""), type="password", key="partner_key_input")
        
        # Atualiza session state quando user digita
        if partner_id != st.session_state.get("partner_id"): st.session_state["partner_id"] = partner_id
        if partner_key != st.session_state.get("partner_key"): st.session_state["partner_key"] = partner_key

        shop_id_input = st.text_input(
            "Shop ID",
            value=st.session_state.get("shop_id_input", ""),
            key="shop_id_widget",
        )
        access_token_input = st.text_input(
            "Access Token",
            value=st.session_state.get("access_token_input", ""),
            type="password",
            key="access_token_widget",
        )
        refresh_token_input = st.text_input(
            "Refresh Token",
            value=st.session_state.get("refresh_token_input", ""),
            type="password",
            key="refresh_token_widget",
        )
        
        # Sincroniza widgets -> session
        st.session_state["shop_id"] = shop_id_input
        st.session_state["access_token"] = access_token_input
        st.session_state["refresh_token"] = refresh_token_input

        api_env = st.selectbox("Ambiente", ["Produção", "Sandbox"], index=0 if preferred_env == "Produção" else 1)
        st.session_state["api_env"] = api_env
        
        # ... (resto das configs manuais se necessário) ...
        
        api_region = st.selectbox(
            "Região (host de produção)",
            options=["Brasil", "Global"],
            key="api_region",
            help=(
                "A Shopee usa hosts diferentes por região. "
                "Brasil usa openplatform.shopee.com.br; Global usa partner.shopeemobile.com."
            ),
            disabled=(api_env != "Produção"),
        )

        if api_env == "Sandbox":
            default_host = SANDBOX_BASE_URL
        else:
            default_host = BASE_URL if api_region == "Brasil" else GLOBAL_BASE_URL

        # Só sobrescreve automaticamente se o valor atual estiver nos padrões.
        if st.session_state.get("api_base_url") in (
            None,
            "",
            BASE_URL,
            GLOBAL_BASE_URL,
            SANDBOX_BASE_URL,
        ):
            st.session_state["api_base_url"] = default_host

        api_base_url = st.text_input(
            "API Base URL",
            value=st.session_state.get("api_base_url", ""),
            key="api_base_url_widget",
        )
        st.session_state["api_base_url"] = api_base_url
        
        redirect_url = st.text_input(
            "Redirect URL",
            value=st.session_state.get("redirect_url", ""),
            key="redirect_url_widget",
        )
        st.session_state["redirect_url"] = redirect_url

    # Mensagens "flash" (aparecem uma vez)
    if str(st.session_state.get("_flash_sidebar") or "").strip():
        st.sidebar.success(str(st.session_state.get("_flash_sidebar") or ""))
        st.session_state["_flash_sidebar"] = ""

    # --- Fim do Setup ---

    # Auto-renovação: se houver refresh_token (Secrets/ENV/Git), evita ter que reautorizar.
    # Só tenta se NÃO tiver access_token válido ainda.
    if (
        preferred_env == "Produção"
        and not st.session_state.get("_auto_token_bootstrap_done")
        and not str(st.session_state.get("access_token") or "").strip()
        and str(st.session_state.get("refresh_token") or "").strip()
        and str(st.session_state.get("partner_id") or "").strip()
        and str(st.session_state.get("partner_key") or "").strip()
        and str(st.session_state.get("shop_id") or "").strip()
        and str(st.session_state.get("api_base_url") or "").strip()
    ):
        try:
            previous_rt = str(st.session_state.get("refresh_token") or "").strip()
            tmp_client = ShopeeClient(
                partner_id=int(st.session_state["partner_id"]),
                partner_key=str(st.session_state["partner_key"]),
                shop_id=0,
                access_token="",
                base_url=str(st.session_state["api_base_url"] or BASE_URL),
            )
            with st.spinner("Renovando sessão (refresh token)..."):
                token_data = tmp_client.refresh_access_token(
                    refresh_token=previous_rt,
                    shop_id=int(str(st.session_state.get("shop_id") or "0").strip()),
                )
            
            new_at = str(token_data.get("access_token", "")).strip()
            new_rt = str(token_data.get("refresh_token", "") or "").strip()
            
            if new_at:
                st.session_state["access_token"] = new_at
                if new_rt:
                    st.session_state["refresh_token"] = new_rt
                
                st.session_state["last_token_refresh_ts"] = int(time.time())
                st.session_state["_flash_sidebar"] = "Sessão restaurada com sucesso!"
                
                # Se mudou o refresh token, salva no Git
                if new_rt and new_rt != previous_rt:
                    new_tokens = {
                        "partner_id": st.session_state["partner_id"],
                        "partner_key": st.session_state["partner_key"],
                        "shop_id": st.session_state["shop_id"],
                        "access_token": new_at,
                        "refresh_token": new_rt,
                        "redirect_url": st.session_state["redirect_url"],
                        "api_base_url": st.session_state["api_base_url"]
                    }
                    save_tokens(new_tokens)
                    git_persist_data()
                
                st.rerun()
        except Exception as exc:
            # Se falhar, limpa para forçar login novo
            if "error_param" in str(exc):
                st.session_state["refresh_token"] = ""
                st.warning("Sessão expirada. Faça login novamente.")
            else:
                st.warning(f"Falha ao restaurar sessão: {exc}")
        finally:
            st.session_state["_auto_token_bootstrap_done"] = True

    st.sidebar.markdown("---")

    st.sidebar.caption(
        "As credenciais são salvas em tokens.json e persistidas no Git."
    )

    if st.sidebar.button("Sincronizar Dados da Shopee"):
        # Recupera valores da sessão para garantir que temos o mais atual
        partner_id = st.session_state.get("partner_id")
        partner_key = st.session_state.get("partner_key")
        shop_id = st.session_state.get("shop_id")
        access_token = st.session_state.get("access_token")
        api_base_url = st.session_state.get("api_base_url")

        # 1. Tenta atualizar grupos do Git antes de tudo
        with st.spinner("Verificando atualizações de grupos (Git)..."):
            git_msg = git_pull_data()
            if "Sucesso" in git_msg:
                st.toast("Grupos atualizados do GitHub!", icon="✅")
            elif "Erro" in git_msg:
                # Apenas avisa, não bloqueia (pode ser ambiente sem git ou offline)
                st.toast(f"Git Pull: {git_msg}", icon="⚠️")

        if not (partner_id and partner_key and shop_id and access_token):
            st.sidebar.error("Preencha todas as credenciais antes de sincronizar.")
        else:
            try:
                client = ShopeeClient(
                    partner_id=int(partner_id),
                    partner_key=partner_key,
                    shop_id=int(shop_id),
                    access_token=access_token,
                    base_url=api_base_url or BASE_URL,
                )
                with st.spinner("Sincronizando itens e variações da Shopee..."):
                    models_cache = build_models_cache(client)

                st.session_state["client"] = client
                st.session_state["models_cache"] = models_cache
                st.session_state["last_sync_ts"] = int(time.time())

                # Re-sincroniza nomes dentro dos grupos salvos (se existirem)
                try:
                    existing_groups = load_groups()
                    if existing_groups:
                        refreshed, updated_count = refresh_group_names_from_models_cache(existing_groups, models_cache)
                        if updated_count:
                            save_groups(refreshed)
                            st.sidebar.info(f"Nomes re-sincronizados em {updated_count} campos dentro dos grupos.")
                except Exception as exc:  # noqa: BLE001
                    st.sidebar.warning(f"Não foi possível re-sincronizar nomes dos grupos: {exc}")

                st.sidebar.success(
                    f"Sincronização concluída. Modelos carregados: {len(models_cache)}"
                )
            except Exception as exc:  # noqa: BLE001
                st.sidebar.error(f"Erro ao sincronizar com a Shopee: {exc}")

    # --- Git Backup ---
    st.sidebar.markdown("---")
    st.sidebar.header("Backup / Persistência")
    
    col_g1, col_g2 = st.sidebar.columns(2)
    
    if col_g1.button("Salvar no GitHub"):
        with st.spinner("Enviando..."):
            msg = git_persist_data()
            if "Sucesso" in msg:
                st.sidebar.success(msg)
            elif "Nenhuma alteração" in msg:
                st.sidebar.info(msg)
            else:
                st.sidebar.error(msg)

    if col_g2.button("Baixar do GitHub"):
        with st.spinner("Baixando..."):
            msg = git_pull_data()
            if "Sucesso" in msg:
                st.sidebar.success(msg)
                time.sleep(1)
                st.rerun()
            else:
                st.sidebar.error(msg)

    # --- Importar / Exportar mapeamentos (groups.json) ---
    with st.sidebar.expander("Importar/Exportar mapeamentos (Grupos)"):
        st.caption(
            "Use isso como backup/restauração. No Streamlit Cloud, o armazenamento local pode não persistir; "
            "com backend remoto configurado, isso também salva/carrega do remoto."
        )

        try:
            current_groups = load_groups()
        except Exception as exc:  # noqa: BLE001
            current_groups = []
            st.error(f"Falha ao carregar grupos atuais: {exc}")

        export_payload = {"groups": current_groups}
        export_bytes = json.dumps(export_payload, ensure_ascii=False, indent=2).encode("utf-8")

        st.download_button(
            "Baixar mapeamentos (groups.json)",
            data=export_bytes,
            file_name="groups.json",
            mime="application/json",
        )

        uploaded = st.file_uploader(
            "Carregar arquivo groups.json para restaurar", type=["json"], accept_multiple_files=False
        )

        if uploaded is not None:
            try:
                raw_text = uploaded.read().decode("utf-8")
                imported_payload = json.loads(raw_text)
                imported_groups = _validate_imported_groups_payload(imported_payload)
                st.success(f"Arquivo lido. Grupos válidos encontrados: {len(imported_groups)}")

                if st.button("Importar e SUBSTITUIR meus grupos"):
                    save_groups(imported_groups)
                    st.success("Importação concluída. Grupos atualizados.")
                    st.rerun()
            except Exception as exc:  # noqa: BLE001
                st.error(f"Falha ao importar JSON: {exc}")


def tab_mapping():
    """Aba 1: Mapeamento de Produtos (Cérebro)."""
    st.subheader("Aba 1 - Mapeamento de Produtos (Cérebro)")

    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])

    if not client or not models_cache:
        st.info(
            "Configure as credenciais e clique em 'Sincronizar Dados da Shopee' na barra lateral."
        )
        return

    groups = load_groups()
    ungrouped_models = filter_ungrouped_models(models_cache, groups)

    st.write(
        f"Modelos não agrupados atualmente: **{len(ungrouped_models)}** (variações Shopee)."
    )

    # --- Sugestões automáticas (pré-agrupamento) ---
    if "mapping_suggestion_active" not in st.session_state:
        st.session_state["mapping_suggestion_active"] = False
    if "mapping_suggestion_keys" not in st.session_state:
        st.session_state["mapping_suggestion_keys"] = []
    if "mapping_selected_keys" not in st.session_state:
        st.session_state["mapping_selected_keys"] = []

    with st.expander("Sugestões automáticas (tecido + cor)"):
        suggestions_all = build_suggested_fabric_color_groups(ungrouped_models, min_group_size=2)
        suggestions = suggestions_all
        if not suggestions:
            st.info("Nenhuma sugestão automática encontrada (ainda).")
        else:
            # Mantém uma lista menor para não poluir a UI
            max_show = 60
            suggestions = suggestions[:max_show]

            def _fmt_sug(d: Dict[str, Any]) -> str:
                return f"{d.get('fabric_label')} | {d.get('color_label')} — {d.get('count')} variações"

            selected_suggestion = st.selectbox(
                "Escolha uma sugestão para carregar:",
                options=list(range(len(suggestions))),
                format_func=lambda i: _fmt_sug(suggestions[int(i)]),
            )

            cols = st.columns([1, 1, 2])
            if cols[0].button("Carregar sugestão"):
                sug = suggestions[int(selected_suggestion)]
                st.session_state["mapping_suggestion_active"] = True
                st.session_state["mapping_suggestion_keys"] = list(sug.get("model_keys") or [])
                st.session_state["mapping_selected_keys"] = list(sug.get("model_keys") or [])

                # Preenche Nome Mestre automaticamente (tecido + cor)
                fabric_label = str(sug.get("fabric_label") or "").strip()
                color_label = str(sug.get("color_label") or "").strip()
                if color_label and color_label != "(Sem cor)":
                    st.session_state["master_name_input"] = f"{fabric_label} {color_label}".strip()
                else:
                    st.session_state["master_name_input"] = fabric_label

                st.rerun()

            # Criação automática em massa (sem precisar salvar grupo a grupo)
            if cols[2].button("Criar TODOS os grupos sugeridos"):
                # Índice rápido model_key -> model
                model_by_key: Dict[str, Dict[str, Any]] = {}
                for m in ungrouped_models:
                    mk = f"{m.get('item_id')}:{m.get('model_id') if m.get('model_id') is not None else 'none'}"
                    model_by_key[mk] = m

                groups = load_groups()
                created = 0
                skipped = 0
                with st.spinner("Criando grupos automaticamente..."):
                    for sug in suggestions_all:
                        model_keys = list(sug.get("model_keys") or [])
                        selected_models = [model_by_key.get(k) for k in model_keys]
                        selected_models = [m for m in selected_models if m is not None]

                        if len(selected_models) < 2:
                            skipped += 1
                            continue

                        fabric_label = str(sug.get("fabric_label") or "").strip()
                        color_label = str(sug.get("color_label") or "").strip()
                        master_name = f"{fabric_label} {color_label}".strip() if color_label and color_label != "(Sem cor)" else fabric_label
                        if not master_name:
                            skipped += 1
                            continue

                        group_id = str(uuid.uuid4())
                        item_ids = sorted({int(m["item_id"]) for m in selected_models})
                        model_ids = sorted({int(m["model_id"]) for m in selected_models if m.get("model_id") is not None})

                        new_group = {
                            "group_id": group_id,
                            "master_name": master_name,
                            "items": [
                                {
                                    "item_id": int(m["item_id"]),
                                    "model_id": m.get("model_id"),
                                    "item_name": m.get("item_name", ""),
                                    "model_name": m.get("model_name", ""),
                                }
                                for m in selected_models
                            ],
                            "shopee_item_ids": item_ids,
                            "shopee_model_ids": model_ids,
                        }

                        groups.append(new_group)
                        created += 1

                try:
                    save_groups(groups)
                    st.success(f"Grupos criados automaticamente: {created} (ignorados: {skipped}).")
                    st.session_state["mapping_suggestion_active"] = False
                    st.session_state["mapping_suggestion_keys"] = []
                    st.session_state["mapping_selected_keys"] = []
                    st.rerun()
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Falha ao salvar grupos criados automaticamente: {exc}")

            if st.session_state.get("mapping_suggestion_active"):
                if cols[1].button("Limpar sugestão"):
                    st.session_state["mapping_suggestion_active"] = False
                    st.session_state["mapping_suggestion_keys"] = []
                    st.session_state["mapping_selected_keys"] = []
                    st.rerun()

                cols[2].caption(
                    "Dica: sugestões usam a âncora 'RAZAI' no título e o nome da variação como cor. "
                    "Revise antes de salvar o grupo."
                )

    with st.expander("Ver itens ignorados nas sugestões (Diagnóstico)"):
        st.caption("Lista de itens que não entraram nas sugestões automáticas e o motivo.")

        # Re-executa lógica similar para diagnosticar
        diagnosis_data = []
        temp_buckets: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

        for m in ungrouped_models:
            fabric_key = extract_fabric_from_title(str(m.get("item_name") or ""))
            if not fabric_key:
                diagnosis_data.append({
                    "Item": m.get("display_name"),
                    "Motivo": "Tecido não identificado (título fora do padrão?)"
                })
                continue

            color_key = extract_color_from_model(str(m.get("model_name") or ""), str(m.get("item_name") or ""))
            temp_buckets.setdefault((fabric_key, color_key), []).append(m)

        for (fk, ck), items in temp_buckets.items():
            if len(items) < 2:
                for m in items:
                    diagnosis_data.append({
                        "Item": m.get("display_name"),
                        "Motivo": f"Grupo isolado (único item com Tecido='{fk}' e Cor='{ck}')"
                    })

        if diagnosis_data:
            st.dataframe(pd.DataFrame(diagnosis_data), use_container_width=True)
        else:
            st.info("Todos os itens não agrupados geraram alguma sugestão.")

    query = st.text_input("Buscar por título/variação (ex: 'Viscose'):", key="mapping_query")

    if st.session_state.get("mapping_suggestion_active") and st.session_state.get("mapping_suggestion_keys"):
        # Quando uma sugestão está ativa, mostramos apenas os itens sugeridos
        filtered_models = [
            m
            for m in ungrouped_models
            if f"{m.get('item_id')}:{m.get('model_id') if m.get('model_id') is not None else 'none'}"
            in set(st.session_state.get("mapping_suggestion_keys") or [])
        ]
    else:
        filtered_models = search_models(ungrouped_models, query)

    if not filtered_models:
        st.warning("Nenhum resultado encontrado para o filtro atual.")
        return

    # Monta dicionário para multiseleção
    options_keys = []
    key_to_model: Dict[str, Dict[str, Any]] = {}
    labels = []
    for m in filtered_models:
        item_id = m.get("item_id")
        model_id = m.get("model_id")
        key = f"{item_id}:{model_id if model_id is not None else 'none'}"
        label = f"[{item_id}/{model_id if model_id is not None else '-'}] {m.get('display_name', '')}"
        options_keys.append(key)
        key_to_model[key] = m
        labels.append(label)

    # Usamos multiselect com rótulos amigáveis
    # Para manter chave estável, usamos options=options_keys e format_func.
    selected_keys = st.multiselect(
        "Selecione as variações que pertencem ao MESMO tecido físico:",
        options=options_keys,
        format_func=lambda k: str(key_to_model[k].get("short_display_name") or key_to_model[k].get("display_name") or ""),
        key="mapping_selected_keys",
    )

    # Sugestão automática baseada nos títulos (tecido + estampa + cor)
    if st.button("Sugerir Nome Mestre pelos títulos"):
        if selected_keys:
            selected_models = [key_to_model[k] for k in selected_keys]
            st.session_state["master_name_input"] = suggest_master_name(selected_models)
        else:
            st.warning("Selecione ao menos uma variação para sugerir o nome.")

    master_name = st.text_input(
        "Nome Mestre para o grupo (ex: 'Viscose Estampada Azul'):",
        key="master_name_input",
    )

    if st.button("Salvar Grupo"):
        if not selected_keys:
            st.error("Selecione ao menos uma variação para criar o grupo.")
            return
        if not master_name.strip():
            st.error("Informe um Nome Mestre para o grupo.")
            return

        selected_models = [key_to_model[k] for k in selected_keys]

        group_id = str(uuid.uuid4())
        item_ids = sorted({int(m["item_id"]) for m in selected_models})
        model_ids = sorted(
            {
                int(m["model_id"])
                for m in selected_models
                if m.get("model_id") is not None
            }
        )

        new_group = {
            "group_id": group_id,
            "master_name": master_name.strip(),
            "items": [
                {
                    "item_id": int(m["item_id"]),
                    "model_id": m.get("model_id"),
                    "item_name": m.get("item_name", ""),
                    "model_name": m.get("model_name", ""),
                }
                for m in selected_models
            ],
            # Estrutura de exemplo solicitada no enunciado
            "shopee_item_ids": item_ids,
            "shopee_model_ids": model_ids,
        }

        groups.append(new_group)
        try:
            save_groups(groups)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Falha ao salvar o grupo no JSON local: {exc}")
            return

        st.success(
            f"Grupo criado com sucesso: '{master_name.strip()}' com {len(selected_models)} variações."
        )

        # Atualiza imediatamente a visão removendo os modelos recém-agrupados
        try:
            st.rerun()
        except Exception:
            st.experimental_rerun()


def tab_inventory():
    """Aba 2: Gestão de Estoque (Painel de Controle)."""
    st.subheader("Aba 2 - Gestão de Estoque (Painel de Controle)")

    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])

    col_refresh, col_hint = st.columns([1, 3])
    if col_refresh.button("Recarregar estoque atual da Shopee"):
        if not client:
            st.error("Cliente Shopee não inicializado. Configure e sincronize na barra lateral.")
        else:
            try:
                with st.spinner("Recarregando itens e estoques da Shopee..."):
                    fresh_cache = build_models_cache(client)
                st.session_state["models_cache"] = fresh_cache
                st.session_state["last_sync_ts"] = int(time.time())
                with_stock = sum(1 for m in fresh_cache if m.get("normal_stock") is not None)
                st.success(f"Estoque recarregado. Modelos: {len(fresh_cache)} | Com estoque: {with_stock}")
                st.rerun()
            except Exception as exc:  # noqa: BLE001
                st.error(f"Falha ao recarregar estoque: {exc}")

    col_hint.caption("Dica: isso atualiza os números de estoque exibidos abaixo.")

    # Teste rápido (somente leitura) para ajudar debug de estoque/credenciais
    with st.expander("Teste de requisição (somente leitura)"):
        st.caption(
            "Roda um preflight na Shopee para verificar se o app consegue ler itens/models e se a resposta contém campos de estoque. "
            "Isso não altera nada na loja."
        )
        if st.button("Executar teste de requisição"):
            if not client:
                st.error("Cliente Shopee não inicializado. Configure e sincronize na barra lateral.")
            else:
                try:
                    # Preferir testar usando um item que exista nos grupos (mais relevante)
                    groups_for_test = load_groups()
                    sample_item_id = None
                    for g in groups_for_test:
                        items = g.get("items", []) or []
                        if items:
                            try:
                                sample_item_id = int(items[0].get("item_id"))
                                break
                            except Exception:
                                continue

                    with st.spinner("Executando preflight de leitura..."):
                        info = client.preflight_read_check(sample_item_id=sample_item_id)
                    st.success("Teste OK. Veja detalhes:")
                    st.json(info)
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Teste falhou: {exc}")

    groups = load_groups()
    if not groups:
        st.info("Nenhum grupo mestre criado ainda. Use a Aba 1 para criar.")
        return

    if not client:
        st.warning(
            "Configurações de credenciais não encontradas. Configure e sincronize na barra lateral antes de atualizar estoques."
        )

    # Índice rápido para obter estoque atual de cada (item_id, model_id)
    def _norm_mid(mid: Any) -> Optional[int]:
        if mid is None:
            return None
        try:
            return int(mid)
        except Exception:
            return None

    stock_index: Dict[Tuple[int, Optional[int]], Optional[int]] = {}
    cache_positions: Dict[Tuple[int, Optional[int]], List[int]] = {}
    for idx, m in enumerate(models_cache):
        key = (int(m.get("item_id")), _norm_mid(m.get("model_id")))
        stock_index[key] = m.get("normal_stock")
        cache_positions.setdefault(key, []).append(idx)

    st.markdown("**Grupos Mestres cadastrados (organizados por tecido):**")

    def _group_fabric_key(g: Dict[str, Any]) -> str:
        # Preferir inferir pelo título do item (mais consistente que master_name)
        items = g.get("items", []) or []
        counts: Dict[str, int] = {}
        for it in items:
            fk = extract_fabric_from_title(str(it.get("item_name") or ""))
            if fk:
                counts[fk] = counts.get(fk, 0) + 1
        if counts:
            return max(counts.items(), key=lambda kv: kv[1])[0]

        # Fallback: tenta usar o começo do master_name (antes de cor comum)
        mk = extract_fabric_from_title(str(g.get("master_name") or ""))
        return mk or "(sem tecido)"

    # Agrupa por tecido
    fabric_to_groups: Dict[str, List[Dict[str, Any]]] = {}
    for g in groups:
        fabric_key = _group_fabric_key(g)
        fabric_to_groups.setdefault(fabric_key, []).append(g)

    # Ordenação estável por rótulo legível
    fabric_keys_sorted = sorted(
        fabric_to_groups.keys(),
        key=lambda k: (_titleize_words(k) if k and k != "(sem tecido)" else "zzz"),
    )

    for fabric_key in fabric_keys_sorted:
        fabric_label = _titleize_words(fabric_key) if fabric_key and fabric_key != "(sem tecido)" else "(Sem tecido)"
        st.markdown(f"### {fabric_label}")

        # Cabeçalho da "tabela visual" por tecido
        header_cols = st.columns([3, 2, 3, 2])
        header_cols[0].markdown("**Nome Mestre**")
        header_cols[1].markdown("**Qtd Itens Vinculados**")
        header_cols[2].markdown("**Estoque Atual (Média)**")
        header_cols[3].markdown("**Novo Estoque**")

        # Campos de entrada (um por grupo)
        for g in fabric_to_groups.get(fabric_key, []):
            group_id = g.get("group_id")
            items = g.get("items", [])

            # Calcula soma/média usando o índice de estoque
            stocks: List[int] = []
            for it in items:
                key = (int(it.get("item_id")), _norm_mid(it.get("model_id")))
                s = stock_index.get(key)
                if s is not None:
                    stocks.append(int(s))

            if stocks:
                media = sum(stocks) / len(stocks)
                # Mostra como inteiro quando faz sentido
                estoque_str = f"{media:.1f}" if abs(media - round(media)) > 1e-9 else f"{int(round(media))}"
            else:
                estoque_str = "-"

            cols = st.columns([3, 2, 3, 2])
            cols[0].write(g.get("master_name", "(sem nome)"))
            cols[1].write(len(items))
            cols[2].write(estoque_str)

            # Campo de digitação do novo estoque (string, para permitir vazio)
            cols[3].text_input(
                "",
                key=f"new_stock_{group_id}",
                placeholder="ex: 0",
            )

    if st.button("Atualizar Estoque em Massa"):
        if not client:
            st.error(
                "Cliente Shopee não inicializado. Configure credenciais e sincronize na barra lateral."
            )
            return

        # Preflight (somente leitura) antes de atualizar, para evitar operação cega.
        try:
            groups_for_test = groups
            sample_item_id = None
            for g in groups_for_test:
                items = g.get("items", []) or []
                if items:
                    try:
                        sample_item_id = int(items[0].get("item_id"))
                        break
                    except Exception:
                        continue
            _preflight = client.preflight_read_check(sample_item_id=sample_item_id)
            st.info(
                "Preflight OK (somente leitura). "
                f"Item testado: {_preflight.get('sample_item_id')} | "
                f"Campos de estoque detectados: {', '.join(_preflight.get('stock_fields_found') or []) or '(nenhum)'}"
            )
        except Exception as exc:  # noqa: BLE001
            st.error(
                "Não vou atualizar estoque porque o teste de requisição falhou. "
                f"Detalhes: {exc}"
            )
            return

        if st.session_state.get("api_env") == "Produção":
            if not st.session_state.get("confirm_prod_update"):
                st.error(
                    "Para Produção, marque a confirmação antes de atualizar estoques."
                )
                return

        total_success = 0
        errors: List[Dict[str, Any]] = []

        for g in groups:
            group_id = g.get("group_id")
            raw_value = st.session_state.get(f"new_stock_{group_id}", "").strip()
            if raw_value == "":
                # Usuário não quer atualizar este grupo
                continue

            try:
                new_stock = int(raw_value)
                if new_stock < 0:
                    raise ValueError("Estoque não pode ser negativo")
            except ValueError:
                errors.append(
                    {
                        "group_id": group_id,
                        "master_name": g.get("master_name"),
                        "error": f"Valor de estoque inválido: '{raw_value}'",
                    }
                )
                continue

            # Agrupa models por item_id para reduzir chamadas
            per_item: Dict[int, List[Optional[int]]] = {}
            for it in g.get("items", []):
                item_id = int(it.get("item_id"))
                model_id = _norm_mid(it.get("model_id"))
                per_item.setdefault(item_id, []).append(model_id)

            for item_id, model_ids in per_item.items():
                try:
                    client.update_stock(item_id=item_id, model_ids=model_ids, new_stock=new_stock)
                    total_success += len(model_ids) if any(m is not None for m in model_ids) else 1

                    # Atualiza cache local para refletir o novo estoque imediatamente.
                    if not model_ids or all(m is None for m in model_ids):
                        # Estoque no nível do item (model_id=None)
                        key = (int(item_id), None)
                        stock_index[key] = int(new_stock)
                        for pos in cache_positions.get(key, []):
                            try:
                                st.session_state["models_cache"][pos]["normal_stock"] = int(new_stock)
                            except Exception:
                                pass
                    else:
                        for mid in model_ids:
                            if mid is None:
                                continue
                            key = (int(item_id), int(mid))
                            stock_index[key] = int(new_stock)
                            for pos in cache_positions.get(key, []):
                                try:
                                    st.session_state["models_cache"][pos]["normal_stock"] = int(new_stock)
                                except Exception:
                                    pass
                except Exception as exc:  # noqa: BLE001
                    # Não interromper todo o processamento; apenas registrar o erro
                    errors.append(
                        {
                            "group_id": group_id,
                            "master_name": g.get("master_name"),
                            "item_id": item_id,
                            "model_ids": model_ids,
                            "error": str(exc),
                        }
                    )

        if total_success:
            st.success(
                f"Atualização de estoque concluída para aproximadamente {total_success} variações/anúncios."
            )
        else:
            st.info("Nenhum estoque foi atualizado (nenhum valor informado ou todos inválidos).")

        if errors:
            st.error(
                "Algumas atualizações falharam. Veja detalhes abaixo para correção manual ou nova tentativa."
            )
            st.json(errors)


    if st.session_state.get("api_env") == "Produção":
        st.checkbox(
            "Confirmo que quero atualizar estoques na Shopee (Produção)",
            key="confirm_prod_update",
        )


def main():
    st.set_page_config(page_title="IMS Shopee - Tecidos", layout="wide")
    st.title("Sistema de Gestão de Estoque Unificado (IMS) - Shopee")

    st.markdown(
        """
        Este painel foi projetado para lojistas de **tecidos** na Shopee que
        possuem **múltiplos anúncios para o mesmo produto físico** (estratégia de SEO).

        - A **Aba 1 (Mapeamento)** é o "cérebro" onde você agrupa variações da Shopee
          em **Grupos Mestres**.
        - A **Aba 2 (Gestão de Estoque)** mostra apenas os **Grupos Mestres** e permite
          atualizar o estoque de todos os anúncios vinculados de uma só vez
          (via `v2.product.update_stock`, conforme documentação da Shopee Open Platform).
        """
    )

    init_session_state()
    sidebar_setup()

    tab1, tab2 = st.tabs(["Mapeamento de Produtos", "Gestão de Estoque"])

    with tab1:
        tab_mapping()

    with tab2:
        tab_inventory()


if __name__ == "__main__":
    main()

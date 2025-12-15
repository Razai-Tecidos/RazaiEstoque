import os
import time
import hmac
import json
import uuid
import hashlib
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import requests
import pandas as pd
import streamlit as st
from difflib import SequenceMatcher


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
CREDS_FILE = "razaiestoque.txt"


# ==========================
# Utilidades de Persistência Local (JSON)
# ==========================

def load_groups() -> List[Dict[str, Any]]:
    """Carrega grupos de produtos a partir de um arquivo JSON local.

    Estrutura base (por grupo):
    {
        "group_id": str,
        "master_name": str,
        "items": [
            {
                "item_id": int,
                "model_id": Optional[int],
                "item_name": str,
                "model_name": str,
            },
            ...
        ],
        "shopee_item_ids": [int, ...],
        "shopee_model_ids": [int, ...]
    }
    """
    if not os.path.exists(GROUPS_FILE):
        return []

    try:
        with open(GROUPS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    # Suporte tanto para lista direta quanto para {"groups": [...]}
    if isinstance(data, dict) and "groups" in data:
        return data["groups"] or []
    if isinstance(data, list):
        return data
    return []


def save_groups(groups: List[Dict[str, Any]]) -> None:
    """Salva grupos de produtos no arquivo JSON local."""
    payload = {"groups": groups}
    with open(GROUPS_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


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
    - SHOPEE_API_BASE_URL
    """
    mapping = {
        "partner_id": "SHOPEE_PARTNER_ID",
        "partner_key": "SHOPEE_PARTNER_KEY",
        "shop_id": "SHOPEE_SHOP_ID",
        "access_token": "SHOPEE_ACCESS_TOKEN",
        "refresh_token": "SHOPEE_REFRESH_TOKEN",
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

    def exchange_code_for_token(self, code: str, shop_id: int) -> Dict[str, Any]:
        """Troca `code` por access_token/refresh_token (v2.public.get_access_token)."""
        path = "/api/v2/auth/token/get"
        body = {"partner_id": self.partner_id, "code": str(code), "shop_id": int(shop_id)}
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

    def get_model_list(self, item_id: int) -> List[Dict[str, Any]]:
        """Retorna a lista de modelos (variações) para um item.

        Ver docs: Product > Get Model List (Shopee Open Platform v2).
        """
        # Path completo incluindo "/api/v2" conforme docs de Get Model List
        path = "/api/v2/product/get_model_list"
        params = {"item_id": int(item_id)}
        data = self._make_request("GET", path, params=params)
        models = data.get("response", {}).get("model", []) or []
        return models

    def update_stock(
        self,
        item_id: int,
        model_ids: Optional[List[Optional[int]]],
        new_stock: int,
    ) -> Dict[str, Any]:
        """Atualiza estoque de um item/model(s) usando /api/v2/product/update_stock.

        - Se model_ids for None ou contiver apenas None, aplica estoque no nível do item.
        - Caso contrário, envia stock_list para cada model_id.

        Ver docs: Product > Update Stock (Shopee Open Platform v2).
        """
        # Path completo incluindo "/api/v2" conforme docs de Update Stock
        path = "/api/v2/product/update_stock"
        body: Dict[str, Any] = {"item_id": int(item_id)}

        # Sem variações (estoque no nível do item)
        if not model_ids or all(m is None for m in model_ids):
            body["stock"] = new_stock
        else:
            stock_list = [
                {"model_id": int(mid), "normal_stock": int(new_stock)}
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
    models_cache: List[Dict[str, Any]] = []

    for item in items:
        item_id = item.get("item_id")
        item_name = item.get("item_name", "")
        has_model = item.get("has_model", False)

        if has_model:
            models = client.get_model_list(item_id)
            for m in models:
                model_id = m.get("model_id")
                model_name = m.get("model_name", "")
                normal_stock = m.get("normal_stock")
                display_name = f"{item_name} - {model_name}" if model_name else item_name
                models_cache.append(
                    {
                        "item_id": item_id,
                        "model_id": model_id,
                        "item_name": item_name,
                        "model_name": model_name,
                        "display_name": display_name,
                        "normal_stock": normal_stock,
                    }
                )
        else:
            # Item sem variações: tratamos como um "modelo único" com model_id=None
            normal_stock = item.get("stock") or item.get("normal_stock")
            display_name = item_name
            models_cache.append(
                {
                    "item_id": item_id,
                    "model_id": None,
                    "item_name": item_name,
                    "model_name": "",
                    "display_name": display_name,
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

    q = query.lower()
    filtered: List[Tuple[float, Dict[str, Any]]] = []

    for m in models:
        text = f"{m.get('item_name', '')} {m.get('model_name', '')}".lower()
        if q in text:
            ratio = SequenceMatcher(None, q, text).ratio()
            if ratio >= min_ratio:
                filtered.append((ratio, m))

    # Ordena da maior similaridade para a menor
    filtered.sort(key=lambda t: t[0], reverse=True)
    return [m for _, m in filtered]


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
    if "last_token_refresh_ts" not in st.session_state:
        st.session_state["last_token_refresh_ts"] = None
    if "_auto_token_bootstrap_done" not in st.session_state:
        st.session_state["_auto_token_bootstrap_done"] = False
    if "_last_oauth_code_exchanged" not in st.session_state:
        st.session_state["_last_oauth_code_exchanged"] = ""


def sidebar_setup() -> None:
    st.sidebar.header("Configurações Shopee (Setup)")

    # Pré-carrega credenciais (sem salvar em disco):
    # 1) arquivo local somente leitura (sandbox/teste)
    # 2) variáveis de ambiente (ideal para produção)
    file_creds = load_test_credentials_from_file()
    secrets_creds = load_credentials_from_streamlit_secrets()
    env_creds = load_credentials_from_env()

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

    # Se veio shop_id no redirect, isso é Live e ajuda a preencher automaticamente.
    if qp_shop_id and not file_creds.get("live_shop_id"):
        file_creds["live_shop_id"] = qp_shop_id

    preferred_env = st.session_state.get("api_env", "Produção")
    if preferred_env == "Sandbox":
        preferred_partner_id = file_creds.get("test_partner_id")
        preferred_partner_key = file_creds.get("test_partner_key")
        preferred_shop_id = file_creds.get("test_shop_id")
        preferred_access_token = file_creds.get("test_access_token")
    else:
        preferred_partner_id = file_creds.get("live_partner_id")
        preferred_partner_key = file_creds.get("live_partner_key")
        preferred_shop_id = file_creds.get("live_shop_id")
        preferred_access_token = None

    # Preenche automaticamente com base no ambiente atual.
    # Por padrão, preferimos LIVE em Produção e também substituímos valores de Sandbox
    # quando detectados (ex.: partner_id/shop_id de teste).
    current_partner_id = str(st.session_state.get("partner_id") or "").strip()
    current_partner_key = str(st.session_state.get("partner_key") or "").strip()
    current_shop_id = str(st.session_state.get("shop_id") or "").strip()
    current_access_token = str(st.session_state.get("access_token") or "").strip()

    test_partner_id = str(file_creds.get("test_partner_id") or "").strip()
    test_partner_key = str(file_creds.get("test_partner_key") or "").strip()
    test_shop_id = str(file_creds.get("test_shop_id") or "").strip()
    test_access_token = str(file_creds.get("test_access_token") or "").strip()

    allow_overwrite = preferred_env == "Produção"

    if preferred_partner_id and (not current_partner_id or (allow_overwrite and current_partner_id == test_partner_id)):
        st.session_state["partner_id"] = str(preferred_partner_id)
    if preferred_partner_key and (not current_partner_key or (allow_overwrite and current_partner_key == test_partner_key)):
        st.session_state["partner_key"] = str(preferred_partner_key)
    if preferred_shop_id and (not current_shop_id or (allow_overwrite and current_shop_id == test_shop_id)):
        st.session_state["shop_id"] = str(preferred_shop_id)

    # Access token só é auto-preenchido no Sandbox (token de teste). Em Produção, o correto
    # é obter via OAuth (code -> access_token).
    if preferred_access_token and (not current_access_token or current_access_token == test_access_token):
        st.session_state["access_token"] = str(preferred_access_token)

    # Secrets (Streamlit Cloud) e ENV têm prioridade sobre arquivo local.
    for source in (secrets_creds, env_creds):
        if source.get("partner_id") and not st.session_state.get("partner_id"):
            st.session_state["partner_id"] = str(source["partner_id"])
        if source.get("partner_key") and not st.session_state.get("partner_key"):
            st.session_state["partner_key"] = str(source["partner_key"])
        if source.get("shop_id") and not st.session_state.get("shop_id"):
            st.session_state["shop_id"] = str(source["shop_id"])
        if source.get("access_token") and not st.session_state.get("access_token"):
            st.session_state["access_token"] = str(source["access_token"])
        if source.get("refresh_token") and not st.session_state.get("refresh_token"):
            st.session_state["refresh_token"] = str(source["refresh_token"])
        if source.get("api_base_url") and not st.session_state.get("api_base_url"):
            st.session_state["api_base_url"] = str(source["api_base_url"])

    st.sidebar.caption(
        "Dica: em **Produção (Live)** use as credenciais LIVE do console Shopee e obtenha o token via OAuth. "
        "Em **Sandbox (Teste)** use as credenciais TEST + shop/token do sandbox."
    )

    partner_id = st.sidebar.text_input(
        "Partner ID",
        key="partner_id",
        help=(
            "Produção/Live: use o **Live Partner_id** do seu app no Shopee Open Platform. "
            "Sandbox/Teste: use o **Test Partner_id**."
        ),
    )
    partner_key = st.sidebar.text_input(
        "Partner Key (HMAC)",
        type="password",
        key="partner_key",
        help=(
            "Produção/Live: use a **Live API Partner Key**. "
            "Sandbox/Teste: use a **Test API Partner Key**."
        ),
    )
    shop_id = st.sidebar.text_input(
        "Shop ID",
        key="shop_id",
        help=(
            "Produção/Live: use o **shop_id da sua loja real** (normalmente vem no redirect do OAuth). "
            "Sandbox/Teste: use o **Shop ID do sandbox**."
        ),
    )
    access_token = st.sidebar.text_input(
        "Access Token",
        type="password",
        key="access_token",
        help=(
            "Produção/Live: é o **access_token LIVE** obtido ao trocar o `code` no bloco OAuth abaixo. "
            "Sandbox/Teste: use o token de teste (ex.: AccessTokenTest)."
        ),
    )

    # Mostra o refresh_token para permitir salvar em Secrets (Streamlit Cloud).
    # Sem isso, o usuário não consegue persistir o token entre reinícios.
    st.sidebar.text_input(
        "Refresh Token (Live)",
        type="password",
        key="refresh_token",
        help=(
            "Produção/Live: token de longa duração retornado no OAuth e/ou ao renovar. "
            "Recomendado salvar no Streamlit Cloud em Secrets como SHOPEE_REFRESH_TOKEN."
        ),
    )

    with st.sidebar.expander("Opções avançadas (API)"):
        api_env = st.selectbox(
            "Ambiente",
            options=["Sandbox", "Produção"],
            key="api_env",
            help=(
                "Sandbox para testes; Produção atualiza a loja real. "
                "O host padrão é preenchido automaticamente."
            ),
        )

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
            key="api_base_url",
            help=(
                "Host base da API Shopee (somente o host, sem /api/v2). "
                "Para BR (produção): https://openplatform.shopee.com.br . "
                "Para Global (produção): https://partner.shopeemobile.com . "
                "Para sandbox: use o host indicado no API Test Tool (ex.: ...sandbox...sg)."
            ),
        )

        if api_env == "Produção":
            st.warning(
                "Produção: as atualizações de estoque afetam sua loja real.",
                icon="⚠️",
            )

        # Auto-renovação: se houver refresh_token (Secrets/ENV), evita ter que reautorizar.
        if (
            api_env == "Produção"
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
                with st.spinner("Renovando access token automaticamente (refresh_token)..."):
                    token_data = tmp_client.refresh_access_token(
                        refresh_token=str(st.session_state.get("refresh_token") or "").strip(),
                        shop_id=int(str(st.session_state.get("shop_id") or "0").strip()),
                    )
                st.session_state["access_token"] = str(token_data.get("access_token", ""))
                new_rt = str(token_data.get("refresh_token", "") or "").strip()
                if new_rt:
                    st.session_state["refresh_token"] = new_rt
                st.session_state["last_token_refresh_ts"] = int(time.time())
                if st.session_state.get("access_token"):
                    st.success("Access token renovado automaticamente via refresh_token.")
                if new_rt and previous_rt and new_rt != previous_rt:
                    st.info(
                        "A Shopee rotacionou seu refresh_token. Atualize o Secrets do Streamlit Cloud com o novo valor:\n"
                        f"SHOPEE_REFRESH_TOKEN = \"{new_rt}\""
                    )
            except Exception as exc:  # noqa: BLE001
                st.warning(f"Não foi possível auto-renovar o token: {exc}")
            finally:
                st.session_state["_auto_token_bootstrap_done"] = True

        st.divider()
        st.markdown("**OAuth (Live) – trocar code por token**")
        st.caption(
            "Após autorizar no console, cole aqui o `code` e o `shop_id` retornados no redirect. "
            "O token é salvo apenas na sessão do Streamlit."
        )

        # Ajuda de copy/paste para Secrets
        if str(st.session_state.get("refresh_token") or "").strip():
            rt_for_copy = str(st.session_state.get("refresh_token") or "").strip()
            st.code(f'SHOPEE_REFRESH_TOKEN = "{rt_for_copy}"')

        oauth_code = st.text_input(
            "Authorization code (somente Live)",
            key="oauth_code",
            help="Produção/Live: code do redirect do OAuth. Válido por poucos minutos e uso único.",
        )
        oauth_shop_id = st.text_input(
            "Shop ID (do redirect – Live)",
            key="oauth_shop_id",
            help="Produção/Live: shop_id retornado no redirect do OAuth (da sua loja real).",
        )

        col_a, col_b = st.columns(2)

        if col_a.button("Trocar code por access token"):
            if not (partner_id and partner_key and api_base_url):
                st.error("Preencha Partner ID, Partner Key e API Base URL antes.")
            elif not (oauth_code.strip() and oauth_shop_id.strip()):
                st.error("Preencha o code e o shop_id retornados no redirect.")
            else:
                try:
                    code_to_exchange = oauth_code.strip()
                    if code_to_exchange == str(st.session_state.get("_last_oauth_code_exchanged") or ""):
                        st.warning(
                            "Esse code já foi tentado nesta sessão. Gere um novo code no Open Platform e tente novamente."
                        )
                        st.stop()

                    tmp_client = ShopeeClient(
                        partner_id=int(partner_id),
                        partner_key=partner_key,
                        shop_id=0,
                        access_token="",
                        base_url=api_base_url or BASE_URL,
                    )
                    with st.spinner("Trocando code por token..."):
                        token_data = tmp_client.exchange_code_for_token(
                            code=code_to_exchange,
                            shop_id=int(oauth_shop_id.strip()),
                        )

                    st.session_state["_last_oauth_code_exchanged"] = code_to_exchange

                    st.session_state["shop_id"] = str(oauth_shop_id.strip())
                    st.session_state["access_token"] = str(token_data.get("access_token", ""))
                    st.session_state["refresh_token"] = str(token_data.get("refresh_token", ""))
                    st.session_state["last_token_refresh_ts"] = int(time.time())

                    if st.session_state["access_token"]:
                        st.success("Token obtido com sucesso. Agora clique em 'Sincronizar Dados da Shopee'.")
                        if st.session_state.get("refresh_token"):
                            st.info(
                                "Para não precisar reautorizar no Open Platform toda vez, salve também o refresh_token no Streamlit Cloud em Secrets como: "
                                "SHOPEE_REFRESH_TOKEN = \"...\""
                            )
                    else:
                        st.warning("Resposta sem access_token. Verifique a resposta abaixo.")
                        st.json(token_data)
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Falha ao obter token: {exc}")

        if col_b.button("Renovar access token (refresh_token)"):
            rt = str(st.session_state.get("refresh_token") or "").strip()
            sid = str(st.session_state.get("shop_id") or "").strip()
            if not (partner_id and partner_key and api_base_url):
                st.error("Preencha Partner ID, Partner Key e API Base URL antes.")
            elif not (rt and sid):
                st.error("Precisa ter refresh_token e shop_id na sessão (faça a troca do code primeiro).")
            else:
                try:
                    previous_rt = rt
                    tmp_client = ShopeeClient(
                        partner_id=int(partner_id),
                        partner_key=partner_key,
                        shop_id=0,
                        access_token="",
                        base_url=api_base_url or BASE_URL,
                    )
                    with st.spinner("Renovando access token..."):
                        token_data = tmp_client.refresh_access_token(
                            refresh_token=rt,
                            shop_id=int(sid),
                        )
                    st.session_state["access_token"] = str(token_data.get("access_token", ""))
                    new_rt = str(token_data.get("refresh_token", "") or "").strip()
                    if new_rt:
                        st.session_state["refresh_token"] = new_rt
                    st.session_state["last_token_refresh_ts"] = int(time.time())
                    st.success("Access token renovado. Agora você pode sincronizar novamente.")
                    if new_rt and previous_rt and new_rt != previous_rt:
                        st.info(
                            "A Shopee rotacionou seu refresh_token. Atualize o Secrets do Streamlit Cloud com o novo valor:\n"
                            f"SHOPEE_REFRESH_TOKEN = \"{new_rt}\""
                        )
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Falha ao renovar token: {exc}")

    st.sidebar.caption(
        "As credenciais não são salvas em disco; apenas em sessão."
    )

    if st.sidebar.button("Sincronizar Dados da Shopee"):
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

                st.sidebar.success(
                    f"Sincronização concluída. Modelos carregados: {len(models_cache)}"
                )
            except Exception as exc:  # noqa: BLE001
                st.sidebar.error(f"Erro ao sincronizar com a Shopee: {exc}")


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

    query = st.text_input("Buscar por título/variação (ex: 'Viscose'):")
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
        format_func=lambda k: f"{k} - {key_to_model[k]['display_name']}",
    )

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
        st.experimental_rerun()


def tab_inventory():
    """Aba 2: Gestão de Estoque (Painel de Controle)."""
    st.subheader("Aba 2 - Gestão de Estoque (Painel de Controle)")

    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])

    groups = load_groups()
    if not groups:
        st.info("Nenhum grupo mestre criado ainda. Use a Aba 1 para criar.")
        return

    if not client:
        st.warning(
            "Configurações de credenciais não encontradas. Configure e sincronize na barra lateral antes de atualizar estoques."
        )

    # Índice rápido para obter estoque atual de cada (item_id, model_id)
    stock_index: Dict[Tuple[int, Optional[int]], Optional[int]] = {}
    for m in models_cache:
        key = (int(m.get("item_id")), m.get("model_id"))
        stock_index[key] = m.get("normal_stock")

    st.markdown("**Grupos Mestres cadastrados:**")

    # Cabeçalho da "tabela visual"
    header_cols = st.columns([3, 2, 3, 2])
    header_cols[0].markdown("**Nome Mestre**")
    header_cols[1].markdown("**Qtd Itens Vinculados**")
    header_cols[2].markdown("**Estoque Atual (Soma/Média)**")
    header_cols[3].markdown("**Novo Estoque**")

    # Campos de entrada (um por grupo)
    for g in groups:
        group_id = g.get("group_id")
        items = g.get("items", [])

        # Calcula soma/média usando o índice de estoque
        stocks: List[int] = []
        for it in items:
            key = (int(it.get("item_id")), it.get("model_id"))
            s = stock_index.get(key)
            if s is not None:
                stocks.append(int(s))

        if stocks:
            soma = sum(stocks)
            media = soma / len(stocks)
            estoque_str = f"Soma={soma} | Média={media:.1f}"
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
                model_id = it.get("model_id")
                per_item.setdefault(item_id, []).append(model_id)

            for item_id, model_ids in per_item.items():
                try:
                    client.update_stock(item_id=item_id, model_ids=model_ids, new_stock=new_stock)
                    total_success += len(model_ids) if any(m is not None for m in model_ids) else 1
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

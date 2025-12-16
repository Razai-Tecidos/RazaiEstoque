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
    """Carrega tokens persistidos (Supabase > tokens.json)."""
    # 1. Tenta Supabase
    sb = _get_supabase_client()
    if sb:
        try:
            response = sb.table("razai_storage").select("value").eq("key", "tokens").execute()
            if response.data and len(response.data) > 0:
                return response.data[0]["value"]
        except Exception:
            pass

    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_tokens(tokens: Dict[str, Any]) -> None:
    """Salva tokens (Supabase + tokens.json)."""
    # 1. Tenta Supabase (Upsert)
    sb = _get_supabase_client()
    if sb:
        try:
            data = {"key": "tokens", "value": tokens}
            sb.table("razai_storage").upsert(data).execute()
        except Exception as e:
            print(f"Erro ao salvar tokens no Supabase: {e}")

    # 2. Salva Local
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)


def git_persist_data() -> str:
    """Salva groups.json e tokens.json no repositório Git local (commit + push)."""
    # Se Supabase estiver ativo, ignoramos o Git para evitar erros de SSH/Auth
    if _get_supabase_client():
        return "Persistência via Supabase ativa. Git ignorado."

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
    # Se Supabase estiver ativo, ignoramos o Git para evitar erros de SSH/Auth
    if _get_supabase_client():
        return "Persistência via Supabase ativa. Git Pull ignorado."

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
    auto_update_names: bool = False,
) -> Tuple[List[Dict[str, Any]], int]:
    """Atualiza item_name/model_name dentro dos grupos com base no cache atual.

    Args:
        groups: Lista de grupos existentes
        models_cache: Cache fresco dos modelos da Shopee
        auto_update_names: Se True, sempre regenera o master_name baseado nos dados atuais

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
        
        # Atualiza o master_name baseado nos dados frescos
        current_master = str(g2.get("master_name") or "").strip()
        
        # Condição de reparo: 
        # - auto_update_names=True: SEMPRE regenera
        # - Caso contrário: só se termina com " e" ou é muito curto
        should_update = auto_update_names or current_master.endswith(" e") or len(current_master.split()) <= 3
        
        if should_update:
            
            # 1. Tenta extração robusta usando dados FRESCOS do models_cache (via index)
            best_new_name = ""
            for it in new_items:
                try:
                    iid = int(it.get("item_id"))
                except Exception:
                    continue
                mid = it.get("model_id")
                
                # Busca dados frescos do models_cache (não os dados truncados do grupo)
                fresh_data = index.get((iid, mid))
                if not fresh_data:
                    continue
                    
                iname = fresh_data.get("item_name", "")
                mname = fresh_data.get("model_name", "")
                
                if iname:
                    fab = extract_fabric_from_title(iname)
                    
                    if fab:
                        fab_clean = _titleize_words(fab)
                        
                        # Extrai cor do model_name e adiciona ao nome
                        if mname and mname.strip():
                            col = extract_color_from_model(mname, "")
                            if col:
                                col_clean = _titleize_words(col)
                                # Só adiciona se a cor NÃO estiver já contida no fab
                                if col_clean.lower() not in fab_clean.lower():
                                    fab_clean = f"{fab_clean} {col_clean}"
                        
                        candidate = fab_clean.strip()
                        if len(candidate) > len(best_new_name):
                            best_new_name = candidate
            
            # 2. Se a extração robusta falhar ou for muito curta, tenta o suggest_master_name (fallback de keywords)
            if not best_new_name or len(best_new_name.split()) < 2:
                temp_models = [{"item_name": it.get("item_name", ""), "model_name": it.get("model_name", "")} for it in new_items]
                fallback_name = suggest_master_name(temp_models)
                if fallback_name and len(fallback_name) > len(best_new_name):
                    best_new_name = fallback_name

            # Aplica se for melhor que o atual (ou se o atual estiver quebrado com " e")
            if best_new_name:
                # Se o atual está quebrado ("... e"), aceitamos qualquer coisa válida que não termine em " e"
                is_broken = current_master.endswith(" e")
                is_improvement = len(best_new_name) > len(current_master)
                
                if (is_broken and not best_new_name.endswith(" e")) or (is_improvement and not best_new_name.endswith(" e")):
                    g2["master_name"] = best_new_name
                    updated_count += 1

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
            # Apenas itens ativos (NORMAL). UNLIST = inativos, BANNED = banidos
            item_status = ["NORMAL"]

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

        Conforme docs v2:
        - API sempre usa stock_list com seller_stock
        - Para itens sem variações, usa model_id = 0
        - seller_stock é array de objetos com stock (location_id opcional se loja não tem warehouse)

        Observação (docs v2): esta API atualiza o **seller_stock**.
        """
        path = "/api/v2/product/update_stock"
        body: Dict[str, Any] = {"item_id": int(item_id)}

        # Sem variações (estoque no nível do item): usa model_id = 0
        if not model_ids or all(m is None for m in model_ids):
            stock_list = [
                {
                    "model_id": 0,
                    "seller_stock": [{"stock": int(new_stock)}]
                }
            ]
        else:
            # Para variações, stock_list para cada model_id
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
        
        # Verifica se houve falhas na resposta
        response = data.get("response", {})
        failure_list = response.get("failure_list", [])
        if failure_list:
            reasons = [f"model {f.get('model_id')}: {f.get('failed_reason')}" for f in failure_list]
            raise RuntimeError(f"Falha ao atualizar estoque: {', '.join(reasons)}")
        
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
    
    # Remove conectivos soltos no final (ex: "Azul e")
    if s.endswith(" e"):
        s = s[:-2].strip()
        
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

    # Limita a 6 palavras (aumentado para pegar cores compostas ex: "folhagem azul e branco")
    tokens = tokens[:6]

    s = " ".join(tokens).strip()
    
    # Remove conectivos soltos no final
    if s.endswith(" e"):
        s = s[:-2].strip()
        
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


def setup_auth_and_creds():
    """Gerencia autenticação, carregamento de credenciais e OAuth (sem UI)."""
    
    # Carrega fontes de dados
    file_creds = load_test_credentials_from_file()
    secrets_creds = load_credentials_from_streamlit_secrets()
    env_creds = load_credentials_from_env()
    git_tokens = load_tokens()

    # Helper para resolver prioridades
    def _resolve(key_session: str, key_git: str, key_secrets: str, key_env: str, key_file: str) -> str:
        val_sess = str(st.session_state.get(key_session) or "").strip()
        if val_sess: return val_sess
        val_git = str(git_tokens.get(key_git) or "").strip()
        if val_git: return val_git
        val_sec = str(secrets_creds.get(key_secrets) or "").strip()
        if val_sec: return val_sec
        val_env = str(env_creds.get(key_env) or "").strip()
        if val_env: return val_env
        val_file = str(file_creds.get(key_file) or "").strip()
        return val_file

    # Determina ambiente
    preferred_env = st.session_state.get("api_env", "Produção")
    
    if preferred_env == "Produção":
        init_partner_id = _resolve("partner_id", "partner_id", "partner_id", "partner_id", "live_partner_id")
        init_partner_key = _resolve("partner_key", "partner_key", "partner_key", "partner_key", "live_partner_key")
        init_shop_id = _resolve("shop_id", "shop_id", "shop_id", "shop_id", "live_shop_id")
        init_access_token = _resolve("access_token", "access_token", "access_token", "access_token", "")
        init_refresh_token = _resolve("refresh_token", "refresh_token", "refresh_token", "refresh_token", "")
        init_redirect_url = _resolve("redirect_url", "redirect_url", "redirect_url", "redirect_url", "")
        init_api_base_url = _resolve("api_base_url", "api_base_url", "api_base_url", "api_base_url", "")
    else:
        init_partner_id = _resolve("partner_id", "test_partner_id", "test_partner_id", "test_partner_id", "test_partner_id")
        init_partner_key = _resolve("partner_key", "test_partner_key", "test_partner_key", "test_partner_key", "test_partner_key")
        init_shop_id = _resolve("shop_id", "test_shop_id", "test_shop_id", "test_shop_id", "test_shop_id")
        init_access_token = _resolve("access_token", "test_access_token", "test_access_token", "test_access_token", "test_access_token")
        init_refresh_token = ""
        init_redirect_url = "https://razaiestoque.streamlit.app/"
        init_api_base_url = SANDBOX_BASE_URL

    # Atualiza Session State
    if not st.session_state.get("partner_id"): st.session_state["partner_id"] = init_partner_id
    if not st.session_state.get("partner_key"): st.session_state["partner_key"] = init_partner_key
    if not st.session_state.get("shop_id"): st.session_state["shop_id"] = init_shop_id
    if not st.session_state.get("access_token"): st.session_state["access_token"] = init_access_token
    if not st.session_state.get("refresh_token"): st.session_state["refresh_token"] = init_refresh_token
    if not st.session_state.get("redirect_url"): st.session_state["redirect_url"] = init_redirect_url
    if not st.session_state.get("api_base_url"): st.session_state["api_base_url"] = init_api_base_url

    # --- OAuth Code Exchange ---
    try:
        # Compatibilidade com versões diferentes do Streamlit
        if hasattr(st, "query_params"):
            qp = st.query_params
            qp_code = qp.get("code")
            qp_shop_id = qp.get("shop_id")
        else:
            qp = st.experimental_get_query_params()
            qp_code = qp.get("code", [None])[0]
            qp_shop_id = qp.get("shop_id", [None])[0]
    except:
        qp_code = None
        qp_shop_id = None

    if (qp_code and qp_shop_id and 
        qp_code != st.session_state.get("_last_oauth_code_exchanged") and 
        init_partner_id and init_partner_key):
        
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
            
            new_at = token_data.get("access_token")
            new_rt = token_data.get("refresh_token")
            
            if new_at:
                st.session_state["access_token"] = new_at
                st.session_state["refresh_token"] = new_rt
                st.session_state["shop_id"] = qp_shop_id
                st.session_state["_last_oauth_code_exchanged"] = qp_code
                
                # Persistência
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
                git_persist_data()
                st.toast("Login realizado com sucesso!", icon="✅")
                time.sleep(1)
                st.rerun()
        except Exception as e:
            st.error(f"Erro no login: {e}")

    # --- Auto Refresh Token ---
    if (preferred_env == "Produção" and 
        not st.session_state.get("_auto_token_bootstrap_done") and 
        not st.session_state.get("access_token") and 
        st.session_state.get("refresh_token")):
        
        try:
            rt = st.session_state["refresh_token"]
            tmp_client = ShopeeClient(
                partner_id=int(st.session_state["partner_id"]),
                partner_key=st.session_state["partner_key"],
                shop_id=0,
                access_token="",
                base_url=st.session_state["api_base_url"] or BASE_URL
            )
            token_data = tmp_client.refresh_access_token(rt, int(st.session_state["shop_id"] or 0))
            
            new_at = token_data.get("access_token")
            new_rt = token_data.get("refresh_token")
            
            if new_at:
                st.session_state["access_token"] = new_at
                if new_rt: st.session_state["refresh_token"] = new_rt
                st.toast("Sessão restaurada!", icon="🔄")
                
                if new_rt and new_rt != rt:
                    # Atualiza persistência se mudou RT
                    save_tokens({
                        "partner_id": st.session_state["partner_id"],
                        "partner_key": st.session_state["partner_key"],
                        "shop_id": st.session_state["shop_id"],
                        "access_token": new_at,
                        "refresh_token": new_rt,
                        "redirect_url": st.session_state["redirect_url"],
                        "api_base_url": st.session_state["api_base_url"]
                    })
                    git_persist_data()
        except Exception:
            st.session_state["refresh_token"] = "" # Limpa se inválido
        finally:
            st.session_state["_auto_token_bootstrap_done"] = True


def view_mapping():
    """View: Mapeamento de Produtos (Cérebro)."""
    st.header("Mapeamento de Produtos")
    st.caption("Agrupe variações da Shopee em produtos mestres para controle unificado.")

    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])

    if not client or not models_cache:
        st.info("⚠️ Configure as credenciais e clique em 'Sincronizar Dados da Shopee' na barra lateral.")
        return

    groups = load_groups()
    ungrouped_models = filter_ungrouped_models(models_cache, groups)

    # --- Métricas do Mapeamento ---
    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Total de Variações", len(models_cache))
    col_m2.metric("Já Agrupados", len(models_cache) - len(ungrouped_models))
    col_m3.metric("Pendentes de Agrupamento", len(ungrouped_models), delta_color="inverse")

    st.divider()

    # --- Sugestões automáticas ---
    with st.expander("✨ Sugestões Automáticas (Tecido + Cor)", expanded=True):
        suggestions_all = build_suggested_fabric_color_groups(ungrouped_models, min_group_size=2)
        
        if not suggestions_all:
            st.info("Nenhuma sugestão automática encontrada no momento.")
        else:
            # Prepara dados para tabela de sugestões
            sug_data = []
            for i, s in enumerate(suggestions_all[:50]): # Limit to 50
                sug_data.append({
                    "ID": i,
                    "Tecido": s.get("fabric_label"),
                    "Cor": s.get("color_label"),
                    "Qtd Variações": s.get("count"),
                    "Exemplo": s.get("example_name")
                })
            
            df_sug = pd.DataFrame(sug_data)
            
            # Layout de seleção de sugestão
            col_s1, col_s2 = st.columns([3, 1])
            
            with col_s1:
                st.dataframe(
                    df_sug, 
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "ID": st.column_config.NumberColumn("ID", width="small"),
                        "Qtd Variações": st.column_config.ProgressColumn(
                            "Variações", 
                            format="%d", 
                            min_value=0, 
                            max_value=max([s['count'] for s in suggestions_all]) if suggestions_all else 10
                        ),
                    }
                )

            with col_s2:
                st.markdown("##### Ações")
                selected_id = st.number_input("ID da Sugestão", min_value=0, max_value=len(sug_data)-1 if sug_data else 0, step=1)
                
                if st.button("Carregar Sugestão", use_container_width=True):
                    sug = suggestions_all[int(selected_id)]
                    st.session_state["mapping_suggestion_active"] = True
                    st.session_state["mapping_suggestion_keys"] = list(sug.get("model_keys") or [])
                    st.session_state["mapping_selected_keys"] = list(sug.get("model_keys") or [])

                    # Preenche Nome Mestre
                    fabric_label = str(sug.get("fabric_label") or "").strip()
                    color_label = str(sug.get("color_label") or "").strip()
                    if color_label and color_label != "(Sem cor)":
                        st.session_state["master_name_input"] = f"{fabric_label} {color_label}".strip()
                    else:
                        st.session_state["master_name_input"] = fabric_label
                    st.rerun()

                if st.button("Criar TODAS (Auto)", type="primary", use_container_width=True):
                    # Lógica de criação em massa (mantida do original)
                    model_by_key = {}
                    for m in ungrouped_models:
                        mk = f"{m.get('item_id')}:{m.get('model_id') if m.get('model_id') is not None else 'none'}"
                        model_by_key[mk] = m

                    groups = load_groups()
                    created = 0
                    with st.spinner("Processando..."):
                        for sug in suggestions_all:
                            model_keys = list(sug.get("model_keys") or [])
                            selected_models = [model_by_key.get(k) for k in model_keys if model_by_key.get(k)]
                            
                            if len(selected_models) < 2: continue
                            
                            fabric_label = str(sug.get("fabric_label") or "").strip()
                            color_label = str(sug.get("color_label") or "").strip()
                            master_name = f"{fabric_label} {color_label}".strip() if color_label and color_label != "(Sem cor)" else fabric_label
                            
                            if not master_name: continue

                            group_id = str(uuid.uuid4())
                            item_ids = sorted({int(m["item_id"]) for m in selected_models})
                            model_ids = sorted({int(m["model_id"]) for m in selected_models if m.get("model_id") is not None})

                            new_group = {
                                "group_id": group_id,
                                "master_name": master_name,
                                "items": [
                                    {"item_id": int(m["item_id"]), "model_id": m.get("model_id"), "item_name": m.get("item_name", ""), "model_name": m.get("model_name", "")}
                                    for m in selected_models
                                ],
                                "shopee_item_ids": item_ids,
                                "shopee_model_ids": model_ids,
                            }
                            groups.append(new_group)
                            created += 1
                    
                    save_groups(groups)
                    st.success(f"{created} grupos criados!")
                    st.rerun()

    st.divider()

    # --- Área de Trabalho (Manual) ---
    st.subheader("Área de Trabalho Manual")
    
    col_search, col_name = st.columns([2, 2])
    query = col_search.text_input("🔍 Buscar Variação", placeholder="Digite para filtrar...", key="mapping_query")
    
    # Filtragem
    if st.session_state.get("mapping_suggestion_active") and st.session_state.get("mapping_suggestion_keys"):
        filtered_models = [
            m for m in ungrouped_models
            if f"{m.get('item_id')}:{m.get('model_id') if m.get('model_id') is not None else 'none'}"
            in set(st.session_state.get("mapping_suggestion_keys") or [])
        ]
        st.info("Modo Sugestão Ativo. Clique em 'Limpar Filtro' para ver todos.", icon="ℹ️")
        if st.button("Limpar Filtro"):
            st.session_state["mapping_suggestion_active"] = False
            st.session_state["mapping_suggestion_keys"] = []
            st.rerun()
    else:
        filtered_models = search_models(ungrouped_models, query)

    # Tabela de Seleção (Multiselect melhorado)
    options_keys = []
    key_to_model = {}
    for m in filtered_models:
        item_id = m.get("item_id")
        model_id = m.get("model_id")
        key = f"{item_id}:{model_id if model_id is not None else 'none'}"
        options_keys.append(key)
        key_to_model[key] = m

    # Container com estilo de "Card"
    with st.container(border=True):
        selected_keys = st.multiselect(
            "Selecione as variações para agrupar:",
            options=options_keys,
            format_func=lambda k: f"{key_to_model[k].get('display_name', '')} (Estoque: {key_to_model[k].get('normal_stock')})",
            key="mapping_selected_keys",
            placeholder="Escolha 2 ou mais itens..."
        )

        if selected_keys:
            st.markdown("---")
            c1, c2 = st.columns([3, 1])
            
            # Sugestão de nome
            suggested_name = ""
            if selected_keys:
                selected_models = [key_to_model[k] for k in selected_keys]
                suggested_name = suggest_master_name(selected_models)
            
            # Se o input já tiver valor (do botão de sugestão), usa ele, senão usa o sugerido
            current_input = st.session_state.get("master_name_input", "")
            if not current_input and suggested_name:
                 st.session_state["master_name_input"] = suggested_name

            master_name = c1.text_input("Nome do Novo Grupo", key="master_name_input")
            
            if c2.button("Salvar Grupo", type="primary", use_container_width=True):
                if not master_name:
                    st.error("Defina um nome para o grupo.")
                else:
                    # Salvar
                    selected_models = [key_to_model[k] for k in selected_keys]
                    group_id = str(uuid.uuid4())
                    item_ids = sorted({int(m["item_id"]) for m in selected_models})
                    model_ids = sorted({int(m["model_id"]) for m in selected_models if m.get("model_id") is not None})

                    new_group = {
                        "group_id": group_id,
                        "master_name": master_name.strip(),
                        "items": [
                            {"item_id": int(m["item_id"]), "model_id": m.get("model_id"), "item_name": m.get("item_name", ""), "model_name": m.get("model_name", "")}
                            for m in selected_models
                        ],
                        "shopee_item_ids": item_ids,
                        "shopee_model_ids": model_ids,
                    }
                    groups.append(new_group)
                    save_groups(groups)
                    st.success("Grupo salvo!")
                    st.session_state["mapping_selected_keys"] = []
                    st.session_state["master_name_input"] = ""
                    st.rerun()


def _render_inventory_table(df: pd.DataFrame, groups: List[Dict], client: Optional[ShopeeClient], key_suffix: str = ""):
    """Renderiza a tabela de estoque e processa atualizações."""
    
    # Calcula max_value seguro para a barra de progresso
    max_stock = max(df["Estoque Atual"]) if not df.empty else 100
    if max_stock <= 0: max_stock = 100

    # Usa session_state para persistir edições entre reruns
    editor_key = f"inventory_editor_{key_suffix}"
    
    edited_df = st.data_editor(
        df,
        column_config={
            "group_id": None, # Esconde ID
            "Nome do Grupo": st.column_config.TextColumn("Nome do Produto (Grupo)", width="large", disabled=True),
            "Variações": st.column_config.NumberColumn("Qtd. Anúncios", disabled=True),
            "Estoque Atual": st.column_config.ProgressColumn(
                "Estoque Atual", 
                format="%d", 
                min_value=0, 
                max_value=max_stock,
            ),
            "Novo Estoque": st.column_config.NumberColumn(
                "Novo Estoque (Editar)", 
                min_value=0, 
                step=1,
                required=False
            )
        },
        hide_index=True,
        use_container_width=True,
        key=f"inventory_editor_{key_suffix}"
    )

    # Botão de Salvar
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("💾 Aplicar Alterações de Estoque", type="primary", key=f"save_btn_{key_suffix}"):
        if not client:
            st.error("Conecte-se à Shopee primeiro.")
            return

        # Processa alterações
        changes_count = 0
        errors = []
        
        with st.status("Processando atualizações...", expanded=True) as status:
            for index, row in edited_df.iterrows():
                new_val = row["Novo Estoque"]
                
                # Se for lista, pega o primeiro elemento
                if isinstance(new_val, list):
                    new_val = new_val[0] if new_val else None
                
                # Pula valores vazios/None/NaN
                try:
                    if pd.isna(new_val):
                        continue
                except (ValueError, TypeError):
                    pass
                    
                if new_val is None or str(new_val).strip() == "":
                    continue
                
                group_id = row["group_id"]
                try:
                    new_stock = int(float(new_val))
                except (ValueError, TypeError):
                    continue
                
                # Encontra o grupo original
                group = next((g for g in groups if g["group_id"] == group_id), None)
                if not group: continue

                status.write(f"📦 Atualizando '{group['master_name']}' para {new_stock}...")
                
                # Lógica de update
                per_item = {}
                for it in group.get("items", []):
                    item_id = int(it.get("item_id"))
                    model_id = int(it.get("model_id")) if it.get("model_id") is not None else None
                    per_item.setdefault(item_id, []).append(model_id)

                for item_id, model_ids in per_item.items():
                    try:
                        status.write(f"   → API: item_id={item_id}, model_ids={model_ids}, stock={new_stock}")
                        result = client.update_stock(item_id=item_id, model_ids=model_ids, new_stock=new_stock)
                        
                        # Mostra resposta da API
                        response = result.get("response", {})
                        success_list = response.get("success_list", [])
                        failure_list = response.get("failure_list", [])
                        
                        if success_list:
                            status.write(f"   ✅ Sucesso: {len(success_list)} model(s)")
                        if failure_list:
                            for f in failure_list:
                                status.write(f"   ⚠️ Falha model {f.get('model_id')}: {f.get('failed_reason')}")
                        
                        # Atualiza cache local
                        for mid in model_ids:
                            for m in st.session_state["models_cache"]:
                                m_mid = int(m.get("model_id")) if m.get("model_id") is not None else None
                                if int(m.get("item_id")) == item_id and m_mid == mid:
                                    m["normal_stock"] = new_stock

                        changes_count += 1
                    except Exception as e:
                        status.write(f"   ❌ ERRO: {e}")
                        errors.append(f"{group['master_name']}: {e}")
            
            if errors:
                status.update(label="Concluído com erros", state="error")
                for e in errors: st.error(e)
            else:
                status.update(label="Atualização concluída!", state="complete")
        
        if changes_count > 0:
            st.success(f"Sucesso! {changes_count} grupos atualizados.")
            time.sleep(1)
            st.rerun()


def view_replenishment():
    """View: Itens Esgotados (Para Reposição)."""
    st.header("📦 Para Reposição (Esgotados)")
    st.caption("Lista de produtos com estoque zerado.")
    
    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])
    groups = load_groups()

    if not groups:
        st.info("Nenhum grupo criado.")
        return

    # Mapa de estoque atual
    stock_map = {} 
    for m in models_cache:
        mid = int(m.get("model_id")) if m.get("model_id") is not None else None
        stock_map[(int(m.get("item_id")), mid)] = m.get("normal_stock", 0)

    # Prepara dados filtrados
    table_data = []
    for g in groups:
        g_stocks = []
        for it in g.get("items", []):
            mid = int(it.get("model_id")) if it.get("model_id") is not None else None
            s = stock_map.get((int(it.get("item_id")), mid))
            if s is not None: g_stocks.append(s)
        
        curr_stock = int(sum(g_stocks)/len(g_stocks)) if g_stocks else 0
        
        # FILTRO: Apenas estoque 0
        if curr_stock == 0:
            table_data.append({
                "group_id": g.get("group_id"),
                "Nome do Grupo": g.get("master_name"),
                "Variações": len(g.get("items", [])),
                "Estoque Atual": curr_stock,
                "Novo Estoque": None 
            })

    if not table_data:
        st.success("Nenhum produto esgotado! 🎉")
        return

    df = pd.DataFrame(table_data)
    _render_inventory_table(df, groups, client, key_suffix="replenish")


def view_dashboard():
    """View: Dashboard e Gestão de Estoque."""
    st.header("Visão Geral de Estoque")
    
    client: Optional[ShopeeClient] = st.session_state.get("client")
    models_cache: List[Dict[str, Any]] = st.session_state.get("models_cache", [])
    groups = load_groups()

    # --- Top Bar Actions ---
    col_act1, col_act2 = st.columns([3, 1])
    with col_act2:
        if st.button("🔄 Recarregar Shopee", use_container_width=True):
            if client:
                with st.spinner("Atualizando..."):
                    fresh = build_models_cache(client)
                    st.session_state["models_cache"] = fresh
                    st.session_state["last_sync_ts"] = int(time.time())
                    
                    # --- AUTO REPAIR/UPDATE NAMES ---
                    groups = load_groups()
                    auto_update = st.session_state.get("auto_update_group_names", False)
                    updated_groups, count = refresh_group_names_from_models_cache(groups, fresh, auto_update_names=auto_update)
                    if count > 0:
                        save_groups(updated_groups)
                        st.toast(f"Nomes atualizados: {count}!", icon="✨")
                    # -------------------------
                    
                st.rerun()
            else:
                st.error("Conecte-se primeiro.")

    # --- Metrics Cards ---
    total_groups = len(groups)
    total_items_linked = sum(len(g.get("items", [])) for g in groups)
    
    # Calcula estoque médio global
    total_stock_sum = 0
    count_stock = 0
    
    # Mapa de estoque atual
    stock_map = {} # (item_id, model_id) -> stock
    for m in models_cache:
        mid = int(m.get("model_id")) if m.get("model_id") is not None else None
        stock_map[(int(m.get("item_id")), mid)] = m.get("normal_stock", 0)

    for g in groups:
        for it in g.get("items", []):
            mid = int(it.get("model_id")) if it.get("model_id") is not None else None
            s = stock_map.get((int(it.get("item_id")), mid), 0)
            total_stock_sum += s
            count_stock += 1
            
    avg_stock = int(total_stock_sum / count_stock) if count_stock > 0 else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Grupos Ativos", total_groups)
    m2.metric("Anúncios Vinculados", total_items_linked)
    m3.metric("Estoque Médio", avg_stock)
    m4.metric("Status API", "Online" if client else "Offline", delta_color="normal" if client else "off")

    st.divider()

    if not groups:
        st.info("Nenhum grupo criado. Vá para 'Mapeamento' para começar.")
        return

    # --- Tabela Principal (Dataframe) ---
    # Prepara dados para exibição tabular limpa
    table_data = []
    for g in groups:
        # Calcula estoque médio deste grupo
        g_stocks = []
        for it in g.get("items", []):
            mid = int(it.get("model_id")) if it.get("model_id") is not None else None
            s = stock_map.get((int(it.get("item_id")), mid))
            if s is not None: g_stocks.append(s)
        
        curr_stock = int(sum(g_stocks)/len(g_stocks)) if g_stocks else 0
        
        table_data.append({
            "group_id": g.get("group_id"),
            "Nome do Grupo": g.get("master_name"),
            "Variações": len(g.get("items", [])),
            "Estoque Atual": curr_stock,
            "Novo Estoque": None # Placeholder para edição
        })

    df = pd.DataFrame(table_data)

    # Edição de Estoque em Tabela
    st.subheader("Atualização em Massa")
    st.caption("Edite a coluna 'Novo Estoque' e clique em Salvar no final da página.")

    _render_inventory_table(df, groups, client, key_suffix="dashboard")


def view_settings():
    """View: Configurações e Conexão."""
    st.header("Configurações e Conexão")
    
    # --- Status da Conexão ---
    has_token = bool(st.session_state.get("access_token"))
    
    with st.container(border=True):
        st.subheader("Status da Conexão")
        if has_token:
            st.success(f"✅ Conectado à Shopee (Shop ID: {st.session_state.get('shop_id')})")
            if st.button("Desconectar / Trocar Conta", type="secondary"):
                st.session_state["access_token"] = ""
                st.session_state["refresh_token"] = ""
                st.session_state["shop_id"] = ""
                save_tokens({})
                git_persist_data()
                st.rerun()
        else:
            st.warning("⚠️ Desconectado")
            
            # Recupera URL de redirect da sessão ou usa padrão
            redirect_url = st.session_state.get("redirect_url", "https://razaiestoque.streamlit.app/")
            
            # Tenta montar URL de auth se tiver credenciais básicas
            partner_id = st.session_state.get("partner_id")
            partner_key = st.session_state.get("partner_key")
            api_base_url = st.session_state.get("api_base_url") or BASE_URL
            
            if partner_id and partner_key:
                try:
                    tmp_client = ShopeeClient(
                        partner_id=int(partner_id),
                        partner_key=partner_key,
                        shop_id=0,
                        access_token="",
                        base_url=api_base_url,
                    )
                    auth_url = tmp_client.build_authorize_url(redirect_url)
                    st.link_button("🔐 Fazer Login na Shopee", auth_url, type="primary")
                except Exception as e:
                    st.error(f"Erro ao gerar link: {e}")
            else:
                st.info("Configure as credenciais abaixo para habilitar o login.")

    st.divider()

    # --- Configurações Manuais ---
    with st.expander("⚙️ Credenciais de API (Avançado)", expanded=not has_token):
        c1, c2 = st.columns(2)
        
        partner_id = c1.text_input("Partner ID", value=st.session_state.get("partner_id", ""))
        partner_key = c2.text_input("Partner Key", value=st.session_state.get("partner_key", ""), type="password")
        
        if partner_id != st.session_state.get("partner_id"): st.session_state["partner_id"] = partner_id
        if partner_key != st.session_state.get("partner_key"): st.session_state["partner_key"] = partner_key

        api_env = st.selectbox("Ambiente", ["Produção", "Sandbox"], index=0 if st.session_state.get("api_env") == "Produção" else 1)
        st.session_state["api_env"] = api_env
        
        # Lógica de host
        if api_env == "Sandbox":
            default_host = SANDBOX_BASE_URL
        else:
            default_host = BASE_URL # Default BR
            
        current_host = st.session_state.get("api_base_url", default_host)
        api_base_url = st.text_input("API Base URL", value=current_host)
        st.session_state["api_base_url"] = api_base_url
        
        redirect_url_input = st.text_input("Redirect URL", value=st.session_state.get("redirect_url", ""))
        st.session_state["redirect_url"] = redirect_url_input

    # --- Backup ---
    st.divider()
    st.subheader("Backup e Persistência")
    
    sb_client = _get_supabase_client()
    if sb_client:
        st.success("✅ Persistência via Supabase Ativa (Cloud)")
        st.caption("Seus dados (grupos e tokens) são salvos automaticamente na nuvem.")
        
        with st.expander("Opções Legacy (Git)"):
            st.caption("Use apenas se souber o que está fazendo.")
            c_git1, c_git2 = st.columns(2)
            if c_git1.button("☁️ Salvar Dados no GitHub"):
                with st.spinner("Salvando..."):
                    msg = git_persist_data()
                    if "Sucesso" in msg: st.success(msg)
                    else: st.warning(msg)
                    
            if c_git2.button("⬇️ Baixar Dados do GitHub"):
                with st.spinner("Baixando..."):
                    msg = git_pull_data()
                    if "Sucesso" in msg: 
                        st.success(msg)
                        time.sleep(1)
                        st.rerun()
                    else: st.warning(msg)

    else:
        st.warning("⚠️ Supabase não detectado. Usando armazenamento local/Git.")
        c_git1, c_git2 = st.columns(2)
        if c_git1.button("☁️ Salvar Dados no GitHub"):
            with st.spinner("Salvando..."):
                msg = git_persist_data()
                if "Sucesso" in msg: st.success(msg)
                else: st.warning(msg)
                
        if c_git2.button("⬇️ Baixar Dados do GitHub"):
            with st.spinner("Baixando..."):
                msg = git_pull_data()
                if "Sucesso" in msg: 
                    st.success(msg)
                    time.sleep(1)
                    st.rerun()
                else: st.warning(msg)

    # --- Importar / Exportar JSON ---
    st.divider()
    with st.expander("📂 Importar/Exportar Arquivo Local (JSON)"):
        st.caption("Backup manual dos grupos (groups.json).")
        
        try:
            current_groups = load_groups()
        except: current_groups = []
        
        export_payload = {"groups": current_groups}
        export_bytes = json.dumps(export_payload, ensure_ascii=False, indent=2).encode("utf-8")
        
        c_ex, c_im = st.columns(2)
        
        c_ex.download_button(
            "⬇️ Baixar groups.json",
            data=export_bytes,
            file_name="groups.json",
            mime="application/json",
            use_container_width=True
        )
        
        uploaded = c_im.file_uploader("Restaurar groups.json", type=["json"])
        if uploaded:
            try:
                raw = uploaded.read().decode("utf-8")
                payload = json.loads(raw)
                imported = _validate_imported_groups_payload(payload)
                if st.button(f"⚠️ Substituir por {len(imported)} grupos do arquivo?", type="primary", use_container_width=True):
                    save_groups(imported)
                    st.success("Importado com sucesso!")
                    time.sleep(1)
                    st.rerun()
            except Exception as e:
                st.error(f"Erro: {e}")

    # --- Atualização de Nomes ---
    st.divider()
    st.subheader("Nomes dos Grupos")
    
    # Toggle para modo automático
    auto_update = st.toggle(
        "🔄 Atualizar nomes automaticamente",
        value=st.session_state.get("auto_update_group_names", False),
        help="Quando ativo, os nomes dos grupos são regenerados automaticamente a cada sincronização, "
             "baseado nos dados atuais da Shopee (tecido + cor da variação)."
    )
    st.session_state["auto_update_group_names"] = auto_update
    
    if auto_update:
        st.info("📌 A cada sincronização, os nomes dos grupos serão atualizados automaticamente.")
    
    # Botão manual para regenerar todos os nomes
    st.caption("Ou regenere manualmente todos os nomes agora:")
    
    col_regen1, col_regen2 = st.columns([1, 2])
    if col_regen1.button("🔧 Regenerar Todos os Nomes", type="secondary", use_container_width=True):
        client = st.session_state.get("client")
        models_cache = st.session_state.get("models_cache", [])
        
        if not client or not models_cache:
            st.error("Sincronize com a Shopee primeiro (clique em '🔄 Sincronizar Agora').")
        else:
            with st.spinner("Regenerando nomes..."):
                groups = load_groups()
                updated_groups, count = refresh_group_names_from_models_cache(groups, models_cache, auto_update_names=True)
                if count > 0:
                    save_groups(updated_groups)
                    st.success(f"✅ {count} nomes atualizados!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.info("Nenhum nome foi alterado.")


def main():
    st.set_page_config(page_title="IMS Shopee - Tecidos", layout="wide", page_icon="📦")
    
    # CSS Customizado para visual "Clean" e Profissional
    st.markdown("""
        <style>
        /* Remove padding excessivo do topo */
        .block-container { padding-top: 1.5rem; padding-bottom: 3rem; }
        
        /* Esconde footer apenas (mantém header para acesso ao menu lateral) */
        footer { visibility: hidden; }
        
        /* Sidebar mais limpa */
        [data-testid="stSidebar"] { 
            background-color: #f8f9fa; 
            border-right: 1px solid #e9ecef;
        }
        
        /* Força texto escuro na sidebar (corrige problema de tema escuro) */
        [data-testid="stSidebar"] * {
            color: #212529 !important;
        }
        
        /* Cards de métricas mais bonitos */
        div[data-testid="stMetric"] {
            background-color: #ffffff;
            border: 1px solid #e0e0e0;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            color: #212529 !important; /* Força texto escuro */
        }

        /* Força cor dos labels e valores dentro das métricas */
        div[data-testid="stMetric"] label,
        div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
            color: #212529 !important;
        }
        
        /* Títulos mais sóbrios */
        h1, h2, h3 { font-family: 'Inter', sans-serif; color: #333; }
        
        /* Botões primários com cor de destaque */
        button[kind="primary"] {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }
        </style>
    """, unsafe_allow_html=True)

    init_session_state()
    setup_auth_and_creds()
    
    # Sidebar Minimalista (Apenas Navegação)
    with st.sidebar:
        st.title("📦 IMS Shopee")
        st.caption("Gestão de Estoque Unificado")
        st.markdown("---")
        
        page = st.radio(
            "Menu", 
            ["📊 Dashboard", "📦 Para Reposição", "🧩 Mapeamento", "⚙️ Configurações"],
            index=0,
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        # Status Rápido na Sidebar
        if st.session_state.get("access_token"):
            st.success("● Online")
        else:
            st.error("● Offline")
            
        if st.button("🔄 Sincronizar Agora", use_container_width=True):
             # Lógica de sync rápido (sem UI complexa)
             partner_id = st.session_state.get("partner_id")
             partner_key = st.session_state.get("partner_key")
             shop_id = st.session_state.get("shop_id")
             access_token = st.session_state.get("access_token")
             api_base_url = st.session_state.get("api_base_url")
             
             if partner_id and access_token:
                 try:
                     client = ShopeeClient(int(partner_id), partner_key, int(shop_id), access_token, api_base_url or BASE_URL)
                     with st.spinner("Sincronizando..."):
                         cache = build_models_cache(client)
                         st.session_state["client"] = client
                         st.session_state["models_cache"] = cache
                         st.session_state["last_sync_ts"] = int(time.time())
                         
                         # --- AUTO REPAIR/UPDATE NAMES ---
                         groups = load_groups()
                         auto_update = st.session_state.get("auto_update_group_names", False)
                         updated_groups, count = refresh_group_names_from_models_cache(groups, cache, auto_update_names=auto_update)
                         if count > 0:
                             save_groups(updated_groups)
                             st.toast(f"Nomes atualizados: {count}!", icon="✨")
                         # -------------------------
                         
                     st.toast("Sincronização concluída!", icon="✅")
                     time.sleep(0.5)
                     st.rerun()  # Recarrega para mostrar nomes corrigidos
                 except Exception as e:
                     st.toast(f"Erro: {e}", icon="❌")
             else:
                 st.toast("Conecte-se primeiro nas Configurações.", icon="⚠️")

    # Roteamento de Páginas
    if page == "📊 Dashboard":
        view_dashboard()
    elif page == "📦 Para Reposição":
        view_replenishment()
    elif page == "🧩 Mapeamento":
        view_mapping()
    elif page == "⚙️ Configurações":
        view_settings()


if __name__ == "__main__":
    main()

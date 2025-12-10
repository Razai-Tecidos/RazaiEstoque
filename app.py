import os
import time
import hmac
import json
import uuid
import hashlib
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
# Por padrão usamos o host de produção. Para testes em sandbox, o usuário pode
# sobrescrever esse valor pela própria interface (campo "API Base URL" na
# barra lateral) com o domínio de sandbox indicado na documentação da Shopee
# ou observado no API Test Tool.
BASE_URL = "https://partner.shopeemobile.com"
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
    """Lê credenciais de teste do arquivo de texto local.

    O arquivo `razaiestoque.txt` é tratado **somente para leitura**, nunca é
    modificado. Usamos apenas campos de teste como:

    - "Test API Partner Key: ..."
    - "Test Partner_id: ..."

    Isso permite ter credenciais já disponíveis no sistema, sem expor nada na
    aplicação além do preenchimento automático da sidebar.
    """
    if not os.path.exists(CREDS_FILE):
        return {}

    partner_key: Optional[str] = None
    partner_id: Optional[str] = None
    shop_id: Optional[str] = None
    access_token: Optional[str] = None

    try:
        with open(CREDS_FILE, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.lower().startswith("test api partner key:"):
                    partner_key = line.split(":", 1)[1].strip()
                elif line.lower().startswith("test partner_id:"):
                    partner_id = line.split(":", 1)[1].strip()
                elif line.lower().startswith("test shop_id:") or line.lower().startswith("test shop id:"):
                    shop_id = line.split(":", 1)[1].strip()
                elif line.lower().startswith("test access token:"):
                    access_token = line.split(":", 1)[1].strip()
    except Exception:
        # Se algo der errado na leitura/parsing, apenas retornamos vazio
        return {}

    creds: Dict[str, Any] = {}
    if partner_key:
        creds["partner_key"] = partner_key
    if partner_id:
        creds["partner_id"] = partner_id
    if shop_id:
        creds["shop_id"] = shop_id
    if access_token:
        creds["access_token"] = access_token
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
                f"HTTP {resp.status_code} da Shopee: {data.get('error')} - {data.get('message')}"
            )

        if data.get("error") not in (None, ""):
            raise RuntimeError(f"Erro na API Shopee: {data.get('error')} - {data.get('message')}")

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


def sidebar_setup() -> None:
    st.sidebar.header("Configurações Shopee (Setup)")

    # Pré-carrega credenciais de teste a partir de arquivo local somente leitura,
    # para que "já estejam no sistema" quando necessário.
    file_creds = load_test_credentials_from_file()
    if file_creds.get("partner_id") and not st.session_state.get("partner_id"):
        st.session_state["partner_id"] = str(file_creds["partner_id"])
    if file_creds.get("partner_key") and not st.session_state.get("partner_key"):
        st.session_state["partner_key"] = str(file_creds["partner_key"])
    if file_creds.get("shop_id") and not st.session_state.get("shop_id"):
        st.session_state["shop_id"] = str(file_creds["shop_id"])
    if file_creds.get("access_token") and not st.session_state.get("access_token"):
        st.session_state["access_token"] = str(file_creds["access_token"])

    partner_id = st.sidebar.text_input("Partner ID", key="partner_id")
    partner_key = st.sidebar.text_input(
        "Partner Key (HMAC)", type="password", key="partner_key"
    )
    shop_id = st.sidebar.text_input("Shop ID", key="shop_id")
    access_token = st.sidebar.text_input(
        "Access Token", type="password", key="access_token"
    )

    with st.sidebar.expander("Opções avançadas (API)"):
        api_base_url = st.text_input(
            "API Base URL",
            key="api_base_url",
            help=(
                "Host base da API Shopee. Por padrão usa produção. "
                "Para sandbox, informe o domínio indicado na documentação/"
                "API Test Tool, por exemplo o host de sandbox v2."
            ),
        )

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

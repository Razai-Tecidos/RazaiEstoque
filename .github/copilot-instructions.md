# Copilot instructions (RazaiEstoque)

## Big picture
- Projeto **single-file** em Python/Streamlit: a aplicação inteira está em `app.py` (UI + cliente Shopee + persistência local).
- Integração com **Shopee Open Platform v2 (user-level)** via `requests` + assinatura **HMAC-SHA256**.
- Modelo mental: **itens/models Shopee** → usuário agrupa em **Grupos Mestres** → app atualiza estoque em massa para todas as variações do grupo.

## Arquivos e dados locais
- `app.py`: contém `ShopeeClient`, funções de cache/filtro e as duas abas do Streamlit (`tab_mapping`, `tab_inventory`).
- `groups.json`: persistência local dos Grupos Mestres. O código **lê lista direta** ou `{ "groups": [...] }`, mas **sempre salva** como `{ "groups": groups }`.
- `razaiestoque.txt`: arquivo **somente leitura** (o app só lê) usado para pré-preencher credenciais de teste/sandbox.

## Persistência de grupos (Cloud)
- Streamlit Cloud pode perder `groups.json` entre reinícios; o app suporta backend remoto via HTTP.
- Ativar com `GROUPS_REMOTE_URL` (em `st.secrets` ou env). Opcional: `GROUPS_REMOTE_TOKEN`, `GROUPS_REMOTE_*_METHOD`.

## Credenciais (prioridade e fluxo)
- Fontes de credenciais: `st.secrets` e variáveis de ambiente têm prioridade; `razaiestoque.txt` é fallback (principalmente Sandbox/Test).
- Live/Produção: tokens normalmente vêm via OAuth redirect (`?code=...&shop_id=...`); o app lê query params e pode renovar `access_token` via `refresh_token` (se presente).
- Nunca persistir credenciais/tokens em disco; ficam em `st.session_state`.

## Shopee API: regras que não podem quebrar
- `BASE_URL`/`api_base_url` deve ser **somente o host** (sem `/api/v2`). Os endpoints já incluem o prefixo (ex.: `/api/v2/product/get_item_list`).
- Hosts variam por região (docs v2):
  - Brasil (produção): `https://openplatform.shopee.com.br`
  - Global (produção): `https://partner.shopeemobile.com`
  - Sandbox: `https://openplatform.sandbox.test-stable.shopee.sg` (ou `.cn`)
- A assinatura v2 (user-level) segue o padrão documentado e implementado em `ShopeeClient._sign`:
  - base string: `partner_id + path + timestamp + access_token + shop_id`
  - `sign = HMAC_SHA256(partner_key, base_string).hexdigest()`
- Requisições passam sempre `partner_id`, `timestamp`, `sign`, `shop_id`, `access_token` como query params (ver `ShopeeClient._make_request`).

## Dados e busca (Aba 1)
- `build_models_cache()` baixa itens e models, e cria registros achatados com `display_name` (item + variação).
- `filter_ungrouped_models()` remove pares `(item_id, model_id)` já presentes em `groups.json`.
- `search_models()` combina filtro por substring com ranking por similaridade (`difflib.SequenceMatcher`) usando normalização sem acentos.
- `suggest_master_name()` é heurística simples (tecido/estampa/cor) para sugerir nome do grupo a partir de títulos.

## Padrões de UI / fluxo
- Credenciais entram pela **sidebar** e ficam só em `st.session_state` (não salvar em disco).
- Sincronização é explícita (botão “Sincronizar Dados da Shopee”), populando `st.session_state["client"]` e `st.session_state["models_cache"]`.
- Aba 1 cria grupos e persiste em `groups.json`; a lista apresentada é apenas de models **não agrupados** (ver `filter_ungrouped_models`).
- Aba 2 não edita grupos; ela só lê `groups.json` e faz update de estoque agrupando chamadas por `item_id` (reduz chamadas de API).

## Workflows locais (Windows/PowerShell)
- Criar venv: `python -m venv .venv` e ativar: `.\.venv\Scripts\Activate.ps1`
- Instalar deps: `pip install -r requirements.txt`
- Rodar: `streamlit run app.py`

## Convenções ao mudar código
- Mantenha a lógica de integração dentro de `ShopeeClient` (não espalhar assinatura/params pela UI).
- Não escreva/modifique `razaiestoque.txt` por código.
- Mudanças em `groups.json` devem manter compatibilidade com os dois formatos de leitura.
- Erros de API devem continuar aparecendo de forma legível no Streamlit (hoje são `RuntimeError` com mensagem curta).

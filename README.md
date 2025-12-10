# IMS Shopee - Tecidos

Sistema de Gestão de Estoque Unificado (IMS) para Shopee, focado em lojistas de tecidos que utilizam múltiplos anúncios para o mesmo produto físico.

## Funcionalidades principais

- **Integração com Shopee Open Platform v2** usando `requests` + `hmac` conforme documentação oficial.
- **Aba 1 - Mapeamento de Produtos (Cérebro)**:
  - Lista variações (models) retornadas pela Shopee.
  - Filtro por texto com sugestão usando `difflib.SequenceMatcher`.
  - Criação de **Grupos Mestres** que vinculam múltiplas variações/anúncios ao mesmo produto físico.
  - Persistência local em `groups.json`.
- **Aba 2 - Gestão de Estoque (Painel de Controle)**:
  - Tabela que mostra apenas os **Grupos Mestres**.
  - Cálculo de soma/média de estoque com base na última sincronização.
  - Atualização em massa do estoque para todos os `item_id`/`model_id` de um grupo via `v2.product.update_stock`.

## Requisitos

- Python 3.9+
- Dependências (instalar no ambiente virtual desejado):

```bash
pip install -r requirements.txt
```

## Como executar (Windows / PowerShell)

Navegue até a pasta do projeto e execute:

```powershell
cd "c:\Users\Rafael\Desktop\RazaiEstoque"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Depois, abra o endereço que o Streamlit mostrar (normalmente `http://localhost:8501`).

## Observações de segurança

- As credenciais da Shopee (Partner ID, Partner Key, Shop ID, Access Token) **não são salvas em disco**, apenas em `session_state` do Streamlit.
- O arquivo `groups.json` contém apenas o mapeamento de grupos e IDs de itens/modelos.

# IMS Shopee - Tecidos

Sistema de Gestão de Estoque Unificado (IMS) para Shopee, focado em lojistas de tecidos que utilizam múltiplos anúncios para o mesmo produto físico.

## Funcionalidades principais

- **Integração com Shopee Open Platform v2** usando `requests` + `hmac` conforme documentação oficial.
- **Aba 1 - Mapeamento de Produtos (Cérebro)**:
  - Lista variações (models) retornadas pela Shopee.
  - Filtro por texto com sugestão usando `difflib.SequenceMatcher`.
  - Criação de **Grupos Mestres** que vinculam múltiplas variações/anúncios ao mesmo produto físico.
  - Persistência local em `groups.json`.
﻿# RazaiEstoque – IMS de Estoque Unificado para Shopee

Sistema de Gestão de Estoque Unificado (Inventory Management System – IMS) para Shopee, desenvolvido em Python com Streamlit.

O objetivo é centralizar o controle de estoque de variações de produtos (models) da Shopee em "Grupos Mestres" (por exemplo, todos os anúncios/variações que representam o mesmo tecido físico) e permitir atualização de estoque em massa via Shopee Open Platform v2.

> **Importante:** este projeto foi desenhado para uso interno do seller ("Seller In House System") e integra com a Shopee via APIs oficiais.

---

## Funcionalidades principais

- **Sincronização com Shopee v2 (sandbox e produção)**
  - Autenticação user-level via Shopee Open Platform v2.
  - Carrega lista de itens (`get_item_list`) e variações/models (`get_model_list`).
- **Mapeamento de produtos em Grupos Mestres**
  - Agrupa variações de diferentes anúncios da Shopee que representam o mesmo produto físico.
  - Busca e filtro por texto com ranqueamento de similaridade.
  - Persistência local em `groups.json` (não perde os grupos entre sessões).
- **Gestão de estoque unificado**
  - Mostra o estoque consolidado por Grupo Mestre (soma/média das variações).
  - Permite informar um **novo estoque alvo** por grupo.
  - Atualiza estoques nas variações relacionadas via `product/update_stock`.
- **Suporte a múltiplos ambientes**
  - Campo de **API Base URL** para alternar entre:
    - Sandbox (testes) – host de sandbox da Shopee.
    - Produção – host oficial da Open Platform v2.

---

## Arquitetura do projeto

Arquivos principais:

- `app.py`
  - Aplicação Streamlit.
  - Implementa a classe `ShopeeClient` com:
    - Assinatura HMAC-SHA256 (user-level) conforme documentação oficial.
    - Métodos:
      - `get_item_list` – `/api/v2/product/get_item_list`
      - `get_model_list` – `/api/v2/product/get_model_list`
      - `update_stock` – `/api/v2/product/update_stock`
  - Camada de dados:
    - Construção de cache de models (item_id, model_id, nomes, estoque).
    - Filtro de models já agrupados.
    - Busca por similaridade com `difflib.SequenceMatcher`.
  - Interface Streamlit:
    - **Sidebar** com setup de credenciais e botão "Sincronizar Dados da Shopee".
    - **Aba 1 – Mapeamento de Produtos**:
      - Seleção de variações para criar/editar Grupos Mestres.
    - **Aba 2 – Gestão de Estoque**:
      - Visualização de grupos e definição de novo estoque alvo.
      - Disparo de atualização de estoque via API.
- `groups.json`
  - Armazena os Grupos Mestres criados na interface.
  - Estrutura básica de cada grupo (conceitual):
    ```json
    {
      "group_id": "uuid",
      "master_name": "Nome do grupo mestre",
      "items": [
        {
          "item_id": 123,
          "model_id": 456,
          "item_name": "Título do anúncio",
          "model_name": "Variação",
          "normal_stock": 10
        }
      ]
    }
    ```
- `razaiestoque.txt`
  - Arquivo **somente leitura** usado pelo app para facilitar teste/sandbox.
  - Contém credenciais de teste fornecidas pela Shopee.

---

## Credenciais de teste (`razaiestoque.txt`)

O arquivo `razaiestoque.txt` contém as credenciais de teste para o ambiente sandbox. Exemplo atual (com valores de **teste**):

```text
RazaiEstoque

Test API Partner Key: shpk614d474f6e544d424e5564424f6b75715744734e67444472727674667944
Test Partner_id:1202356
App Category: Seller In House System
App Status: Developing
```

Você pode também incluir manualmente (caso ainda não estejam):

```text
Test Shop_id: 226244332
Test Access Token: <ACCESS_TOKEN_SANDBOX_FORNECIDO_NO_API_TEST_TOOL>
```

Observações importantes:

- **Não edite este arquivo via código**: o app apenas lê seu conteúdo.
- Os valores acima são de **sandbox** e servem apenas para testes.
- Para produção, use variáveis de ambiente ou outro mecanismo seguro; **não** coloque tokens reais em repositórios públicos.

---

## URL do aplicativo

Ambiente atual de deploy (Streamlit Cloud):

- URL: `https://razaiestoque.streamlit.app/`

Esta URL também é usada como base para **Redirect URL Domain** no console de desenvolvedor da Shopee (tanto para Test Redirect URL Domain quanto para Live Redirect URL Domain, se desejar manter o mesmo domínio).

---

## Como rodar o projeto localmente

1. **Criar e ativar ambiente virtual (Windows/PowerShell)**

```powershell
cd C:\Users\Rafael\Desktop\RazaiEstoque
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. **Instalar dependências**

```powershell
pip install -r requirements.txt
```

3. **Garantir que `razaiestoque.txt` está preenchido com as credenciais de teste**

- Confirme que os campos de teste estão corretos (partner_id, partner_key, shop_id, access_token de sandbox, se você tiver adicionado).

4. **Rodar o app Streamlit**

```powershell
streamlit run app.py
```

---

## Como usar o app (fluxo geral)

1. **Acessar a interface**
   - Local: `http://localhost:8501`
   - Deploy: `https://razaiestoque.streamlit.app/`

2. **Preencher credenciais na sidebar**
   - O app tenta ler automaticamente de `razaiestoque.txt`:
     - `Test Partner_id`
     - `Test API Partner Key`
     - (Opcional) `Test Shop_id`
     - (Opcional) `Test Access Token`
   - Você pode ajustar/confirmar esses valores manualmente pela sidebar.

3. **Configurar ambiente (sandbox vs produção)**
   - No painel "Opções avançadas (API)", informe a **API Base URL**:
     - Sandbox (testes atuais): `https://openplatform.sandbox.test-stable.shopee.sg`
     - Produção (após Go-Live): `https://partner.shopeemobile.com`

4. **Sincronizar dados da Shopee**
   - Clique em **"Sincronizar Dados da Shopee"** na sidebar.
   - O app irá:
     - Autenticar na API Shopee.
     - Buscar itens e models da loja.

5. **Mapear Grupos Mestres** (aba "Mapeamento de Produtos")
   - Use o campo de busca para localizar variações (models) pelo nome.
   - Selecione múltiplas variações que representem o mesmo produto físico.
   - Dê um nome ao Grupo Mestre (ex.: "Tecido Algodão Liso Azul").
   - Salve o grupo; ele será persistido em `groups.json`.

6. **Gerir estoque unificado** (aba "Gestão de Estoque")
   - Visualize os Grupos Mestres com resumo de estoque.
   - Informe um **novo estoque** para o grupo (estoque desejado por variação).
   - Clique em **"Atualizar Estoque em Massa"**.
   - O app chamará `product/update_stock` para cada item/model associado.

---

## Integração com Shopee – visão geral

- **Autenticação (user-level)**
  - Segue o guia oficial da Shopee Open Platform v2.
  - Usa `partner_id`, `partner_key`, `shop_id`, `access_token` e `timestamp` para gerar a assinatura HMAC-SHA256.
- **Principais endpoints usados**
  - `GET /api/v2/product/get_item_list`
  - `GET /api/v2/product/get_model_list`
  - `POST /api/v2/product/update_stock`
- **Ambientes**
  - **Sandbox**: usar `Test Partner_id`, `Test API Partner Key`, `SHOP_ID` e `ACCESS_TOKEN` de sandbox + host de sandbox.
  - **Produção**: usar credenciais de produção e host de produção.

Sempre consulte a documentação oficial da Shopee para confirmar hosts, caminhos e parâmetros atualizados.

---

## Próximos passos após resposta da Shopee (Go-Live)

Quando a Shopee aprovar o aplicativo e/ou responder ao formulário de Go-Live, siga estes passos:

1. **Revisar ambiente aprovado**
   - Verifique se a aprovação é para **produção** e se há alguma observação específica (por exemplo, restrição de IP, redirecionamento, escopos de API autorizados).

2. **Configurar credenciais de produção**
   - No console da Shopee, obtenha:
     - `partner_id` de produção.
     - `partner_key` de produção.
   - Não use mais o `Test Partner_id`/`Test API Partner Key` ao acessar o ambiente de produção.

3. **Configurar Redirect URL / OAuth**
   - Confirme que o domínio de redirect (por exemplo, `https://razaiestoque.streamlit.app`) está igual ao configurado no console.
   - Caso a Shopee solicite, implemente/ajuste o fluxo de OAuth para:
     - Receber o `code` de autorização.
     - Trocar `code` por `access_token` (e opcionalmente `refresh_token`) usando o endpoint de token da Shopee.
   - Enquanto isso, você pode continuar usando o método manual (API Test Tool), mas o ideal é automatizar no futuro.

4. **Atualizar a API Base URL para produção**
   - Na sidebar, em "Opções avançadas (API)", defina:
     - `API Base URL`: `https://partner.shopeemobile.com`
   - Mantenha o host de sandbox apenas para testes.

5. **Separar credenciais de sandbox e produção**
   - Evite misturar valores de teste e produção no mesmo arquivo.
   - Sugestão:
     - Manter `razaiestoque.txt` apenas para sandbox.
     - Usar variáveis de ambiente ou outro arquivo não versionado (por exemplo, `.env.local`) para produção.

6. **Testar em produção com cuidado**
   - Depois de configurar credenciais de produção:
     - Sincronize dados da loja real.
     - Crie alguns Grupos Mestres com poucos itens para teste.
     - Faça uma atualização de estoque pequena e confira diretamente no Seller Center da Shopee.

7. **Ajustes finais e monitoramento**
   - Se a Shopee solicitar logs ou exemplos, você pode:
     - Registrar respostas resumidas da API (códigos de erro, mensagens) apenas para debug.
   - Garanta que não há exposição de credenciais em logs públicos.

---

## Boas práticas e segurança

- Nunca compartilhe `partner_key`, `access_token` ou credenciais reais em repositórios públicos.
- Use **sandbox** para todos os testes até a aprovação final.
- Leia sempre a documentação oficial da Shopee para mudanças de API.

---

## Licença

Uso interno do seller (Seller In House System). Ajuste esta seção conforme a política de licenciamento desejada para o projeto.

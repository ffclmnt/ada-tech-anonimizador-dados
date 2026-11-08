# 🛡️ TucanoPay - Anonimizador de Dados (LGPD)

> Aplicação web em Python/Streamlit para higienização e anonimização criptográfica de dados sensíveis em arquivos estruturados (CSV e Excel), desenvolvida em conformidade com as diretrizes da Lei Geral de Proteção de Dados Pessoais (LGPD).

Este projeto foi desenvolvido como um portfólio acadêmico e prático para a formação da **Ada Tech**, unindo conceitos de Engenharia de Software, Ciência de Dados (Pandas) e Direito Digital (Privacy by Design).

---

## ✨ Funcionalidades Principais

O sistema atua em três frentes principais no tratamento das planilhas:

### 1. Diagnóstico e Padronização de Dados
Antes de anonimizar, a ferramenta audita a planilha para evitar que variações de digitação gerem hashes inconsistentes:
* **Remoção de ruídos:** Limpeza de espaços extras e padronização de nulos disfarçados (`N/A`, `null`, `-`).
* **Documentos (CPF/CNPJ):** Validação de dígitos verificadores e remoção de pontuação, mantendo zeros à esquerda.
* **Formatos Universais:** Conversão de datas para o padrão **ISO 8601** (`AAAA-MM-DD`), padronização de telefones para **E.164** (`+55...`), e formatação segura de moedas e CEPs.

### 2. Motor de Anonimização
O usuário pode aplicar diferentes regras de ofuscação de acordo com a sensibilidade de cada coluna:
* 🔒 **Hash (Pseudonimização):** Utiliza **HMAC-SHA256** com uma chave secreta (`ANON_KEY`). Garante que o mesmo valor (ex: e-mail) gere sempre o mesmo hash, permitindo o cruzamento de dados em bancos analíticos sem expor a identidade real.
* 👁️ **Máscara (Truncamento):** Exibe apenas os primeiros caracteres de um dado (ex: CPF) seguidos de asteriscos de tamanho fixo, impedindo a engenharia reversa pelo comprimento da string.
* 🎲 **Randomização:** Substitui dados originais por strings alfanuméricas criptograficamente seguras geradas via módulo `secrets`.
* 📝 **Ocultação em Texto Livre (Regex):** Varre colunas de texto (como observações ou históricos) e substitui padrões conhecidos por *tags* (ex: `[CPF REMOVIDO]`, `[CARTÃO REMOVIDO]`, `[NOME REMOVIDO]`).

### 3. Proteções de Segurança e Privacy by Design
* **Processamento In-Memory:** O upload das planilhas é feito via `io.BytesIO`. Os dados nunca tocam o disco rígido do servidor.
* **Prevenção contra CSV Injection:** Neutralização de fórmulas maliciosas (células iniciadas com `=`, `+`, `-`, `@`).
* **Blindagem de Telemetria:** Arquivo `.streamlit/config.toml` configurado para desativar o rastreamento de uso (`gatherUsageStats = false`) e ocultar detalhes de erros técnicos em produção (`showErrorDetails = "none"`).

---

## 🚀 Como executar o projeto localmente

### Pré-requisitos
* Python 3.9 ou superior
* Git

### Passos de Instalação

1. Clone este repositório:
```bash
git clone https://github.com/ffclmnt/ada-tech-anonimizador-dados.git
cd ada-tech-anonimizador-dados
```

2. Crie e ative um ambiente virtual:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure sua chave secreta localmente:
Crie uma pasta chamada `.streamlit` na raiz do projeto e dentro dela um arquivo `secrets.toml` com o seguinte conteúdo:
```toml
ANON_KEY = "sua-chave-longa-e-aleatoria-aqui"
```
*(Nota: O arquivo `secrets.toml` já está no `.gitignore` para evitar vazamentos)*.

5. Execute a aplicação:
```bash
streamlit run tucano_anon.py
```
A interface gráfica abrirá automaticamente no seu navegador no endereço `http://localhost:8501`.

---

## 🛠️ Tecnologias Utilizadas
* **[Python 3](https://www.python.org/):** Linguagem base.
* **[Streamlit](https://streamlit.io/):** Framework para a construção ágil da interface web.
* **[Pandas](https://pandas.pydata.org/):** Motor de processamento, análise em lote e manipulação dos DataFrames.
* **[OpenPyXL](https://openpyxl.readthedocs.io/):** Motor para leitura e escrita segura de arquivos `.xlsx`.
* **Criptografia Nativa:** Bibliotecas `hashlib`, `hmac` e `secrets` para geração de ofuscação robusta.

---
*Desenvolvido para apresentação acadêmica - Ada Tech.*
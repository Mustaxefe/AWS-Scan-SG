# 🔐 AWS Security Group Scanner

Script em Python para identificar Security Groups expostos publicamente na AWS e classificar o nível de risco com base em portas sensíveis.

---

## 📌 Objetivo

Este projeto foi desenvolvido com o objetivo de simular uma análise de segurança em ambientes cloud, identificando possíveis exposições indevidas causadas por regras permissivas em Security Groups.

---

## ⚙️ Funcionalidades

- 🔍 Listagem de Security Groups via boto3
- 🌐 Detecção de regras abertas para:
  - `0.0.0.0/0` (IPv4)
  - `::/0` (IPv6)
- 🚨 Identificação de portas sensíveis:
  - SSH (22), RDP (3389), VNC (5900), Telnet (23)
  - Bancos de dados (3306, 5432, 1433, 1521, 27017, 6379, 9200)
- 📊 Classificação de risco:
  - Crítico
  - Alto
  - Médio
  - Baixo
- 📁 Exportação de resultados em:
  - CSV
  - JSON

---

## 🧠 Classificação de Risco

| Tipo de Exposição            | Risco    |
|------------------------------|----------|
| Acesso administrativo aberto | Crítico  |
| Bancos de dados expostos     | Alto     |
| Serviços internos expostos   | Médio    |
| Sem exposição pública        | Baixo    |

---

## 🛠️ Tecnologias Utilizadas

- Python 3
- boto3 (AWS SDK)
- AWS IAM (Least Privilege)

---

## 🚀 Como Executar

### 1. Clonar o repositório

git clone https://github.com/SEU_USUARIO/aws-sg-scanner.git

cd aws-sg-scanner

---

### 2. Instalar dependências

pip install -r requirements.txt

---

### 3. Configurar credenciais AWS

aws configure

---

### 4. Executar o script

python3 scanner.py

---

### Exemplo de saída

```text
Security Group: ssh-vuln
Quantidade de regras encontradas: 1
Porta exposta: 22  
```
---

### Permissões necessárias

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeSecurityGroups"
  ],
  "Resource": "*"
}
```
---

### Cenário de Teste

Foram criados Security Groups propositalmente vulneráveis para validar o funcionamento do scanner, incluindo:

 - SSH aberto para internet
 - Banco de dados expostos
 - Tráfego totalmente liberado
 - Regras IPv6 abertas

---

### 📚 Aprendizados

Durante o desenvolvimento deste projeto, foram explorados conceitos como:

- Segurança em Cloud (AWS)
- Estrutura e funcionamento de Security Groups
- Automação de auditoria com Python
- Princípio de menor privilégio (IAM)
- Identificação de superfícies de ataque

---

### Possíveis Melhorias
- Suporte a múltiplas regiões
- Correlação com instâncias EC2 (exposição real)
- Integração com AWS Security Hub
- Execução automatizada via Lambda
- Dashboard de visualização dos riscos

---

### Autor
Felipe Cordeiro
[Linkedin](https://www.linkedin.com/in/cordeiro-felipe/)

---

### ⚠️ Aviso

Este projeto é destinado para fins educacionais e deve ser utilizado apenas em ambientes controlados.
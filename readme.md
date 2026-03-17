# 🚀 Ansible PBR Automation (Cisco)

Projeto de automação de **Policy-Based Routing (PBR)** em dispositivos Cisco, utilizando **Ansible** e **Netmiko**, com foco em ambientes distribuídos e alta disponibilidade.

---

## 📌 Objetivo

Automatizar a configuração de PBR em múltiplos roteadores, garantindo:

- Padronização de configuração
- Redução de erro humano
- Escalabilidade operacional
- Integração com IP SLA / Track

---

## 🏗️ Estrutura do Projeto
├── inventory/ # Inventário de hosts
├── group_vars/ # Variáveis por grupo (NÃO versionar credenciais)
├── host_vars/ # Variáveis específicas por host
├── playbooks/ # Playbooks principais
│ ├── central_v200.yml
│ ├── remote_sbt.yml
│ └── *_netmiko.yml
├── scripts/ # Scripts auxiliares
├── logs/ # Logs de execução
├── .venv/ # Ambiente virtual (ignorado)


---

## ⚙️ Tecnologias Utilizadas

- Ansible
- Netmiko
- Python 3.x
- Cisco IOS

---

## 🚀 Como Executar

### 1. Clonar repositório


git clone https://github.com/seu-usuario/ansible-pbr.git
cd ansible-pbr

### 2. Criar ambiente virtual

python3 -m venv .venv
source .venv/bin/activate
pip install ansible netmiko

### 3. Configurar variáveis

cp group_vars/all.yml.example group_vars/all.yml
cp host_vars/router1.yml.example host_vars/router1.yml

### 4. Executar playbook

ansible-playbook -i inventory/hosts playbooks/remote_sbt.yml

#########################################################################

📡 Funcionalidades

> Configuração de PBR
> Integração com IP SLA + Track
> Backup automático (running-config)
> Execução em massa
> Suporte a múltiplos sites

📊 Casos de Uso

> Balanceamento de links satelitais
> Failover com IP SLA
> Ambientes MPLS + Satélite + Internet

⚠️ Boas Práticas

> Sempre validar em ambiente de homologação
> Usar --check antes de aplicar
> Versionar apenas templates
> Registrar logs de execução

👨‍💻 Autor

Projeto desenvolvido para automação de redes em ambiente crítico (CINDACTA IV / TTTM).

SO BETPatrick CHAGAS dos Santos

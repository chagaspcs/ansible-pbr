# ⚙️ Setup do Ambiente

## 1. Ambiente virtual

```bash
python3 -m venv .venv
source .venv/bin/activate


## 2. Instalação￼

pip install ansible netmiko


## 3. Configuração

cp group_vars/all.yml.example group_vars/all.yml


## 4. Execução

ansible-playbook -i inventory/hosts playbooks/remote_sbt.yml


---

## 📄 docs/security.md

```markdown
# 🔐 Segurança

## ❌ Nunca fazer

- Subir senhas no GitHub
- Versionar `group_vars/all.yml`
- Versionar `host_vars/*.yml`

---

## ✅ Boa prática

- Usar arquivos `.example`
- Usar variáveis de ambiente
- Usar Ansible Vault (recomendado)

---

## 🔒 Alternativa (Vault)

```bash
ansible-vault encrypt group_vars/all.yml


---

# 🔐 3. Templates SEGUROS (CRÍTICO)

## 📄 group_vars/all.yml.example

```yaml
---
ansible_user: "seu_usuario"
ansible_password: "sua_senha"
ansible_network_os: "ios"
ansible_connection: "network_cli"

# Role pbr_fix

Ajusta a prioridade de um route-map de PBR em roteadores Cisco **somente se**:
1. Uma rota específica estiver presente na RIB.
2. Uma policy `ip policy route-map <nome>` estiver aplicada na interface configurada.

## Variáveis principais

- `prefix_to_check` / `mask_to_check`
- `interface_to_check`
- `route_map_name`
- `new_sequence` / `old_sequence`
- `rm_match_acl`
- `rm_new_nexthop`
- `test_dest` / `test_source`
- `route_output_pattern`

Configure-as em `group_vars/routers.yml` ou `host_vars/<host>.yml`.

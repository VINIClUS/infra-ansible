# samba_ad_compatibility

Primeira prova protegida S2, manual, somente em um LXC lab próprio já iniciado.
Defaults `samba_ad_compatibility_enabled: false` e
`samba_ad_compatibility_apply: false`. Exige `--limit` exato de **um nó atual
do probe**, facts correspondentes e somente `--tags samba_ad_compatibility`.
O lifecycle `samba_ad_guest` continua limitado ao nó do template.

Entrada separada/inert: `contracts/samba_ad/s2-example.yml`. O request conserva
schema/hash de S1, scope lab, action present e digest atual. A role usa uma cópia
enabled para leituras, com apply falso; não cria/inicia/remove guests. Exige
proveniência por revisões completas e hash do parecer S1 aplicado/auditado.
`policy_sha256` é SHA256 do JSON canônico de `request.firewall` (sort_keys e
separadores sem espaços). Não alterar firewall/marker para adotar clone existente.

Disabled encerra a role. Check-mode/apply falso faz preflight readonly, sem
executar a prova mutante, abrir arquivo, instalar pacotes ou fazer cleanup.
Config `planned`/ausente, pending, drift, router/firewall desconhecido, template
mudado, digest obsoleto ou power state diferente são recusados.

Em apply explícito, o transporte é `pct exec` no VMID conferido. Antes de abrir
um arquivo exclusivo em `/var/lib`, o helper compara hostname, euid, namespaces
user/mnt/pid/cgroup com o init do LXC e com o PVE, uid_map não identidade, AppArmor,
boot-id, filesystem e device/inode do diretório. O path de cgroup lido dentro do
guest permanece nessa representação; o host registra separadamente membership,
PID/starttime/NSpid do init resolvido por `pct pid VMID`, estáveis antes/depois.
Paths de namespaces de cgroup diferentes não são comparados. O arquivo usa
O_EXCL/O_NOFOLLOW e fd; cleanup confere nome/device/inode, sem globs ou rm -rf.
Somente ext4/xfs/zfs/btrfs são aceitos nesta implementação; outro layout é erro
operacional que exige revisão, não incompatibilidade Samba automática.

`security.NTACL` recebe um sentinel opaco, sem instalar Samba: prova autorização
do namespace protegido, não valida descritor Samba. EPERM/EACCES/EOPNOTSUPP
reproduzido na mesma operação basta para selecionar QEMU, com qualification
pending. Não instala Samba nem cria segundo LXC para insistir. Se passar, a ACL
POSIX usa o formato Linux UAPI v2 e verifica leitura por UID mapeado autorizado
e negação por outro UID. Não há dependência nova de ferramenta/pacote ACL.

A evidência privada contém observações de identidade antes/depois e o resultado
estruturado, sem saída bruta de comandos. Diretório do operador deve existir,
ser próprio, canônico, sem symlinks em nenhum ancestral e modo 0700. Antes da
prova, `prepare_report` roda no controlador, `become: false`, com a mesma validação
do writer: usuário efetivo/owner/mode, canonicalidade, acesso e saída exclusiva
do run_id gerado no controlador. Não cria laudo ou placeholder. O runner usa esse
run_id; `write_report` repete a validação e confere o mesmo usuário e dir dev/ino
antes de gravar `<run_id>.json` por O_EXCL, modo 0600 e fsync. Não sobrescreve runs anteriores.
Manter esse diretório fora do Git. Request/resultados vão por stdin e `no_log`.
A saída humana contém somente estado/status/escopo. Erro operacional é persistido
quando há laudo e depois falha a role; falha de preflight não executa a prova.

Exit 0 significa primeira prova aprovada; 3 é incompatibilidade reproduzida;
2 é erro operacional. Nenhum deles qualifica sozinho LXC ou VM para produção.
Respostas e snapshots exigem objetos/protocolo válidos antes de entrar nas
observations. Após uma tentativa, formato rejeitado mantém result nulo, cleanup
desconhecido/incompleto, erro operacional e selection nula, com laudo persistível;
não se conserva stdout bruto. Um pós-readback inválido mantém after nulo e
preserva o resultado da prova que já foi validado, sem inventar confirmação.
Timeout, ferramenta ausente, EINVAL, ENOSPC, identidade errada, drift ou cleanup
incompleto não escolhem plataforma. Não há fallback para execução no host.

Esta role não implementa instalação, floresta lab, segundo LXC, bateria AD,
prova QEMU nem limpeza de guest automática. A continuação está no
[runbook S2](../../docs/samba-ad-s2.md): laudo durável primeiro; depois stop e
absent explícitos pelo lifecycle S1. Runtime depende de S1 aplicado e auditoria
independente de estado. Nenhum recurso/compatibilidade foi observado por estes testes.

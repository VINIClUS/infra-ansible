# Samba AD — S2, prova protegida e contrato de evidência

Código disponível: stop lab explícito, cleanup/readbacks, primeira prova LXC,
substrato QEMU via QGA, agregação conservadora, laudo/classificador e consumidor
genérico de bundle privado. Nenhum runtime S2,
escolha real, pin válido, floresta institucional ou prontidão foi estabelecido.
S1 aplicado e parecer independente de estado são precondições de execução.

## Execução manual posterior

1. Revisar novos digests, VMID/node/tipo/nome/MAC/IP, ownership, pending/tasks,
   template, capacidade/reserva de 2 GiB e firewall PVE/roteador. Iniciar apenas
   o probe próprio pelo `start` de S1 se necessário, com tag/limit S1 originais.
2. Preparar configuração privada S2 fora de group_vars/host_vars: flags de opt-in,
   request S1 atual, provenance e router exatos; usar diretório protegido fora do
   Git para laudos. Nenhum exemplo público comprova estado ou autoriza aplicação.
   Antes da prova, o controlador executa `prepare_report(directory)` sem become,
   com a mesma função de validação usada por `write_report(directory, report, prepared)`.
   Confere canonicalidade/ancestrais sem symlink, owner igual ao usuário efetivo,
   modo 0700, acesso e ausência de saída daquele run_id. O run_id nasce nesse
   preflight e é o mesmo enviado ao probe e ao writer, ambos vinculados ao mesmo
   usuário e dir dev/ino. Não há reserva/placeholder que pareça um laudo medido.
   O writer revalida tudo após a prova; mudança concorrente ou falha de I/O ainda
   pode impedir persistência e interrompe o fluxo sem autorizar cleanup/avanço.
3. Executar primeiro preflight, limitado ao nó atual do probe, e somente depois
   a prova explícita. Exemplo de forma de comando, com paths substituíveis:

   ```bash
   ansible-playbook -i /caminho/privado/hosts.yml playbooks/samba-ad-compatibility.yml \
     -e @/caminho/privado/request-s2.yml --limit pve-test --tags samba_ad_compatibility --check
   ```

4. A primeira prova ocorre exclusivamente dentro do LXC e limpa somente seu
   arquivo. Xattr protegido negado duas vezes com identidade válida seleciona
   `qemu`, qualification `pending`. Persistir laudo antes de parar/remover o
   próprio probe. Não instalar Samba ou criar segundo LXC após falha conclusiva.
5. `action: stop` exige lab próprio e digest atual; shutdown 60 s, forceStop=0,
   readback stopped. Timeout não causa kill/delete/retry. `absent` continua sem
   parada implícita; conferir firewall próprio, ausência final e volumes. Resíduo
   exige recuperação técnica direcionada, sem apagar por prefixo ou glob.
6. Uma prova positiva mantém selection nula. Antes de instalar qualquer pacote,
   revisar egress exato, origem assinada/fingerprint/InRelease/hashes/advisories
   e Samba 4.25.1/LDB/Python coerentes. Firewall faz parte do hash de propriedade:
   se precisar de política diferente, limpar somente o lab próprio e recriar
   uma geração com política revisada; não atualizar marcador para adotar clone.

## Continuação LXC que ainda exige implementação e runtime próprios

LXC só pode ser qualificado com dois hosts físicos, em `lab.ad.test`, e a bateria
completa: NTACL Samba real/ACL/SID, systemd, SYSVOL unidirecional com autor único,
sysvolcheck/GPT.INI, replicação/Kerberos/DNS/SID, relógio, auditoria e rede/isolamento.
Não conceder CAP_SYS_TIME, capacidades de auditoria do host, privileged, nesting
ou unconfined; não usar user.NTACL. Não afirmar DFS-R nativo ou executar dbcheck
--fix. Credenciais somente por stdin/FD/API em memória, nunca por argv/log.

Fallback VM já está autorizado, mas não é provisionado por esta role. Após
cleanup/readback e capacidade novos, provar candidato QEMU próprio em cada
placement, sequencial se necessário: full clone/migração offline, 2 vCPU,
4 GiB/64 GiB, sockets=1/balloon=0, sem passthrough ou filesystem do host.
Confirmar console/QGA e identidade/nonce da VM; não presumir agent ou confiança
SSH pelo nome do template. Namespaces com números iguais em kernels diferentes
não identificam a VM. Prova mínima: protected xattr/ACL efetiva, systemd, relógio,
auditoria no kernel próprio e rede/isolamento. Qualifica apenas `qemu_substrate`;
Samba/SYSVOL/replicação de produção continuam nas etapas S4/S5.

O runner da bateria completa LXC continua não implementado. Backups/DR, custódia
externa e inventário/migração municipal permanecem fora da entrega e dos gates.

## Substrato QEMU mínimo, manual e separado da produção

A mesma role aceita `samba_ad_compatibility_probe: qemu_substrate`, mantendo
`enabled/apply: false` por padrão e o mesmo `--limit` do nó atual, tag dedicada,
request S1 de lab, proveniência e parecer S1. O request deve apontar para QEMU
próprio já iniciado, disco `scsi0`, digest atual e template/digest revisados.
O lifecycle continua exclusivamente em S1; o runner não clona, instala pacotes,
inicia serviços, altera relógio, concede capacidades ou provisiona Samba/AD.
Check-mode/apply falso somente lê precondições S1; não entra no QGA, cria arquivo
ou prepara laudo. Assim esse preflight não comprova disponibilidade do agent.

Em apply, o transporte nativo é `qm guest exec` síncrono com `--pass-stdin 1`,
timeout QGA de 30 s e subprocess de 40 s. Não há polling, retry, shell ou fallback
no PVE. O clone deve trazer QGA e Python3 instalados e agent habilitado no config;
falta dessas condições é erro operacional. A captura faz ping QGA limitado a
10 s, nonce novo por stdin e verifica hostname exato, root, boot-id distinto do
PVE, UUID SMBIOS do config igual ao DMI observado, filesystem e diretório. Config
PVE, boot/UUID e âncora node/VMID/spec/digests são estáveis antes/depois. Números
de namespace de kernels diferentes não são comparados. O runner exige execução
no nó PVE correto e nunca executa o helper diretamente no host.

| Check mínimo | Medição real e limite |
| --- | --- |
| security_ntacl | Sentinel opaco em security.NTACL via fd e readback; não é um descritor Samba. |
| posix_acl | ACL UAPI v2 e leitura permitida/negada por UIDs distintos, no arquivo próprio. |
| systemd | PID 1 systemd e is-system-running=running; degraded falha operacionalmente. |
| clock | NTPSynchronized=yes e realtime da VM dentro da janela PVE ±2 s; nenhuma escrita de relógio. |
| audit | AUDIT_GET via NETLINK_AUDIT no kernel da VM: enabled, listener PID, política de falha e zero lost. |
| isolation | systemd-detect-virt identifica qemu/kvm, sem container; config S1 sem passthrough/mounts/hooks. |
| network | Uma NIC além de lo, MAC/MTU/IPv4/gateway exatos e UP/LOWER_UP; firewall PVE/roteador via guards S1. |

Audit mede status do kernel/listener, não entrega de eventos ou retenção de logs.
Network mede configuração e política carregada; não afirma alcance de serviços
nem substitui os testes de protocolos S4/S5. Clock compara com o relógio PVE da
janela; não certifica a fonte NTP. Os binários systemd e ip devem existir no
template; não são instalados pelo probe. Resposta parcial/PID, truncamento, nonce
errado, timeout, ausência de ferramenta, drift ou qualquer falha é operacional,
nunca incompatibilidade LXC nem sucesso sintético. Um timeout pode deixar processo
do guest em andamento: cleanup fica desconhecido/incompleto até recuperação e
readback direcionados, sem kill/retry automático.

O helper limpa só seu arquivo com o mesmo O_EXCL/O_NOFOLLOW e verificação de inode
da primeira prova. A role persiste o laudo completo no controlador antes de
reportar falha. Um QEMU medido conserva `selection: null`, `qualification: pending`
e cleanup guest pending. Executar em dois nós físicos distintos, sequencialmente
se necessário, persistindo cada laudo antes de stop/absent explícitos S1.

### Agregação após cleanup explícito

`tools/samba_ad/qemu_probe_runner.py` também oferece entrada manual JSON por stdin
em um PVE do cluster, usando cópia revisada dos módulos. Não usa credenciais por
argv. Exemplo de forma, com o payload privado já preparado:

```bash
python3 tools/samba_ad/qemu_probe_runner.py < /caminho/privado/s2-aggregate.json
```

O objeto fecha `{mode: aggregate, operation: {enabled, apply, check, reports,
requests, directory, provenance}}`. Flags são booleanas explícitas; disabled
retorna sem API/escrita. `reports` contém os objetos originais duráveis, na mesma
ordem dos requests S1 `lab`/digest de cada geração. `provenance` contém as revisões
completas `public_revision/private_revision` da agregação revisada. `directory`
é absoluto/canônico/0700, próprio do usuário efetivo, fora do Git, no PVE onde o
comando roda. Fazer primeiro `check: true`; depois `check: false, apply: true`.

A agregação não para/remove guests. Exige ausência atual de todos os VMIDs,
firewalls e volumes pelos readbacks S1, inclusive quando VMID foi reutilizado
entre gerações. Só executar após o último cleanup S1. Também revalida versões
kernel/PVE e digests dos templates; filesystem/política divergentes são recusados.
Preserva o laudo LXC integral e todos os demais laudos nas observations, com seus
hashes e revisões originais, sem reclassificar um erro operacional. `helper_sha256`
e `s1_audit_sha256` agregados são os hashes canônicos das respectivas listas
ordenadas dos hashes originais; não representam um único helper/parecer novo.
O header registra a revisão da agregação, permitindo que o LXC tenha sido medido
antes da implementação QEMU. Os originais continuam necessários para auditoria.

Antes de contar um placement, a agregação revalida o protocolo fechado da origem,
não apenas o envelope genérico. QEMU exige capturas antes/depois coerentes com
node/VMID/spec/config/template, boot/UUID e filesystem; `before.probe_request`
registra o request enviado ao helper, incluindo run_id, nonce, identidade e
resource, separadamente da resposta. O resultado deve corresponder a esse
request e aos checks/cleanup externos, com resumos tipados de cada medição.
Laudos QEMU antigos sem esse request gravado são recusados; não completar o
campo retrospectivamente a partir da resposta. Preservar o original e produzir
uma nova medição em execução autorizada.
A primeira prova LXC mantém seu protocolo original: run_id, snapshots e resultado
são validados pelos validadores LXC, com VMID/init/starttime/NSpid, namespaces,
hostname, boot, uid_map/AppArmor e filesystem estáveis. Os campos do subject
node/spec/config/template e a política devem corresponder ao request S1 da
origem. Não exige nonce/UUID QEMU nem compara namespaces entre kernels.
Traços ausentes, campos desconhecidos ou contradições são recusados. Resultados
operacionais coerentes e completos permanecem pending; falhas posteriores que
invalidam as capturas ou contradizem o resultado também impedem a agregação.
Nenhum readback atual de ausência reconstrói uma medição histórica, e os hashes
preservados demonstram integridade/coerência, não atestação externa da origem.
Só a incompatibilidade LXC preservada permite seleção qemu. Apenas dois nós
distintos com todos os MINIMUM reais e cleanup completo dão `qemu_substrate`.
Um nó ou qualquer erro permanece pending. O mesmo writer exclusivo 0600/fsync
persiste o agregado antes de imprimir estado/metadados; check-mode não escreve.
Não cria bundle/pin/aprovação independente, nem autoriza S4/S5 por si só.

## Laudo e bundle operacional privado

`compatibility.validate_report` fecha schema `samba-ad-s2/v1`: run_id/UTC,
public_revision/private_revision, hashes do helper transportado e parecer S1,
subjects com node/kind/spec/config/template/boot, checks por subject, cleanup,
observations antes/depois/resultado, selection, qualification e fingerprint.
Cada subject exige `template: {node, kind, vmid, digest}` igual a uma referência
do fingerprint e com digest/kind coerentes com o subject. Qualificação do alvo
usa somente subjects que testaram aquele template completo naquele placement;
um template aparecer na lista global não qualifica seu uso em todos os nós.
Cleanup separa `file: complete|incomplete|not_created` de
`guest: complete|pending`: primeira prova nunca declara o guest removido.
Fingerprint inclui versões de kernel/PVE por nó, templates/digests, filesystem,
isolamento e hash de política. Os valores de identidade/observações são privados;
o relatório público deve referenciar seus hashes e contagens sanitizados.
Nas observações, `host_anchor` vincula VMID ao init por `pct pid`, starttime,
NSpid terminando em 1 e membership host-side, revalidados durante a captura e
após a prova. O namespace cgroup é conferido por inode junto a user/mnt/pid.
O path `guest.cgroup` é observado dentro do CT e comparado somente nessa mesma
representação; nunca com o path host-side do init lido pelo processo do PVE.
O decoder exige objeto JSON; formato de resultado e snapshots são validados
antes de incorporar qualquer observação. Se uma resposta pós-tentativa é
rejeitada, o laudo conserva run_id/âncora, erro operacional e selection nula,
com result/after nulos quando não validados e cleanup desconhecido/incompleto
quando a resposta da prova não permite afirmá-lo. Sem stdout bruto ou prova
inventada. Resultado/cleanup já validados são preservados em falha posterior de
API/readback; a confirmação posterior rejeitada não é registrada como válida.

`select_platform(report)` distingue erro operacional e incompatibilidade
reproduzida. `qualification(report)` exige dois nós distintos e todos os checks:
security_ntacl/posix_acl/systemd/clock/audit/isolation/network para QEMU, acrescidos
de samba_systemd/sysvol/replication para LXC. QEMU exige ainda a incompatibilidade
LXC preservada no laudo agregado. Um guest QEMU com check incompatível não passa.

`request.compatibility` é envelope `{sha256, data}`, sendo sha256 do JSON canônico
de data. `data` fecha schema `samba-ad-s2-bundle/v1` e contém:

| Artefato | Campos de vínculo exigidos |
| --- | --- |
| pin | schema=1; report_sha256, choice_sha256, audit_sha256; provenance com reviewed_config_revision completo, path privado fixo e review_ref imutável `git:<commit>:<path>` |
| choice | schema=1; platform, qualification, target_role dc01/dc02, target_sha256, report_sha256, fingerprint_sha256 |
| report | Laudo completo e qualificado; cleanup completo e observações antes/depois/resultado presentes |
| audit | schema=1; scope S2-state, decision accept, hashes exatos de report/choice, revisões testadas e mesma review_ref do pin |

`target_sha256` usa exatamente o algoritmo de ownership de S1: JSON canônico de
owner/scope/resource/template/firewall. Não alterar esse algoritmo. Alterar alvo,
tipo, template, egress, kernel/PVE ou artefatos invalida o vínculo. O consumer
compara ainda o fingerprint de kernel/PVE vivo, template/digest, sizing e nó
qualificado antes do lifecycle production. Digests históricos do probe destruído
nunca são os expected_digest dos finais. Production conserva todas as guardas
S1 e defaults falsos; só os alvos DC vinculados são aceitos, não CA/pilotos.

Pin e bundle reais ficam exclusivamente na configuração operacional PRIVADA,
revisada e carregada de revisão imutável. A origem dessa configuração é a raiz
de confiança do operador: hashes e referências verificam coerência, não provam
por si uma revisão humana ou a autenticidade de um Git remoto. O auditor deve
conferir a revisão privada efetivamente carregada e os pareceres/artefatos que
ela referencia. Não fornecer bundle ad hoc por booleano ou declarar aprovação
apenas porque seus hashes foram recalculados. Não existe pin operacional público.

Production é recusado sem todas essas entradas. O consumidor não cria recursos
por si só, não integra auto-deploy e não dispensa despacho da etapa consumidora.
Nenhum final ou floresta institucional pertence ao runtime S2.

## Verificação local e limites

Testes usam adapters falsos para PVE, transporte e operações da prova; não gravam
security.NTACL/ACL no host local. Os testes de persistência gravam apenas JSON
temporário. Checks locais focados e syntax/lint não comprovam pct/namespace,
shutdown, filesystem, firewall ou confiança QGA reais. Conferir ajuda/API instalada
antes do runtime; formatos desconhecidos falham fechados.

APIs de shutdown/delete não recebem digest transacional neste adapter: há
readback imediatamente anterior e execução manual serial. Congelar operações
concorrentes do recurso durante a janela; lock/pending/drift abortam. A observação
de capacidade não é reserva transacional. Cleanup do arquivo usa diretório root
não gravável por terceiros; não é defesa contra outro processo root malicioso
substituindo a entrada entre stat e unlink.

Referências: contratos S1 e plano aprovado versionados; formato ACL conferido nos
headers Linux UAPI `linux/posix_acl.h` e `linux/posix_acl_xattr.h` instalados;
AUDIT_GET/status em `linux/audit.h`; transporte em
[qm(1), qm guest exec](https://pve.proxmox.com/pve-docs/qm.1.html), consultado em
2026-11-08 (Context7 indisponível por quota). Conferir CLI instalada antes do runtime.
Context7 indisponível pela cota informada; nenhum download foi necessário.

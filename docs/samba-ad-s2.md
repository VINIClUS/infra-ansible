# Samba AD — S2, prova protegida e contrato de evidência

Código disponível: stop lab explícito, cleanup/readbacks, primeira prova LXC,
laudo/classificador e consumidor genérico de bundle privado. Nenhum runtime S2,
escolha real, pin válido, floresta institucional ou prontidão foi estabelecido.
S1 aplicado e parecer independente de estado são precondições de execução.

## Execução manual posterior

1. Revisar novos digests, VMID/node/tipo/nome/MAC/IP, ownership, pending/tasks,
   template, capacidade/reserva de 2 GiB e firewall PVE/roteador. Iniciar apenas
   o probe próprio pelo `start` de S1 se necessário, com tag/limit S1 originais.
2. Preparar configuração privada S2 fora de group_vars/host_vars: flags de opt-in,
   request S1 atual, provenance e router exatos; usar diretório protegido fora do
   Git para laudos. Nenhum exemplo público comprova estado ou autoriza aplicação.
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

## Continuação que ainda exige implementação e runtime próprios

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

Os runners dessas duas continuações não estão implementados aqui. O consumidor
aceita laudos completos produzidos e auditados posteriormente, sem gerar checks
passed ou aprovação. Backups/DR, custódia externa e inventário/migração municipal
permanecem fora da entrega e dos gates.

## Laudo e bundle operacional privado

`compatibility.validate_report` fecha schema `samba-ad-s2/v1`: run_id/UTC,
public_revision/private_revision, hashes do helper transportado e parecer S1,
subjects com node/kind/spec/config/template/boot, checks por subject, cleanup,
observations antes/depois/resultado, selection, qualification e fingerprint.
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
headers Linux UAPI `linux/posix_acl.h` e `linux/posix_acl_xattr.h` instalados.
Context7 indisponível pela cota informada; nenhum download foi necessário.

# Samba AD DC — plano de implementação em produção

> Para agentes: executar uma etapa por chat novo, com revisão independente do diff antes do merge e auditoria independente após aplicações. A coordenação acompanha todas as etapas até a conclusão.

**Goal:** entregar dois DCs Samba seguros no Proxmox, com PKI, clientes piloto e observabilidade.
**Architecture:** primeiro homologar LXC não privilegiado; usar VMs quando ACLs protegidas, SYSVOL, tempo, auditoria ou isolamento forem incompatíveis. Separar os DCs em hosts físicos distintos e a CA intermediária em uma VM própria.
**Tech Stack:** Proxmox VE, Debian 13, Samba 4.25.1, Ansible, ansible-vault, step-ca, rsync, Loki/Prometheus/Alloy existentes.
**Spec:** este documento registra o desenho aprovado. A SPEC-AD-001 fornecida pelo usuário é referência técnica; as decisões explícitas do usuário abaixo prevalecem sobre o anexo.

## Global Constraints

- O usuário autorizou implementação, criação de chats, multiagentes, SSH, PRs, merges e alterações de infraestrutura dentro deste escopo. Não repetir pedidos de autorização já concedida.
- Criar uma floresta nova no namespace institucional autorizado, com NetBIOS definido no campo domain.netbios do inventário privado após verificar colisões. O nome DNS, a topologia e os endereços reais ficam exclusivamente no inventário privado.
- LXC deve ser não privilegiado, com AppArmor ativo e sem nesting desnecessário. Não usar user.NTACL, capacidades do host ou AppArmor unconfined para contornar falhas. A alternativa VM está autorizada.
- FFL/DFL 2016; esquema 2019/v88 é um conceito distinto. Validar opções na versão instalada, sem elevação repetida ou dbcheck --fix automático.
- Samba 4.25.1 e dependências compatíveis de repositório assinado, com origem, assinatura, fingerprint e advisories verificados. Não presumir que o pacote nativo da distribuição atende ao requisito.
- ansible-vault é o mecanismo aprovado. Valores só no inventário privado em arquivos vault.yml integralmente cifrados; não imprimir valores nem passar segredos em argumentos.
- Não armazenar chaves privadas, bancos de PKI, tickets ou outros materiais sensíveis no Git, mesmo cifrados. A chave da raiz fica offline fora dos servidores.
- Código reutilizável neste repositório; topologia e variáveis reais em infra-ansible-inventory. Exemplos públicos fictícios e inertes.
- Roles novas desabilitadas por padrão, com --limit exato e uma tag dedicada por fluxo mutante. Identidade e precondições verificadas antes de cada alteração.
- Preservar checkouts e alterações de terceiros. Usar worktrees e branches codex/. Não enfraquecer os contratos das roles existentes.
- Não adicionar provisionamento de floresta ao deploy automático de main. Merges continuam sujeitos aos checks e à revisão independente; acompanhar o pipeline existente após merge.
- Implantar o serviço em produção e usar somente clientes piloto novos. A migração municipal contará com uma etapa própria; não alterar DHCP/DNS da LAN nem ingressar estações existentes nesta entrega.
- A entrega vigente compreende dois DCs, PKI, clientes piloto novos e observabilidade. Inventário municipal completo não é gate de prontidão.
- Não alterar serviços de e-SUS PEC, SIHA ou outros projetos. Não enviar mensagens externas ou notificações sem autorização específica.
- Prefixar comandos shell com rtk; documentação humana usa comandos normais. Registrar evidências sem segredos ou dados pessoais.

## Review Focus

- Nenhum fluxo deve aceitar VMID, SID, node, endereço ou tipo conflitante, nem substituir recursos existentes silenciosamente.
- Reexecuções não recriam florestas, repetem ingresso, elevam esquema ou ampliam regras de firewall.
- Certificados precisam validar SAN, cadeia, EKU e correspondência da chave; rotação cria novo par de chaves.
- Uma falha de coletor ou timer de certificados deve gerar estado observável, sem imprimir material sensível.
- Os auditores devem avaliar os controles da entrega vigente conforme a última decisão de escopo do usuário.

## Protocolo por etapa

1. Ler o brief e os contratos vigentes; registrar mini-plano, entradas, saídas e verificações.
2. Para comportamento novo, escrever testes úteis de precondições/falhas antes da implementação. Evitar testes que apenas espelham texto de implementação.
3. Implementar somente a etapa, atualizar documentação e rodar checks apropriados.
4. Produzir relatório com commits, comandos/resultados, evidências, riscos e precondições da próxima etapa; abrir PR sem merge.
5. Um chat novo revisa diff imutável, aderência à especificação e qualidade/segurança. Correções passam por nova revisão.
6. A coordenação faz merge após aprovação e checks; acompanha CI e autoriza tecnicamente a aplicação já aprovada pelo usuário.
7. Após aplicação, outro chat novo verifica estado, exposição e regressões. Só avançar com evidências.

## Task 1: S0 — Descoberta e contratos

**Consumes:** este plano, SPEC-AD-001 e contratos dos dois repositórios nas revisões remotas verificadas.
**Produces:** desenho/contratos públicos com dados fictícios; manifesto privado desabilitado; relatório de descoberta sanitizado; PRs com testes de contrato.

- [ ] Confirmar estado dos repositórios, autoridade DNS já declarada, ausência de floresta informada pelo usuário, DNS/SRV, redes e capacidade por leitura.
- [ ] Inspecionar templates, versões, armazenamento, relógio e coletor existente. Não iniciar/parar guests, instalar pacotes ou alterar infraestrutura nesta etapa.
- [ ] Registrar no inventário privado realm, NetBIOS, placement, VMIDs, MACs/IPs reservados, templates, rede, fontes, acessos administrativos e perfis de segredos por nome.
- [ ] Definir uma rede de identidade exclusiva e portas por origem/destino; preservar todas as redes e regras existentes.
- [ ] Preparar verificação de split DNS para nomes públicos necessários aos pilotos; a migração municipal é etapa separada.
- [ ] Criar defaults inertes de contrato e validadores significativos, sem implementar provisionamento antecipadamente. Confirmar caminho de execução manual separado do deploy automático.
- [ ] Rodar testes e checks cabíveis, revisar vazamentos, commitar e abrir PRs. Não fazer merge nem aplicar.

## Task 2: S1 — Rede e provisionamento

**Consumes:** manifesto privado e contratos auditados de S0.
**Produces:** rede de identidade, entrypoints manuais e guests próprios verificáveis, sem floresta institucional ainda.

- [ ] Implementar uma role de provisionamento dedicada, sem generalizar proxmox_lxc_guest do controlador.
- [ ] Clonar integralmente os templates locais, migrar os clones desligados e iniciar somente após validar identidade/rede no destino.
- [ ] Validar capacidade e reserva mínima de 2 GiB por host antes de cada criação; falhar sem interromper guests de terceiros.
- [ ] Aplicar rede/roteador/firewall com estado anterior verificado para reversão técnica, dead-man, acesso por console Proxmox e readback por nova conexão. Preservar políticas das demais zonas.
- [ ] Adotar 2 vCPU/4 GiB/64 GiB por DC; CA separada 2 vCPU/2 GiB/20 GiB. Placement e identidades reais são privados.
- [ ] Cobrir colisões, digest obsoleto, falha parcial, reexecução, rede e regressões; auditar antes e depois da aplicação.

## Task 3: S2 — Compatibilidade LXC

**Consumes:** substrato auditado e recursos descartáveis marcados como pertencentes ao laboratório.
**Produces:** laudo de compatibilidade e escolha determinística LXC ou VM.

- [ ] Usar lab.ad.test em dois hosts e comprovar security.NTACL, ACL/xattr, SYSVOL, Samba/systemd, relógio, auditoria e replicação.
- [ ] Não conceder CAP_SYS_TIME, capacidades de auditoria do host, modo privilegiado ou AppArmor unconfined para aprovar o teste.
- [ ] Em incompatibilidade, preservar o laudo e adotar VMs automaticamente, conforme autorização. Limpeza alcança somente recursos descartáveis desta etapa.

## Task 4: S3 — PKI

**Consumes:** plataforma aprovada e nomes privados reservados.
**Produces:** raiz offline, intermediária online e automação de certificados com chaves individuais.

- [ ] Custódia da raiz por Vinicius, em diretório local protegido fora do Git, sem cópia da chave em DC/CA online. Guardar passphrase no cofre privado.
- [ ] Criar perfis separados com allowlist exata de SANs para LDAPS dos DCs, HTTPS da CA e telemetria; não compartilhar credencial ampla entre perfis.
- [ ] Emitir certificados de sete dias, com nova chave antes de dois terços da validade; validar cadeia/SAN/EKU/chave antes da troca atômica.
- [ ] Testar rejeição de certificado inválido, atualização efetiva do Samba e alertas de expiração/rotação; documentar limitações de revogação do step-ca.

## Task 5: S4 — DC01 e hardening

**Consumes:** plataforma, PKI e manifesto validados.
**Produces:** floresta institucional nova, host e protocolos endurecidos, com SID registrado no inventário privado.

- [ ] Provisionar somente host vazio, com pacote assinado e stack Samba/LDB/Python coerente. Verificar FFL/DFL 2016 e esquema v88 na versão instalada.
- [ ] Exigir senhas de 14 caracteres, complexidade, histórico 30, idade mínima de um dia, idade máxima zero, armazenamento reversível off e bloqueio 10/15/15.
- [ ] Exigir SMB signing, LDAP signing/channel binding, TLS >=1.2 com identidade validada e DNS updates seguros; recusar SMB1 e NTLMv1. Manter NTLMv2 como piso e AES preferido.
- [ ] Aplicar SSH não-root com chave, journald persistente, auditoria, integridade, atualização controlada e firewall por origem/destino. Adequar tempo ao ambiente sem conceder capacidades do host ao LXC.
- [ ] Testar controles negativos e reexecução; não usar dbcheck --fix nem alterações cegas de esquema.

## Task 6: S5 — DC02 e SYSVOL

**Consumes:** SID/FQDN/saúde de DC01 e credenciais protegidas.
**Produces:** segundo DC da mesma floresta, replicação e SYSVOL monitorados.

- [ ] Juntar DC02 à floresta existente; não provisionar uma segunda floresta. Validar SID, SRV, GC, Kerberos e replicação por ambos os DCs.
- [ ] Definir DC01 como autor de GPO; sincronizar SYSVOL unidirecionalmente com chave restrita, preservação ACL/xattr/SID e verificação de GPT.INI e sysvolcheck.
- [ ] Monitorar defasagem e impedir autoria concorrente. Não afirmar DFS-R nativo.

## Task 7: S6 — Clientes e GPO piloto

**Consumes:** dois DCs íntegros, PKI e templates de clientes.
**Produces:** Windows e Linux piloto ingressados, OUs e políticas verificadas.

- [ ] Usar somente clones novos. Confirmar licença e suporte da versão/edição Windows; o nome do template não comprova suporte.
- [ ] Aplicar baseline Microsoft correspondente ao sistema efetivamente instalado, RSAT e GPOs por OU piloto; distribuir somente a cadeia pública da PKI.
- [ ] Comprovar ingresso, autenticação, gpupdate/gpresult, acesso a SYSVOL e políticas por ambos os DCs.
- [ ] LAPS criptografado, WHfB, AES-only e NTLM totalmente desabilitado ficam condicionados a testes P1 próprios.

## Task 8: S7 — Observabilidade

**Consumes:** serviços e coletor existente, com perfis restritos da PKI.
**Produces:** logs, métricas e alertas de AD sem afetar projetos vizinhos.

- [ ] Coletar JSON auth/dsdb, Linux/SSH/auditoria, PKI e Windows piloto com transporte autenticado, filas locais e escopo exclusivo do AD.
- [ ] Demonstrar alertas de grupos privilegiados, políticas, SYSVOL, replicação, validade/rotação de certificados e falhas de coleta/timers de certificados.
- [ ] Não alterar retenção global de outros projetos nem enviar mensagens externas. Verificar perda e retomada do coletor.

## Task 9: S8 — Produção e aceite

**Consumes:** código/inventário auditados, checks e controles pré-produção aprovados.
**Produces:** serviço em produção para o piloto, relatório de prontidão e runbooks.

- [ ] Realizar auditorias novas de segurança, especificação e estado observado, vinculadas a SHAs, pacotes e evidências.
- [ ] Corrigir falhas críticas/altas dos controles da entrega vigente.
- [ ] Validar saúde de ambos os DCs, DNS/Kerberos/LDAP/SMB, GPO, certificados e alertas.
- [ ] Declarar prontidão de produção conforme o aceite do usuário. A migração municipal contará com uma etapa própria.

## Trabalho futuro separado após produção

Backup e exercícios de recuperação/DR serão tratados em trabalho futuro separado, após a aplicação em produção, fora desta entrega e sem requisito, validação ou gate para homologação ou aceite de produção. Recursos existentes de terceiros permanecem preservados.

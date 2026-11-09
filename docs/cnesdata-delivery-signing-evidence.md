# EXT2 — assinatura e evidência de delivery

Contrato ratificado: infra-ansible#29/6727502727, v6 amendment SHA256
`962d8ec55c36865ad4ecebe35ecfb0d0f5b3059e2876f37d57ba05098342230e` e scope
`e4295a9088b96236c72645efd375c46f5c6c6aa8397e2f112207c22e7d54b566`.
Autoria Code sobre EXT1 integrado `99fc0e4805b96fbca7df06440d5ea3ad42e53369`,
liberada no comentário #29/6728085802. Código/testes não são Ready ou aceite AWS.

## Evidência S3

`tools/cnesdata_delivery/evidence.py` usa bucket geral externo, já versionado e com
Object Lock; não cria/adota bucket, configuração, policy ou state externo. Somente
as três keys current do handoff governado recebem single `put_object`, em bytes,
IfNoneMatch, checksum SHA256, cifra com CMK full ARN e BucketKeyEnabled=False.
COMPLIANCE e retain_until absoluto vêm do owner, sem novo TTL ou retenção arbitrária.

Antes da escrita e depois do readback, consulta versioning, lock e encryption; o
default precisa devolver boolean false presente. Head/Get/Retention usam a VersionId
retornada pelo Put, nunca latest. Head exige false presente, checksum/length/cifra
exatos; Get confirma os bytes e retention confirma mode/date absolutos. ETag não é
hash. Timeout/409/412 não repete escrita: recovery_required até referência original
autenticada permitir somente releitura. SDK mutante deve ter total_max_attempts=1.

Read histórico só admite referências completas do catálogo autorizado e não grava.
Q1 corrigido: no bucket geral versionado contratado, checksum de Head SSE-KMS usa
Decrypt; GenerateDataKey é necessário ao upload atual, não é acrescentado à sessão
histórica por generalização de directory buckets. `s3:GetObjectVersion` é permissão
IAM, `head_object/get_object(VersionId=...)` são APIs; não existe `s3:HeadObject`.

## Carrier e procedência

`ext2_transport.py` confere API de attempt, source SHA/caller/reusable distintos,
closure pinada de fontes e checks; jobs paginados da tentativa exata e step log
do publisher completo. Nomes apenas selecionam dentro da fonte auditada: duplicidade,
step errado, produtor incompleto, script/source divergente e ausência de logs recusam.
O artifact REST não fornece run_attempt; nenhum campo inventado o substitui.

O ZIP público tem só receipt-ref.json com VersionId/hash/tamanho do receipt privado.
Recomputar hashes distintos de ZIP, member e receipt, sem self-hash. Nunca publicar
bucket/key/receipt/payload/tokens/URLs no artifact ou log. Cada objeto privado S3
permanece sujeito ao mesmo readback estrito. Artifact/log têm retenção independente
de COMPLIANCE S3: ausência/expiração recusa, sem export local como prova.

GET autenticado usa API GitHub versão 2026-03-10, timeout20s, JSON8MiB, jobs256/4páginas,
step log64KiB, ZIP1MiB, member4KiB. Download permite um redirect HTTPS somente em
hosts oficiais; bearer fica só em api.github.com e URL assinada nunca é registrada.
Run corrente pode estar in_progress após publisher success; histórico exige tentativa
original completed/success e aceitação no catálogo retido. Nenhuma dessas provas é
fornecida por channel/issuer JSON/result=success ou artifact name.

## Assinatura, reusable e consumer privado

O reusable próprio tem somente workflow_call: `validate-no-creds` autentica source/
request/closure sem id-token; `sign-store-publish` assume a única role própria,
valida Phase A e produz uma Sign DIGEST/ECDSA_SHA_256; `verify-handoff` sucede o
publisher completo e assume a mesma role com sessão somente leitura. Histórico
pula o job Sign e consome publisher original completed/success. Não há caller novo.

Usa `CNESDATA_DELIVERY_GOVERNANCE` já existente, em subobjeto privado `ext2`, sem novo
segredo ou campo v2. O owner fornece authority #29/6727502727, activation_enabled,
storage, provenance, authorization, signing, crypto, consumer, session_duration_seconds
e history. Ausência, shape errado ou fonte/SDK/tool fingerprint divergente fecha.
`invocation` vem do contexto GitHub autenticado, não do descriptor. A autorização
protegida fixa run/attempt/source/release/candidate e deadline absoluto do owner;
rerun/ambiguidade exigem recovery revisado, nunca re-sign automático. O marcador
in-process de mutação não é um lock distribuído: a closure auditada do caller deve
ter uma única invocação de assinatura, sem fan-out/matrix. Não há nova lease/grant.

Inputs privados do reusable: request_descriptor canônico, seu SHA256, expected_source_sha
e mode activation/historical. Descriptor fechado: request_version=1, mode, source_sha,
inputs e ext2_post_upload_receipt_v1. Em activation, inputs contém candidate_reference,
phase_a_reference e retained_unit_task_definition_arns; refs são do contrato existente
repo/run/attempt/artifact/digest/workflow/source. Em histórico, inputs=null e o locator
precisa de entrada exata no catálogo retido protegido. Nenhum campo seleciona script,
role, policy, backend, SDK endpoint, retenção ou source mutável. Descriptor é metadata
pública e nunca deve conter credenciais, URL assinada ou corpo privado.

O gate não publica um schema concorrente de activation. Antes de emitir credenciais,
obtém por API/SHA/digest os arquivos aprovados de #470: activation.schema.json,
verify_activation.py e build_activation.py. O adapter privado tem admit_ext2(payload,
request=..., github=..., governance=..., now=..., historical=...) no verifier;
prepare_ext2(request, ...) e render_ext2(VerifiedActivation, ...) no builder. admit_ext2
valida schema/procedência/Phase A/freshness originais e retorna bytes originais de
candidate/Phase A e activation_fields normalizados. O gate recompõe os digests,
release/source/canary/ECR/revisões, verifica key usage/policy/SPKI reais e só então Sign.
Esse ABI privado deve ser alinhado ao consumer integrado antes de Ready; fixtures
offline não o tornam existente. Nenhum arquivo CnesData é implementado por EXT2.

KMS Sign e Put SDK usam total_max_attempts=1, sem credencial ambiente ou endpoint de
caller. A sessão cabe em2048 ou recusa sem widening; histórico tem Decrypt, nunca
GenerateDataKey/Sign/Put. O prazo é rechecado com relógio atual antes das mutações.
OpenSSL pinado pelo owner verifica prehash de SHA256 independentemente de KMS;
fixtures geram chave efêmera só no diretório temporário de teste. O binário/fingerprint
e suas dependências reais são facts de toolchain/Ready, sem promessa de configuração live.

O renderer roda depois de verificar toda a cadeia e recebe VerifiedActivation com
bytes/refs originais. Só produz as quatro variáveis aprovadas, em arquivo temporário
privado do job. Wiring real e saída consumível por promoção/rollback são do owner
antes de Ready; locator sozinho não significa que outro job leu bytes privados.

Fontes: [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html),
[override de Bucket Keys por objeto](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-bucket-key-object.html),
[retries do SDK](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html).

Sem operação AWS/host/DNS/CA/apply em desenvolvimento; operações reais permanecem
manuais e exigem owner handoff, readbacks, IAM/freeze, custos USD8 produto/USD15
agregado, paid Actions USD0, EXT5/EXT6 e smoke. Preservar Actions personal e
Deploy develop desabilitados. Código não fecha #29 enquanto Produção estiver pendente.

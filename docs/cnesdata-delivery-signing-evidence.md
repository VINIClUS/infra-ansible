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

Fontes: [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html),
[override de Bucket Keys por objeto](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-bucket-key-object.html),
[retries do SDK](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html).

Sem operação AWS/host/DNS/CA/apply em desenvolvimento; operações reais permanecem
manuais e exigem owner handoff, readbacks, IAM/freeze, custos USD8 produto/USD15
agregado, paid Actions USD0, EXT5/EXT6 e smoke. Preservar Actions personal e
Deploy develop desabilitados. Código não fecha #29 enquanto Produção estiver pendente.

# Pré-requisitos externos da delivery CnesData (EXT-1 provider OIDC, EXT-2 evidência)

Raiz `opentofu/cnesdata-delivery-prerequisites/`, state exclusivo
`shared/cnesdata-delivery-prerequisites/prod/opentofu.tfstate`. Produz os dois recursos
que `opentofu/cnesdata-delivery/` consome como externos. Este código não executa
plan/apply, não altera os 22 recursos do foundation nem a raiz delivery. Código verde não
é Ready nem aceite AWS.

## Ownership

| Recurso | Produtor | Consumidor |
|---|---|---|
| Provider OIDC `token.actions.githubusercontent.com` (audience `sts.amazonaws.com`) | esta raiz (`github_oidc_enabled`) | `github_delivery.provider_*` (EXT-1), por ARN via data source |
| CMK de cifra de evidência dedicada | esta raiz (`evidence_enabled`) | `kms_key_arn` v2, `github_delivery.evidence_kms_arn`, `ext2.cipher_kms_key_arn` |
| Bucket de evidência (Object Lock, versionado) | esta raiz (`evidence_enabled`) | `storage.evidence_bucket_{name,arn}`, `ext2.bucket_arn` |

Por que não outro lugar:

- Raiz delivery: `evidence.tf` declara que ela não possui bucket/CMK, e o EXT-2 nunca adota
  o bucket. O provider é `data` com precondition "never create another provider".
- Foundation: os testes fixam exatamente 22 recursos gerenciados e o executor/boundary só
  enxerga as chaves de backend de `foundation` e `budget-backend`. Novo recurso ou chave
  exige mudar recursos aplicados.
- `personal-infra-live`: o amendment limita o escopo a backend e Budget/freeze.

Nenhum outro root declara `resource "aws_iam_openid_connect_provider"`; este é o único.

## Contrato do bucket

- Object Lock habilitado na criação, versionamento `Enabled`, `force_destroy=false`.
- Sem retenção padrão: o modo COMPLIANCE e o `retain_until` absoluto são aplicados por
  objeto pelo gate EXT-2 com valor do dono (sem novo TTL). Uma retenção padrão seria
  irreversível e arbitrária.
- SSE-KMS com a CMK dedicada, `BucketKeyEnabled=false` (o gate exige readback `false` e
  as policies usam `kms:EncryptionContext:aws:s3:arn` de objeto).
- Public Access Block completo, `BucketOwnerEnforced`, policy que nega `s3:*` sem TLS.
- Lifecycle só aborta multipart incompleto (7 dias). Não expira versões: leituras
  históricas usam VersionId exato e Object Lock impediria a remoção de qualquer forma.
- CMK `SYMMETRIC_DEFAULT`, rotação ativa, policy de delegação à conta como no foundation.
  A chave de assinatura `kms:Sign` continua separada, em `cnesdata-delivery`.

## Gates

Ambos `false` por padrão: com os defaults o plano tem 0 recursos e outputs `null`.

## BOM esperado

| Entrada | Plano |
|---|---|
| defaults | 0 a adicionar, 0 a mudar, 0 a destruir |
| `github_oidc_enabled=true` | +1 (`aws_iam_openid_connect_provider.github[0]`) |
| `evidence_enabled=true` | +9 (CMK, alias, bucket, versioning, PAB, ownership, SSE, policy, lifecycle) |
| ambos | +10 / 0 / 0 |

## Outputs

- `github_oidc_provider`: `arn`, `url`, `client_id_list`, `thumbprint_list` (fixo e validado, default os thumbprints publicados pelo GitHub em https://github.blog/changelog/2023-06-27-github-actions-update-on-oidc-integration-with-aws/;
  alimenta `github_delivery.provider_thumbprints`; exige 40 hex no root delivery).
- `evidence_storage`: `evidence_bucket_name`, `evidence_bucket_arn`, `kms_key_arn`. Fragmento,
  não é `shared_outputs` v2 completo.

## Testes

```sh
PATH=~/.local/opt/tofu-1.13.2:$PATH \
CNESDATA_TEST_AWS_PROVIDER_DIR=<cache do provider aws 6.54.0> \
python3 -m pytest -q tests/test_cnesdata_delivery_prerequisites.py
```

Planos nativos com mock provider, sem credenciais, backend ou rede.

# Deploying to AWS or GCP

Both clouds follow the same four steps. Only the Terraform module, the registry and the
workload-identity annotation differ. No cloud credential is stored anywhere (ADR 0013).

## 1. Provision with Terraform

| | AWS | GCP |
|---|---|---|
| Module | `deploy/terraform/modules/eks` | `deploy/terraform/modules/gke` |
| Example | `deploy/terraform/examples/eks` | `deploy/terraform/examples/gke` |
| Existing prerequisites | EKS cluster with the `eks-pod-identity-agent` add-on, VPC, two private DB subnets, a client security group | GKE cluster with Workload Identity, VPC with private services access |
| Registry | ECR, one immutable-tag repository per image (`repositories`) | one Artifact Registry Docker repository, immutable tags |
| Database | RDS Postgres, encrypted, private, master password in Secrets Manager | Cloud SQL Postgres, private IP, IAM database login |
| Per-runtime identity | IAM role bound to a ServiceAccount by EKS Pod Identity | Google service account bound by Workload Identity |
| Model access | `bedrock:InvokeModel*` on exact model ARNs (`bedrock_model_arns`, no wildcards) | `roles/aiplatform.user` (`vertex = true`) |
| Secrets | Secrets Manager entries named `<name>/<runtime>/<secret>` (`secret_names`) | Secret Manager entries `<name>--<runtime>--<secret>` |

Declare one entry in `runtimes` per service (`ai-gateway`, `context-data`, and so on) with
its namespace. Run `terraform apply` from a copy of the example. Terraform creates the
secrets empty; put their values in with the cloud's CLI.

## 2. Build and push images

Build each service from the repo root with podman, for example
`podman build -f services/ai/gateway/Dockerfile -t <registry>/ai-gateway:<version> .`, then push.
Tags are immutable, so push each version once.

## 3. Install each service with the shared chart

`deploy/charts/bae6-service` deploys every runtime. Per service, supply:

- `image.repository` and `image.digest` (`sha256:...`). Tags are refused unless `allowTag` is
  set, which is for development clusters only.
- `serviceAccount.annotations` from step 1:
  - AWS with Pod Identity needs no annotation.
  - AWS with IRSA: `eks.amazonaws.com/role-arn: <runtime_role_arns output>`.
  - GCP: `iam.gke.io/gcp-service-account: <name>-<runtime>@<project>.iam.gserviceaccount.com`.
- `env` for plain settings and `envFromSecrets` for secrets such as the database URL.
  Sync cloud secrets into Kubernetes Secrets with External Secrets Operator or the CSI
  driver (`docs/platform/secrets-and-identity.md`).
- For `ai-gateway`: the model catalog, price book and budgets as `BAE6_AI_CONFIG`, kept in Git.
  List Bedrock model ids or Vertex projects and regions there, matching the ARNs or roles
  from step 1.

```
helm upgrade --install ai-gateway deploy/charts/bae6-service -n bae6 -f ai-gateway.values.yaml
```

## 4. Verify

- `kubectl -n bae6 get pods` shows every runtime ready (probes are `/health/live` and `/health/ready`).
- Call the gateway with a token for its audience. A refusal naming credentials means the
  identity binding from step 1 does not match the ServiceAccount's name and namespace.

## What differs by cloud at runtime

- AWS credentials come from EKS Pod Identity. Static `AWS_ACCESS_KEY_ID` keys work only
  under `NODE_ENV=development`.
- Vertex tokens come from the GKE metadata server.
- Hugging Face tokens are the one stored provider credential, held in a Kubernetes Secret
  (ADR 0015).
- Never ship `deploy/dev/*` (mock-oidc and the other mocks) or `allowTag` values to a real cluster.

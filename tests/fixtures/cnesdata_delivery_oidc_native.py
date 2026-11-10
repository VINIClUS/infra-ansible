"""Reuse isolated exact-root harness, augment only synthetic provider responses."""
import json
import shutil
import subprocess
from fixtures.cnesdata_delivery_roles_anywhere.native import Native as Base, ROOT


class Native(Base):
    def run(self, directory, *args):
        if args[0] == "test":
            path = directory / "contract.tftest.hcl"
            text = path.read_text().replace('mock_data "aws_caller_identity"', '''mock_data "aws_iam_openid_connect_provider" {
    defaults = {
      url = "token.actions.githubusercontent.com"
      client_id_list = ["sts.amazonaws.com"]
      thumbprint_list = ["0000000000000000000000000000000000000000"]
    }
  }
  mock_data "aws_caller_identity"''')
            for role in ("plan", "deploy"):
                text += f'''
override_resource {{
  target = aws_iam_role.delivery["{role}"]
  values = {{
    arn = "arn:aws:iam::111122223333:role/cnesdata-test-{role}"
    id = "cnesdata-test-{role}"
  }}
}}
'''
            if json.loads((directory / "inputs.tfvars.json").read_text()).get("application_promotion") is not None:
                text += '''
override_resource {
  target = aws_iam_role.application[0]
  values = {
    arn = "arn:aws:iam::111122223333:role/cnesdata-prod-application"
    id = "cnesdata-prod-application"
  }
}
'''
            path.write_text(text)
        return super().run(directory, *args)


    def schema(self):
        """Pinned provider GetSchema in a backend-free, network-isolated root."""
        directory = self.base / "readonly-schema"
        directory.mkdir()
        (directory / "main.tf").write_text('terraform {\n required_providers {\n aws = { source = "hashicorp/aws", version = "6.54.0" }\n }\n}\n')
        shutil.copy2(ROOT / ".terraform.lock.hcl", directory / ".terraform.lock.hcl")
        initialized = self.run(directory, "init", "-backend=false", "-input=false", "-lockfile=readonly")
        assert initialized.returncode == 0, initialized.stdout + initialized.stderr
        response = subprocess.run([self.rtk, "proxy", self.unshare, "--user", "--map-root-user", "--net",
                                   self.tofu, "providers", "schema", "-json"], cwd=directory, env=self.env,
                                  capture_output=True, text=True, timeout=60, check=False)
        assert response.returncode == 0, response.stdout + response.stderr
        return json.loads(response.stdout)["provider_schemas"]["registry.opentofu.org/hashicorp/aws"]["resource_schemas"]

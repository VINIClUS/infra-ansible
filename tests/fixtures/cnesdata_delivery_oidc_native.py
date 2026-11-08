"""Reuse isolated exact-root harness, augment only synthetic provider responses."""
from fixtures.cnesdata_delivery_roles_anywhere.native import Native as Base


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
            path.write_text(text)
        return super().run(directory, *args)

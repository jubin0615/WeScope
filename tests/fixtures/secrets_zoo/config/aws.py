import os

# expect: secret-hardcoded
AWS_ACCESS_KEY_ID = "{{FAKE:aws}}"
AWS_REGION = os.environ.get("AWS_REGION", "ap-northeast-2")

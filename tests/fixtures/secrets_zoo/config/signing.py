# 개인키 본문이 결과·ChatGPT 전송 내용에 원문으로 남지 않아야 한다 (한 줄 문자열과 여러 줄 PEM)

# expect: secret-hardcoded
INLINE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n{{FAKE:pem1}}\n{{FAKE:pem2}}\n-----END RSA PRIVATE KEY-----"

# expect: secret-hardcoded
BLOCK_KEY = """-----BEGIN PRIVATE KEY-----
{{FAKE:pem3}}
{{FAKE:pem4}}
-----END PRIVATE KEY-----"""

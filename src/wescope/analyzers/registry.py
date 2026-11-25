"""등록 순서 = 실행 순서. secrets가 맨 앞: SecretRegistry를 채워 이후 마스킹 기준이 된다."""
from wescope.analyzers.config import ConfigAnalyzer
from wescope.analyzers.insecure_defaults import InsecureDefaultsAnalyzer
from wescope.analyzers.routes import RoutesAnalyzer
from wescope.analyzers.secrets import SecretsAnalyzer
from wescope.analyzers.semgrep import SemgrepAnalyzer


def analyzers():
    return [SecretsAnalyzer(), SemgrepAnalyzer(), RoutesAnalyzer(), ConfigAnalyzer(), InsecureDefaultsAnalyzer()]

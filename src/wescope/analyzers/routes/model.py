from dataclasses import dataclass


@dataclass
class Route:
    methods: list[str]
    path: str
    file: str
    line: int                 # 라우트를 등록한 줄 (데코레이터·app.get)
    span: tuple[int, int]     # 핸들러 함수 범위 (체인 상관에 사용)
    function: str
    guards: str               # 데코레이터·미들웨어·의존성·전역 가드 원문 (가드 단서 검색용)
    body: str                 # 핸들러 원문 (핸들러가 다른 곳에 정의되면 빈 문자열)
    evidence: str

    @property
    def label(self) -> str:
        return f"{'/'.join(self.methods)} {self.path}"

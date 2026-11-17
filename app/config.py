from dataclasses import dataclass
import os

@dataclass(frozen=True)
class Settings:
    db_path: str = "./data/loghour.db"
    rule_version: str = "2026.11"
    timezone: str = "Asia/Shanghai"
    # 管理密钥用于签发/撤销授权；审计密钥用于读取原始批次与全量导出。
    # 演示环境给出默认值，生产环境必须通过环境变量覆盖。
    admin_key: str = "dev-admin"
    audit_key: str = "dev-audit"
    # 下载凭据有效期上限；实际有效期还会被授权到期时间截短。
    token_ttl_seconds: int = 3600

    @classmethod
    def from_env(cls):
        return cls(db_path=os.getenv("DB_PATH", cls.db_path),
                   rule_version=os.getenv("RULE_VERSION", cls.rule_version),
                   admin_key=os.getenv("ADMIN_KEY", cls.admin_key),
                   audit_key=os.getenv("AUDIT_KEY", cls.audit_key),
                   token_ttl_seconds=int(os.getenv("TOKEN_TTL_SECONDS", cls.token_ttl_seconds)))

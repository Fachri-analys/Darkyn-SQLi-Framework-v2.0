# core/types.py
from enum import Enum

class DarkynError(Exception):
    pass

class InjectionError(DarkynError):
    pass

class ExfilError(DarkynError):
    pass

class AttackMode(Enum):
    STEALTH    = "stealth"
    AGGRESSIVE = "aggressive"
    NORMAL     = "normal"
    BLIND      = "blind"

class DBType(Enum):
    MYSQL      = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL      = "mssql"
    ORACLE     = "oracle"
    SQLITE     = "sqlite"
    UNKNOWN    = "unknown"

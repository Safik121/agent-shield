import functools
import os
import inspect
import json
import sqlite3
import contextvars
import re

# Store original sqlite3.connect
_orig_sqlite3_connect = sqlite3.connect

# Active database restriction context
_db_restricted_context = contextvars.ContextVar("db_restricted_context", default=None)


def _is_write_query(sql) -> bool:
    if isinstance(sql, bytes):
        sql = sql.decode('utf-8', errors='ignore')
    elif not isinstance(sql, str):
        sql = str(sql)
        
    sql_clean = sql.strip().upper()
    # Remove SQL line comments
    sql_clean = re.sub(r'--.*$', '', sql_clean, flags=re.MULTILINE)
    # Remove SQL block comments
    sql_clean = re.sub(r'/\*.*?\*/', '', sql_clean, flags=re.DOTALL)
    
    write_keywords = {"INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "REPLACE", "RENAME", "TRUNCATE"}
    words = re.findall(r'\b[A-Z]+\b', sql_clean)
    for word in words:
        if word in write_keywords:
            return True
    return False


def _report_db_violation_and_raise(sql, info):
    func = info["func"]
    project_root = info["project_root"]
    reports_dir = os.path.join(project_root, "shield_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    try:
        func_file = inspect.getfile(func)
        func_abs_file = os.path.abspath(func_file)
    except Exception:
        func_abs_file = "unknown"
        
    report = {
        "violation_type": "database_violation",
        "function_name": func.__name__,
        "file_path": func_abs_file,
        "details": {
            "attempted_query": str(sql)[:1000],
            "reason": "Write/modification query in read-only sandbox mode."
        },
        "instruction": (
            f"AI Assistant Instruction: The function '{func.__name__}' in file '{func_abs_file}' "
            f"attempted to execute a database modification query: '{str(sql)[:200]}...'. "
            f"Database access is restricted to read-only queries. Please remove database write/alter queries."
        )
    }
    
    report_path = os.path.join(reports_dir, "violation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        
    from agent_shield.contracts import DatabaseViolationError
    raise DatabaseViolationError(f"Database Sandbox: execution of database modification query is forbidden.")


class _WrappedSqliteCursor:
    def __init__(self, orig_cursor, info):
        self._orig_cursor = orig_cursor
        self._info = info
        
    def execute(self, sql, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql):
                _report_db_violation_and_raise(sql, self._info)
        return self._orig_cursor.execute(sql, *args, **kwargs)
        
    def executemany(self, sql, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql):
                _report_db_violation_and_raise(sql, self._info)
        return self._orig_cursor.executemany(sql, *args, **kwargs)
        
    def executescript(self, sql_script, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql_script):
                _report_db_violation_and_raise(sql_script, self._info)
        return self._orig_cursor.executescript(sql_script, *args, **kwargs)
        
    def __getattr__(self, name):
        return getattr(self._orig_cursor, name)
        
    def __iter__(self):
        return iter(self._orig_cursor)


class _WrappedSqliteConnection:
    def __init__(self, orig_conn, info):
        self._orig_conn = orig_conn
        self._info = info
        
    def cursor(self, *args, **kwargs):
        cursor = self._orig_conn.cursor(*args, **kwargs)
        return _WrappedSqliteCursor(cursor, self._info)
        
    def execute(self, sql, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql):
                _report_db_violation_and_raise(sql, self._info)
        return self._orig_conn.execute(sql, *args, **kwargs)
        
    def executemany(self, sql, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql):
                _report_db_violation_and_raise(sql, self._info)
        return self._orig_conn.executemany(sql, *args, **kwargs)
        
    def executescript(self, sql_script, *args, **kwargs):
        if self._info["read_only"]:
            if _is_write_query(sql_script):
                _report_db_violation_and_raise(sql_script, self._info)
        return self._orig_conn.executescript(sql_script, *args, **kwargs)
        
    def __getattr__(self, name):
        return getattr(self._orig_conn, name)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._orig_conn.__exit__(exc_type, exc_val, exc_tb)


def _custom_sqlite3_connect(*args, **kwargs):
    conn = _orig_sqlite3_connect(*args, **kwargs)
    restricted = _db_restricted_context.get()
    if restricted:
        return _WrappedSqliteConnection(conn, restricted)
    return conn


# Hook sqlite3 globally
sqlite3.connect = _custom_sqlite3_connect


def restrict_db(read_only: bool = True):
    """Decorator to restrict database access within the decorated function.
    
    Currently supports sqlite3. If read_only is True, prevents any database
    modifications (INSERT, UPDATE, DELETE, DROP, CREATE, etc.).
    """
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                token = _db_restricted_context.set({
                    "read_only": read_only,
                    "func": func,
                    "project_root": project_root
                })
                try:
                    return await func(*args, **kwargs)
                finally:
                    _db_restricted_context.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(current_dir)
                
                token = _db_restricted_context.set({
                    "read_only": read_only,
                    "func": func,
                    "project_root": project_root
                })
                try:
                    return func(*args, **kwargs)
                finally:
                    _db_restricted_context.reset(token)
            return wrapper
    return decorator

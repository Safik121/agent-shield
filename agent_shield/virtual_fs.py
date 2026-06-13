import functools
import os
import io
import inspect
import builtins
import contextvars

# Original filesystem functions
_orig_open = builtins.open
_orig_exists = os.path.exists
_orig_isdir = os.path.isdir
_orig_isfile = os.path.isfile
_orig_listdir = os.listdir
_orig_remove = os.remove
_orig_unlink = getattr(os, "unlink", None)
_orig_rename = os.rename
_orig_replace = os.replace
_orig_mkdir = os.mkdir
_orig_makedirs = os.makedirs
_orig_rmdir = os.rmdir

# Virtual FS state: contextvar mapping absolute path -> {"type": "file"|"dir"|"deleted", "content": bytes}
_vfs_state = contextvars.ContextVar("vfs_state", default=None)


class VirtualFile:
    def __init__(self, path, mode, vfs_state_dict):
        self.path = path
        self.mode = mode
        self.vfs_state_dict = vfs_state_dict
        
        self.is_write = any(c in mode for c in ('w', 'a', 'x', '+'))
        self.is_binary = 'b' in mode
        
        existing = vfs_state_dict.get(path)
        if existing and existing.get("type") == "file":
            initial_data = existing["content"]
        else:
            initial_data = b""
            
        if 'w' in mode:
            initial_data = b""
            
        self.buffer = io.BytesIO(initial_data)
        if 'a' in mode:
            self.buffer.seek(0, io.SEEK_END)
            
    def read(self, size=-1):
        data = self.buffer.read(size)
        if not self.is_binary:
            return data.decode('utf-8', errors='ignore')
        return data
        
    def write(self, data):
        if not self.is_binary and isinstance(data, str):
            data = data.encode('utf-8')
        res = self.buffer.write(data)
        
        self.vfs_state_dict[self.path] = {
            "type": "file",
            "content": self.buffer.getvalue()
        }
        return len(data)
        
    def seek(self, offset, whence=io.SEEK_SET):
        return self.buffer.seek(offset, whence)
        
    def tell(self):
        return self.buffer.tell()
        
    def close(self):
        self.buffer.close()
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _is_real_read_allowed(path, allowed_list):
    if allowed_list is None:
        return True
    path = os.path.abspath(path)
    for allowed in allowed_list:
        if allowed == "*":
            return True
        allowed_abs = os.path.abspath(os.path.expanduser(allowed))
        if path == allowed_abs or path.startswith(allowed_abs + os.sep):
            return True
    return False


def _virtual_exists(path, state):
    abs_path = os.path.abspath(path)
    entry = state.get(abs_path)
    if entry:
        return entry["type"] != "deleted"
    for k in state:
        if state[k]["type"] != "deleted" and k.startswith(abs_path + os.sep):
            return True
    return False


def _virtual_isdir(path, state):
    abs_path = os.path.abspath(path)
    entry = state.get(abs_path)
    if entry:
        return entry["type"] == "dir"
    for k in state:
        if state[k]["type"] != "deleted" and k.startswith(abs_path + os.sep):
            return True
    return False


def _virtual_isfile(path, state):
    abs_path = os.path.abspath(path)
    entry = state.get(abs_path)
    return entry is not None and entry["type"] == "file"


# Custom hooks
def _custom_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        path = os.path.abspath(str(file))
        is_write = any(c in mode for c in ('w', 'a', 'x', '+'))
        
        # Check if deleted in virtual state
        entry = vfs.get(path)
        if entry and entry["type"] == "deleted" and not is_write:
            raise FileNotFoundError(f"No such file or directory: '{file}'")
            
        if is_write:
            # Create parent directories virtually if needed
            parent = os.path.dirname(path)
            if parent and parent != path:
                if parent not in vfs:
                    vfs[parent] = {"type": "dir"}
            return VirtualFile(path, mode, vfs)
        else:
            if entry and entry["type"] == "file":
                return VirtualFile(path, mode, vfs)
            
            # Fallback to real disk if allowed
            allowed_reads = vfs.get("__allow_real_read__")
            if _is_real_read_allowed(path, allowed_reads):
                try:
                    return _orig_open(file, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline, closefd=closefd, opener=opener)
                except Exception:
                    raise FileNotFoundError(f"No such file or directory: '{file}'")
            else:
                raise FileNotFoundError(f"Virtual FS: Read permission denied for real disk path '{file}'")
                
    return _orig_open(file, mode=mode, buffering=buffering, encoding=encoding, errors=errors, newline=newline, closefd=closefd, opener=opener)


def _custom_exists(path):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        entry = vfs.get(abs_path)
        if entry:
            return entry["type"] != "deleted"
        if _virtual_exists(path, vfs):
            return True
        allowed_reads = vfs.get("__allow_real_read__")
        if _is_real_read_allowed(abs_path, allowed_reads):
            return _orig_exists(path)
        return False
    return _orig_exists(path)


def _custom_isdir(path):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        entry = vfs.get(abs_path)
        if entry:
            return entry["type"] == "dir"
        if _virtual_isdir(path, vfs):
            return True
        allowed_reads = vfs.get("__allow_real_read__")
        if _is_real_read_allowed(abs_path, allowed_reads):
            return _orig_isdir(path)
        return False
    return _orig_isdir(path)


def _custom_isfile(path):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        entry = vfs.get(abs_path)
        if entry:
            return entry["type"] == "file"
        allowed_reads = vfs.get("__allow_real_read__")
        if _is_real_read_allowed(abs_path, allowed_reads):
            return _orig_isfile(path)
        return False
    return _orig_isfile(path)


def _custom_listdir(path='.'):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        entries = set()
        
        # Collect virtual entries
        for k in vfs:
            if k.startswith(abs_path + os.sep):
                rel = k[len(abs_path) + 1:]
                parts = rel.split(os.sep)
                if parts[0] and vfs[k]["type"] != "deleted":
                    entries.add(parts[0])
                    
        # Check deleted real files
        deleted_keys = {k for k in vfs if vfs[k]["type"] == "deleted"}
        
        allowed_reads = vfs.get("__allow_real_read__")
        if _is_real_read_allowed(abs_path, allowed_reads):
            try:
                for entry in _orig_listdir(path):
                    entry_abs = os.path.abspath(os.path.join(abs_path, entry))
                    if entry_abs not in deleted_keys:
                        entries.add(entry)
            except Exception:
                pass
        return list(entries)
    return _orig_listdir(path)


def _custom_remove(path, *, dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        vfs[abs_path] = {"type": "deleted"}
        return
    return _orig_remove(path, dir_fd=dir_fd)


def _custom_unlink(path, *, dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        vfs[abs_path] = {"type": "deleted"}
        return
    if _orig_unlink:
        return _orig_unlink(path, dir_fd=dir_fd)


def _custom_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        src_abs = os.path.abspath(src)
        dst_abs = os.path.abspath(dst)
        entry = vfs.get(src_abs)
        if entry:
            vfs[dst_abs] = entry
            vfs[src_abs] = {"type": "deleted"}
        else:
            # Read from real if allowed, and write virtually to dst
            allowed_reads = vfs.get("__allow_real_read__")
            if _is_real_read_allowed(src_abs, allowed_reads):
                try:
                    with _orig_open(src, "rb") as f:
                        content = f.read()
                    vfs[dst_abs] = {"type": "file", "content": content}
                    vfs[src_abs] = {"type": "deleted"}
                except Exception as e:
                    raise FileNotFoundError(f"Rename failed: {e}")
        return
    return _orig_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


def _custom_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        return _custom_rename(src, dst)
    return _orig_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


def _custom_mkdir(path, mode=0o777, *, dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        vfs[abs_path] = {"type": "dir"}
        return
    return _orig_mkdir(path, mode=mode, dir_fd=dir_fd)


def _custom_makedirs(name, mode=0o777, exist_ok=False):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(name)
        vfs[abs_path] = {"type": "dir"}
        return
    return _orig_makedirs(name, mode=mode, exist_ok=exist_ok)


def _custom_rmdir(path, *, dir_fd=None):
    vfs = _vfs_state.get()
    if vfs is not None:
        abs_path = os.path.abspath(path)
        vfs[abs_path] = {"type": "deleted"}
        return
    return _orig_rmdir(path, dir_fd=dir_fd)


# Apply global monkeypatches
builtins.open = _custom_open
os.path.exists = _custom_exists
os.path.isdir = _custom_isdir
os.path.isfile = _custom_isfile
os.listdir = _custom_listdir
os.remove = _custom_remove
if _orig_unlink:
    os.unlink = _custom_unlink
os.rename = _custom_rename
os.replace = _custom_replace
os.mkdir = _custom_mkdir
os.makedirs = _custom_makedirs
os.rmdir = _custom_rmdir


def virtual_fs(in_memory_write: bool = True, allow_real_read: list[str] = None):
    """Decorator to redirect all filesystem writes to an in-memory virtual storage.
    
    If in_memory_write is True, any file creations or modifications are stored in RAM.
    If allow_real_read is provided, reading files not present in the virtual FS is allowed
    from these paths. If None, reading from the entire disk is allowed.
    """
    def decorator(func):
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                token = _vfs_state.set({
                    "__allow_real_read__": allow_real_read
                })
                try:
                    return await func(*args, **kwargs)
                finally:
                    _vfs_state.reset(token)
            return wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                token = _vfs_state.set({
                    "__allow_real_read__": allow_real_read
                })
                try:
                    return func(*args, **kwargs)
                finally:
                    _vfs_state.reset(token)
            return wrapper
    return decorator

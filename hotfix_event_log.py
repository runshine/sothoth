import pathlib, py_compile

p = pathlib.Path('/app/app/service/event_log.py')
c = p.read_text(encoding='utf-8')

if 'tmp.replace' not in c:
    print('already patched (no tmp.replace found)')
    exit(0)

start_idx = c.find('\ndef write_final(')
if start_idx == -1:
    print('write_final not found!'); exit(1)

end_search = c.find('\ndef ', start_idx + 10)
if end_search == -1:
    end_search = len(c)

new_func = '''
def write_final(path, all_events) -> bool:
    """Append __final__ marker only; events already written by append_events."""
    if path is None:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write('{"__final__":true}' + "\\n")
        return True
    except Exception as exc:
        logger.warning("write_final failed path=%s: %s", path, exc)
        return False
'''

c2 = c[:start_idx] + new_func + c[end_search:]
p.write_text(c2, encoding='utf-8')
py_compile.compile(str(p), doraise=True)
print('PATCHED write_final OK')

# test/test_utils.py
import time
import tracemalloc
from typing import Callable, Any, List, Tuple


def _time_call(fn: Callable, *args, **kwargs) -> Tuple[Any, float]:
    """Měří čas provádění funkce v milisekundách."""
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return result, elapsed_ms


def _memory_call(fn: Callable, *args, **kwargs) -> Tuple[Any, float]:
    """Měří špičkovou alokaci paměti během volání funkce v KiB."""
    tracemalloc.clear_traces()
    result = fn(*args, **kwargs)
    # Získáme (current, peak) paměť alokovanou Pythonem během trasování
    _, peak_mem_bytes = tracemalloc.get_traced_memory()
    peak_mem_kib = peak_mem_bytes / 1024.0
    return result, peak_mem_kib


def _stats(values: List[float]) -> Tuple[float, float, float]:
    """Vrátí (min, avg, max) ze seznamu hodnot."""
    n = len(values)
    if n == 0:
        return (0.0, 0.0, 0.0)
    return (min(values), sum(values) / n, max(values))


def _print_table(rows: List[Tuple[str, ...]], headers: Tuple[str, ...]):
    """Vytiskne pěknou tabulku s výsledky."""
    data = [headers] + rows
    col_w = [max(len(str(row[i])) for row in data) for i in range(len(headers))]

    def fmt_row(r):
        return " | ".join(str(r[i]).ljust(col_w[i]) for i in range(len(headers)))

    sep = "-+-".join("-" * w for w in col_w)
    print(fmt_row(headers))
    print(sep)
    for r in rows:
        print(fmt_row(r))
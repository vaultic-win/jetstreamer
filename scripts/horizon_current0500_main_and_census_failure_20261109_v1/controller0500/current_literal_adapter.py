import ast
SAMPLE_UTC='2026-11-09T05:00:22Z'
SAMPLE_UNIX=1794200422
def literal(v):return v
def adapt(s):ast.parse(s);return s

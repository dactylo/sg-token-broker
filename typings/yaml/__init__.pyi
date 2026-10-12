# Minimal PyYAML interface used by `sg_token_broker`; `types-PyYAML` is not in
# the locked development environment. Only the supported symbols below are declared.

# Position in a YAML stream; `line` and `column` count from zero.
class Mark:
    line: int
    column: int

# Error raised while parsing YAML.
class YAMLError(Exception): ...

# YAML error that records where in the stream parsing failed.
class MarkedYAMLError(YAMLError):
    context: str | None
    context_mark: Mark | None
    problem: str | None
    problem_mark: Mark | None

# Parse one YAML document from text or bytes.
#
# Args:
#     stream: YAML content to parse.
#
# Returns:
#     The parsed Python object.
#
# Raises:
#     YAMLError: If `stream` is not valid YAML.
def safe_load(stream: str | bytes) -> object: ...

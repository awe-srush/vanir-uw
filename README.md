# Vanir Python Language Support via tree-sitter

This document describes the design, implementation, and testing of Python language
support added to Vanir using the tree-sitter parsing library.

---

## Table of Contents

1. [Background](#background)
2. [Architecture Overview](#architecture-overview)
3. [Parsing Flow](#parsing-flow)
4. [tree_sitter_base.py](#tree_sitter_basepy)
5. [python_parser.py](#python_parserpy)
6. [Python-specific Handling](#python-specific-handling)
7. [language_parsers.py Fix](#language_parserspy-fix)
8. [Build Changes](#build-changes)
9. [Python 3.9 Guard](#python-39-guard)
10. [Testing Across Python Versions](#testing-across-python-versions)
11. [End-to-End Validation](#end-to-end-validation)

---

## Background

Vanir is a static analysis tool for detecting missing security patches. It supports
C/C++ and Java using ANTLR4-based parsers. This change adds Python support using
**tree-sitter**, a modern parser library where language support ships as pip packages,
requiring no grammar files or build-time code generation.

### ANTLR vs tree-sitter

| | ANTLR (C/C++, Java) | tree-sitter (Python) |
|---|---|---|
| Grammar | Hand-written `.g4` file | Pre-built pip package |
| Build step | Yes (Bazel + Java) | No |
| Runs in | Python | C (via Python bindings) |
| Add new language | Write full grammar | `pip install tree-sitter-X` |
| Output to Vanir | FunctionChunk + LineChunk | Same |

Both parsers feed the same Vanir pipeline. The normalizer, hasher, and detector are
unchanged.

### What tree-sitter gives you

tree-sitter produces a **CST (Concrete Syntax Tree)**, a structured representation
of every token in the source file including punctuation, keywords, and whitespace
tokens. For Vanir's purposes this is equivalent to an AST since we filter out noise
via `SKIP_TOKEN_TYPES` and retain only meaningful code tokens.

---

## Architecture Overview

### Old inheritance chain
```
AbstractLanguageParser (ABC)
    ├── CppParser
    └── JavaParser
```

### New inheritance chain
```
AbstractLanguageParser (ABC)
    ├── CppParser
    ├── JavaParser
    └── TreeSitterParserBase (ABC -- new middle layer)
            └── PythonParser
            └── GoParser (future)
            └── RustParser (future)
```

`TreeSitterParserBase` is an abstract middle layer that implements the full
`get_chunks()` pipeline once for all tree-sitter parsers. Concrete parsers like
`PythonParser` only implement the three language-specific methods.

---

## Parsing Flow

When Vanir scans a `.py` file, the following sequence is executed:

```
parse_file("attachments.py")          [language_parsers.py]
        |
        v
get_parser_class("attachments.py")
  sees .py extension, finds PythonParser
        |
        v
PythonParser("attachments.py")        [tree_sitter_base.py __init__]
  reads file bytes
  Parser(PY_LANGUAGE).parse(bytes)
  tree-sitter builds CST in memory
        |
        v
get_chunks()                          [tree_sitter_base.py]
  1. QueryCursor(FUNC_QUERY).matches(root)
     finds all function_definition nodes
  2. For each function:
     _extract_param_names()           [python_parser.py]
     _extract_annotations()           [python_parser.py]
     _collect_locals_calls()          [python_parser.py]
     _flat_tokens_cursor()            [tree_sitter_base.py]
     assembles FunctionChunkBase
  3. _collect_tokens_cursor(root)
     builds {line: tokens} for whole file -> LineChunkBase
  4. _collect_errors_cursor(root)
     collects ERROR nodes -> parse errors
        |
        v
ParseResults(function_chunks, line_chunk, parse_errors)
        |
        v
parser.py wraps chunks:
  signature.create_function_chunk() -> FunctionChunk
  signature.create_line_chunk()     -> LineChunk
        |
        v
normalizer.py
  replaces variable names with VAR_0, VAR_1
  replaces function names with FN_0, FN_1
        |
        v
hasher.py
  MurmurHash3 on normalized tokens -> 128-bit hash per chunk
        |
        v
Hash stored (sign generation) or compared (detection)
```

---

## tree_sitter_base.py

**Location:** `vanir/language_parsers/tree_sitter_base.py`

This is the core new file. It contains three module-level cursor utility functions
and the `TreeSitterParserBase` class.

### Module-level utility functions

#### `_collect_tokens_cursor(node, skip_types, string_type, out_dict)`

Iterative TreeCursor walk that collects all meaningful tokens from a node's subtree,
grouped by line number. At each node it makes one of three decisions:

- **Skip** -- node type is in `skip_types` (comments, whitespace, etc.) and prune entire subtree
- **Emit** -- node is a string literal or leaf (no children), record `node.text` under its line number
- **Descend** -- node is a container, go into its children

Navigation uses tree-sitter's C-level `TreeCursor`:
- `cursor.goto_first_child()` -- go down
- `cursor.goto_next_sibling()` -- go right
- `cursor.goto_parent()` -- go up

Result: `{line_number: [token, token, ...]}` for the whole file. Used for the
**line chunk**.

#### `_flat_tokens_cursor(node, skip_types, string_type)`

Thin wrapper around `_collect_tokens_cursor`. Returns a flat ordered list of tokens
sorted by line number. Used for **function chunk tokens**.

#### `_collect_errors_cursor(root)`

Walks the entire tree looking for `ERROR` nodes, places where tree-sitter could not
parse the syntax. Unlike `_collect_tokens_cursor`, this never prunes -- it descends
into ERROR nodes too, because errors may be nested inside partially parsed subtrees.

Returns a list of `common.ParseError` with line number, column, and the bad token
text. Vanir logs these as warnings but continues parsing the rest of the file.

### `TreeSitterParserBase` class

Implements the full `get_chunks()` pipeline. Subclasses set four class-level
attributes:

| Attribute | Purpose | Python example |
|-----------|---------|----------------|
| `LANGUAGE` | tree-sitter Language object | `_Language(_tspython.language())` |
| `_FUNC_QUERY` | compiled query for function discovery | matches `function_definition` |
| `SKIP_TOKEN_TYPES` | node types to prune | `{'comment', 'newline', 'indent', ...}` |
| `STRING_NODE_TYPE` | node type for string literals | `'string'` |

**`__init__(filename)`** reads the file and builds the syntax tree. `Parser` is
imported lazily inside the method (not at module level) so the base class file can
be safely imported on Python 3.9 where tree-sitter is not installed.

**`get_chunks(affected_line_ranges_for_functions)`** is the main pipeline:

1. Run `_FUNC_QUERY` to get all function nodes
2. Filter to functions overlapping the requested line ranges
3. For each function: extract name, parameters, annotations, locals, calls, tokens
4. Build full-file token map for the line chunk
5. Collect parse errors
6. Return `ParseResults`

Three steps in (3) are delegated to abstract methods that subclasses must implement.

### Three abstract methods

```python
@abc.abstractmethod
def _extract_param_names(self, params_node) -> list: ...

@abc.abstractmethod
def _extract_annotations(self, func_node) -> tuple: ...

@abc.abstractmethod
def _collect_locals_calls(self, body_node, nested_ranges) -> tuple: ...
```

These are left abstract because parameter syntax, type annotation syntax, and
variable assignment syntax are all language-specific.

---

## python_parser.py

**Location:** `vanir/language_parsers/python/python_parser.py`

Thin subclass of `TreeSitterParserBase`. Compiles two queries at module import time
and implements the three abstract methods.

### Module-level setup

```python
try:
    import tree_sitter_python as _tspython
    from tree_sitter import Language as _Language
    from tree_sitter import QueryCursor as _QueryCursor
    _PY_LANGUAGE = _Language(_tspython.language())
    _FUNC_QUERY = _PY_LANGUAGE.query("""
        (function_definition
            name: (identifier) @func.name
            body: (block) @func.body) @func.def
    """)
    _LOCALS_QUERY = _PY_LANGUAGE.query("""
        (assignment left: (_) @assign.lhs)
        (augmented_assignment left: (identifier) @aug.lhs)
        (for_statement left: (_) @for.lhs)
        (named_expression name: (identifier) @walrus.name)
        (call function: (identifier) @call.name)
    """)
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _PY_LANGUAGE = None
    _FUNC_QUERY = None
    _LOCALS_QUERY = None
    _TREE_SITTER_AVAILABLE = False
```

Both queries are compiled once at import time, never per file. If tree-sitter is
not installed (Python 3.9), `_TREE_SITTER_AVAILABLE` is set to `False` and all
objects remain `None`.

### `_FUNC_QUERY` -- function discovery

S-expression pattern that matches every `function_definition` node in a Python file:
```
(function_definition
    name: (identifier) @func.name
    body: (block) @func.body) @func.def
```
Capture labels `@func.def`, `@func.name`, `@func.body` allow retrieving matched
nodes by name from `QueryCursor.matches()`.

Matches regular functions, async functions, and methods inside classes. Does not
match lambdas (those are `lambda` nodes, not `function_definition`).

### `_LOCALS_QUERY` -- variables and calls

Five patterns covering all ways Python creates a variable:

```python
(assignment left: (_) @assign.lhs)                   # x = 1
(augmented_assignment left: (_) @aug.lhs)             # x += 1
(for_statement left: (_) @for.lhs)                   # for x in items:
(named_expression name: (identifier) @walrus.name)   # (x := len(items))
(call function: (identifier) @call.name)             # foo()
```

Each pattern is a different AST node type. There is no single "creates a variable"
node in tree-sitter's Python grammar, so all five must be enumerated. Missing any
one means those variable names are invisible to Vanir's function signature.

### `PythonParser` class

```python
class PythonParser(TreeSitterParserBase):
    LANGUAGE = _PY_LANGUAGE
    _FUNC_QUERY = _FUNC_QUERY
    SKIP_TOKEN_TYPES = frozenset({
        'comment', 'newline', 'indent', 'dedent', 'line_continuation'
    })
    STRING_NODE_TYPE = 'string'

    @classmethod
    def get_supported_extensions(cls):
        return ['.py'] if _TREE_SITTER_AVAILABLE else []
```

### `_extract_param_names`

Loops through children of the `parameters` node. Each child may be one of several
types:

```
parameters
├── identifier               "self"        read .text directly
├── typed_parameter          "data: str"   read identifier child only
├── typed_default_parameter  "x: int = 0"  read identifier child only
├── list_splat_pattern       "*args"        read identifier child
└── dictionary_splat_pattern "**kwargs"    read identifier child
```

Returns: `["self", "data", "x", "args", "kwargs"]`

### `_extract_annotations`

Reads type hints from the function node:

- **Return type** -- `func_node.child_by_field_name('return_type')` reads `-> bool` and returns `["bool"]`
- **Parameter types** -- for each typed parameter, reads its `type` field and returns e.g. `["str"]`, `["List", "[", "int", "]"]`

Both use `_flat_tokens_cursor` to get a flat token list from the annotation subtree.

### `_collect_locals_calls`

Runs `_LOCALS_QUERY` on the function body using `QueryCursor(_LOCALS_QUERY).captures(body_node)`.
Returns a dict of capture label to list of nodes.

For each captured node, checks `_is_nested()` -- if the node's byte offset falls
inside a nested function's byte range, it is excluded. This prevents inner function
variables from contaminating the outer function's local variable list.

Returns `(local_vars_set, called_fns_set)`, both sets of strings.

Back in the base class, parameters are subtracted from `local_vars_set` so parameter
names do not appear in both lists.

---

## Python-specific Handling

### SKIP_TOKEN_TYPES

```python
SKIP_TOKEN_TYPES = frozenset({
    'comment',           # comments -- irrelevant to signatures
    'newline',           # explicit newline tokens in Python CST
    'indent',            # whitespace increase entering a block (Python uses indentation, not {})
    'dedent',            # whitespace decrease leaving a block
    'line_continuation', # backslash \ at end of line
})
```

`frozenset` is used for O(1) lookup. This check runs on every node during tree
walking.

### STRING_NODE_TYPE

All string literals -- `'hello'`, `"hello"`, `"""docstring"""`, `f"f-string"` -- are
the same node type `'string'` in tree-sitter's Python grammar. Setting
`STRING_NODE_TYPE = 'string'` causes the walker to emit the entire string as one
opaque token rather than descending into its subtree.

### Nested functions

Both outer and inner functions are found by `_FUNC_QUERY`. The base class computes
`nested_ranges` -- byte ranges of all functions nested inside the current function.
`_collect_locals_calls` uses these to exclude captures that fall inside nested
functions, so each function gets an independent, uncontaminated chunk.

Example:

```python
def outer(self, filepath: str):
    local_path = os.path.join(filepath)

    def inner(x):
        result = process(x)
        return result

    data = fetch(local_path)
```

Result for `outer`:
```
local_variables:  ["data", "local_path"]   # inner's "result" excluded
called_functions: ["fetch"]                # inner's "process" excluded
```

Result for `inner` (its own separate chunk):
```
local_variables:  ["result"]
called_functions: ["process"]
```

### Design decisions consistent with existing parsers

Method chains are not captured as called functions across all Vanir parsers -- only
bare function/method identifiers are collected. This is intentional: method chains
vary widely across codebases and versions, and including them would produce unstable
signatures with high false-negative rates.

Lambdas are Python-specific and not extracted as function chunks. They appear as
tokens within their enclosing function's token list, which is sufficient for
line-based signature matching.

Class definitions are not extracted as chunks in any Vanir parser. Methods inside
classes are extracted as regular function chunks, consistent with how C++ and Java
parsers handle class methods.

---

## language_parsers.py Fix

When `TreeSitterParserBase` was introduced as a middle layer, `PythonParser` became
an indirect subclass of `AbstractLanguageParser`. The existing `get_parser_class()`
used `cls.__subclasses__()` which only returns direct subclasses -- so `PythonParser`
became invisible to the parser lookup.

Fix: replaced with a recursive function that skips abstract classes:

```python
def _all_subclasses(cls):
    result = []
    for sub in cls.__subclasses__():
        if not sub.__abstractmethods__:   # skip abstract classes
            result.append(sub)
        result.extend(_all_subclasses(sub))  # recurse
    return result
```

`__abstractmethods__` is a `frozenset` on every class -- empty for concrete classes,
non-empty for abstract ones. This correctly excludes `TreeSitterParserBase` (which
has three unimplemented abstract methods) while including `PythonParser` (which
implements all of them).

---

## Build Changes

### 1. `requirements/requirements.txt`

```
tree-sitter>=0.25.2; python_version>='3.10'
tree-sitter-python>=0.23.4; python_version>='3.10'
```

PEP 508 environment markers -- pip reads `; python_version>='3.10'` and only installs
tree-sitter on Python 3.10+. On 3.9 these lines are silently ignored.

### 2. `requirements/requirements_lock_3.10.txt` through `requirements_lock_3.13.txt`

Pinned tree-sitter versions added to each lock file. The `requirements_lock_3.9.txt`
file has no tree-sitter entries.

### 3. `vanir/language_parsers/BUILD.bazel`

New Bazel library target for the base class:

```python
py_library(
    name = "tree_sitter_base",
    srcs = ["tree_sitter_base.py"],
    deps = [":abstract_language_parser", ":common"],
)
```

No tree-sitter dependency here -- the base class does not import tree-sitter at
module level.

### 4. `vanir/language_parsers/python/BUILD.bazel`

tree-sitter added as a dependency of the Python parser:

```python
deps = [
    "//vanir/language_parsers:tree_sitter_base",
    requirement("tree-sitter"),
    requirement("tree-sitter-python"),
]
```

---

## Python 3.9 Guard

tree-sitter officially requires Python >= 3.10, as declared in its
[`pyproject.toml`](https://github.com/tree-sitter/py-tree-sitter/blob/master/pyproject.toml):

```
requires-python = ">=3.10"
```

No `cp39` wheel is published on PyPI. Vanir supports Python 3.9, so a guard is
required to prevent crashes.

### Guard location: `python_parser.py`

**Place 1 -- import guard (module level):**

```python
try:
    import tree_sitter_python as _tspython
    from tree_sitter import Language, QueryCursor
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
```

Runs once at module import time. On Python 3.9, the `except` branch runs and
`_TREE_SITTER_AVAILABLE` is set to `False`.

**Place 2 -- extensions guard:**

```python
@classmethod
def get_supported_extensions(cls):
    return ['.py'] if _TREE_SITTER_AVAILABLE else []
```

When `language_parsers.py` calls `get_parser_class("foo.py")`, it checks
`get_supported_extensions()` for every parser. On Python 3.9 this returns `[]` --
so `.py` is not in the list, `PythonParser` is never selected, and `.py` files are
silently skipped. C/C++ and Java parsers continue to work normally.

The guard is not in `tree_sitter_base.py`. The base class has no guard. It
assumes if it is being instantiated, tree-sitter is available. The guard lives in
the concrete subclass which is the one that knows whether its language package is
installed.

---

## Testing Across Python Versions

### Docker setup

Four Docker containers for Linux testing (tree-sitter requires Linux for Bazel):

| Container | Python version | Command |
|-----------|---------------|---------|
| `vanir-py310` | 3.10 | `docker compose run --rm vanir-py310` |
| `vanir-py311` | 3.11 | `docker compose run --rm vanir-py311` |
| `vanir-py312` | 3.12 | `docker compose run --rm vanir-py312` |
| `vanir-py313` | 3.13 | `docker compose run --rm vanir-py313` |

Each container has its own named Bazel cache volume so Python toolchains do not
conflict across versions.

To verify which Python version is running inside a container:
```bash
python3 --version
```

### Running tests inside a container

```bash
# Attach to a running container
docker exec -it vanir-uw-vanir-py312-1 bash

# Run all Vanir tests
bazel test //... --config=py3.12 --test_output=all
```

All 23 existing tests pass across Python 3.10, 3.11, 3.12, and 3.13 with zero
regressions.

### Python 3.9 behavior

On Python 3.9, Bazel will fail at build time when trying to resolve tree-sitter
wheels:

```
No matching wheel for current configuration's Python version.
This distribution supports the following Python configuration settings:
    //_config:is_cp310
    //_config:is_cp311
    //_config:is_cp312
    //_config:is_cp313
```

This is expected. tree-sitter has no 3.9 wheel. The guard in `python_parser.py`
handles this at runtime: `_TREE_SITTER_AVAILABLE = False` and `.py` files are
skipped.

---

## End-to-End Validation

The new Python parser was validated end-to-end using a real CVE against a real
Python codebase.

### Vulnerability: GHSA-xjgw-4wvw-rgm4

A path traversal vulnerability (CVSS 9.0 Critical) in `mcp-atlassian`, a Python
MCP server for Atlassian tools. The fix was released in v0.17.0.

### Vulnerability input file (`mcp_vuln.json`)

Since mcp-atlassian is a PyPI package and Vanir only supports GIT and Android
ecosystems natively, the vulnerability was expressed as a GIT-type entry:

```json
[{
  "id": "GHSA-xjgw-4wvw-rgm4",
  "modified": "2025-03-01T00:00:00Z",
  "summary": "mcp-atlassian path traversal",
  "affected": [{
    "ranges": [{
      "type": "GIT",
      "repo": "https://github.com/sooperset/mcp-atlassian",
      "events": [
        {"introduced": "0"},
        {"fixed": "52b9b0997681e87244b20d58034deae89c91631e"}
      ]
    }]
  }]
}]
```

### Sign generation

```bash
bazel run //:sign_generator_runner --config=py3.11 -- \
  --vulnerability_file_name=/workspace/mcp_vuln.json \
  --signature_file_name=/tmp/vanir/sigs.json
```

Vanir clones the repo, computes the diff at commit `52b9b09`, runs `PythonParser`
on both the vulnerable and patched versions of each changed file, hashes the
chunks, and writes signatures to `sigs.json`.

### Detection

```bash
# Clone the last vulnerable version
git clone https://github.com/sooperset/mcp-atlassian /tmp/mcp-atlassian
cd /tmp/mcp-atlassian && git checkout v0.16.1

# Scan it
bazel run //:detector_runner --config=py3.11 -- \
  --vulnerability_file_name=/tmp/vanir/sigs.json \
  --target_selection_strategy=all_files \
  --report_file_name_prefix=/tmp/vanir/mcp-report \
  --minimum_number_of_files=1 \
  offline_directory_scanner /tmp/mcp-atlassian
```

**Result:** `GHSA-xjgw-4wvw-rgm4` correctly flagged as unpatched in v0.16.1. The
vulnerable function `download_attachment` in `attachments.py` was detected.

### Parser validation on large Python codebases

The detector was also run against `requests` and `flask` to validate the parser on
larger real-world Python codebases:

```bash
git clone https://github.com/psf/requests /tmp/requests

bazel run //:detector_runner --config=py3.12 -- \
  --vulnerability_file_name=/tmp/vanir/sigs.json \
  --target_selection_strategy=all_files \
  --report_file_name_prefix=/tmp/vanir/report \
  --minimum_number_of_files=1 \
  offline_directory_scanner /tmp/requests
```

Both ran with 0 parse errors across all scanned `.py` files.


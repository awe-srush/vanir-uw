# integration/python-parser-e2e

## Summary

End-to-end integration branch that pulls together all Python parser feature branches and validates them against the latest upstream Vanir changes.

## Objective

This branch serves as the integration test environment for the Python language parser feature, combining the following branches:

- **`bug/fix-subclass-discovery`** — fixes subclass discovery to support multi-level parser hierarchies
- **`feat/tree-sitter-integration`** — adds `TreeSitterParserBase`, a shared base class for tree-sitter backed language parsers
- **`feat/python-parser`** — adds the Python language parser implementation using tree-sitter
- **`feat/python-parser-deps`** — adds `tree-sitter` and `tree-sitter-python` pip dependencies to `requirements.txt`
- **`feat/python-parser-build`** — adds Bazel build targets for the Python parser and tree-sitter base

## Testing

All branches were integrated with the latest upstream Vanir changes (July 2026) and tested end-to-end on Python 3.12 inside Docker. The detector was run against a real-world vulnerability ([GHSA-j6g5-3hh3-pgw8](https://osv.dev/vulnerability/GHSA-j6g5-3hh3-pgw8) — AWS Bedrock AgentCore) using a pre-fix clone of the target repository, validating that the Python parser correctly identifies unpatched code.

## Notes

During integration testing, a breaking API change in `tree-sitter==0.26.0` (released June 30, 2026) was uncovered. The fix — capping `tree-sitter<0.26` in `requirements.txt` — is included in this branch and should be reflected in `feat/python-parser-deps`.

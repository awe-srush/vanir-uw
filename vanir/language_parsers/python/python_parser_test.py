# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for vanir/language_parsers/python/python_parser.py."""

import textwrap

from vanir.language_parsers.python import python_parser

from absl.testing import absltest


@absltest.skipUnless(
    python_parser._TREE_SITTER_AVAILABLE,
    'tree-sitter not available (requires Python >= 3.10)',
)
class PythonParserTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.testcode = textwrap.dedent("""\
        x = 10
        def test_func(arg1: int, arg2: str = "hi") -> bool:
            local_var = transform(arg1)
            result = validate(local_var, arg2)
            return result
        def empty_func():
            pass
    """)
    testfile = self.create_tempfile('testfile.py', content=self.testcode)
    self.test_filename = testfile.full_path

  def _get_chunk(self, name, chunks):
    for c in chunks:
      if c.name == name:
        return c
    self.fail(f'No chunk named {name!r}')

  # ------------------------------------------------------------------
  # Basic structure
  # ------------------------------------------------------------------

  def test_function_names(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    names = [c.name for c in results.function_chunks]
    self.assertIn('test_func', names)
    self.assertIn('empty_func', names)

  def test_parameters(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertEqual(chunk.parameters, ['arg1', 'arg2'])

  def test_empty_parameters(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('empty_func', results.function_chunks)
    self.assertEmpty(chunk.parameters)

  # ------------------------------------------------------------------
  # Type annotations
  # ------------------------------------------------------------------

  def test_return_types(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertEqual(chunk.return_types, [['bool']])

  def test_used_data_types(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertIn(['int'], chunk.used_data_types)
    self.assertIn(['str'], chunk.used_data_types)

  def test_no_annotations_on_empty_func(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('empty_func', results.function_chunks)
    self.assertEmpty(chunk.return_types)
    self.assertEmpty(chunk.used_data_types)

  # ------------------------------------------------------------------
  # Local variables and called functions
  # ------------------------------------------------------------------

  def test_local_variables(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertIn('local_var', chunk.local_variables)
    self.assertIn('result', chunk.local_variables)
    # parameters must NOT appear as local vars
    self.assertNotIn('arg1', chunk.local_variables)
    self.assertNotIn('arg2', chunk.local_variables)

  def test_called_functions(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertIn('transform', chunk.called_functions)
    self.assertIn('validate', chunk.called_functions)

  # ------------------------------------------------------------------
  # Tokens
  # ------------------------------------------------------------------

  def test_tokens_not_empty(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    chunk = self._get_chunk('test_func', results.function_chunks)
    self.assertNotEmpty(chunk.tokens)
    # function keyword must appear
    self.assertIn('def', chunk.tokens)
    # parameter names must appear
    self.assertIn('arg1', chunk.tokens)

  # ------------------------------------------------------------------
  # Line chunk
  # ------------------------------------------------------------------

  def test_line_chunk_tokens(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    # Line 1: x = 10
    self.assertIn(1, results.line_chunk.tokens)
    self.assertEqual(results.line_chunk.tokens[1], ['x', '=', '10'])
    # Line 2: def test_func(...)
    self.assertIn(2, results.line_chunk.tokens)
    self.assertIn('def', results.line_chunk.tokens[2])
    self.assertIn('test_func', results.line_chunk.tokens[2])

  def test_line_chunk_no_comments(self):
    code = textwrap.dedent("""\
        # this is a comment
        y = 5  # inline comment
    """)
    testfile = self.create_tempfile('nocomments.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    # Line 1 is purely a comment — should be absent
    self.assertNotIn(1, results.line_chunk.tokens)
    # Line 2 should have y, =, 5 but NOT comment text
    self.assertIn(2, results.line_chunk.tokens)
    self.assertIn('y', results.line_chunk.tokens[2])
    for tok in results.line_chunk.tokens[2]:
      self.assertFalse(tok.startswith('#'), f'comment leaked into tokens: {tok!r}')

  # ------------------------------------------------------------------
  # Affected line range filter
  # ------------------------------------------------------------------

  def test_affected_line_range_filter_includes(self):
    # test_func starts at line 2 — range (2, 5) should include it
    results = python_parser.PythonParser(self.test_filename).get_chunks(
        affected_line_ranges_for_functions=[(2, 5)]
    )
    names = [c.name for c in results.function_chunks]
    self.assertIn('test_func', names)

  def test_affected_line_range_filter_excludes(self):
    # empty_func starts at line 6 — range (2, 5) should exclude it
    results = python_parser.PythonParser(self.test_filename).get_chunks(
        affected_line_ranges_for_functions=[(2, 5)]
    )
    names = [c.name for c in results.function_chunks]
    self.assertNotIn('empty_func', names)

  def test_no_filter_returns_all_functions(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    self.assertLen(results.function_chunks, 2)

  # ------------------------------------------------------------------
  # String handling
  # ------------------------------------------------------------------

  def test_triple_quoted_string_is_single_token(self):
    code = textwrap.dedent("""\
        def doc_func():
            \"\"\"This is a
            multi-line docstring.\"\"\"
            pass
    """)
    testfile = self.create_tempfile('docstring.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    chunk = self._get_chunk('doc_func', results.function_chunks)
    # The docstring should appear as a single token, not split across lines
    string_tokens = [t for t in chunk.tokens if '"""' in t or "'''" in t]
    self.assertLen(string_tokens, 1)
    self.assertIn('multi-line docstring', string_tokens[0])

  def test_fstring_is_single_token(self):
    code = textwrap.dedent("""\
        def fmt_func(name):
            return f"hello {name}"
    """)
    testfile = self.create_tempfile('fstring.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    chunk = self._get_chunk('fmt_func', results.function_chunks)
    fstring_tokens = [t for t in chunk.tokens if t.startswith('f"') or t.startswith("f'")]
    self.assertLen(fstring_tokens, 1)

  # ------------------------------------------------------------------
  # Complex annotations
  # ------------------------------------------------------------------

  def test_generic_type_annotation(self):
    code = textwrap.dedent("""\
        from typing import Optional, List
        def complex_func(data: List[str]) -> Optional[bool]:
            return None
    """)
    testfile = self.create_tempfile('generic.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    chunk = self._get_chunk('complex_func', results.function_chunks)
    self.assertIn(['Optional', '[', 'bool', ']'], chunk.return_types)
    self.assertIn(['List', '[', 'str', ']'], chunk.used_data_types)

  # ------------------------------------------------------------------
  # Nested functions
  # ------------------------------------------------------------------

  def test_nested_function_extracted_separately(self):
    code = textwrap.dedent("""\
        def outer(x):
            def inner(y):
                return y * 2
            return inner(x)
    """)
    testfile = self.create_tempfile('nested.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    names = [c.name for c in results.function_chunks]
    self.assertIn('outer', names)
    self.assertIn('inner', names)

  def test_nested_locals_not_in_outer(self):
    code = textwrap.dedent("""\
        def outer(x):
            outer_var = 1
            def inner(y):
                inner_var = 2
                return inner_var
            return outer_var
    """)
    testfile = self.create_tempfile('nested_locals.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    outer_chunk = self._get_chunk('outer', results.function_chunks)
    # outer_var should appear; inner_var must NOT (it belongs to inner)
    self.assertIn('outer_var', outer_chunk.local_variables)
    self.assertNotIn('inner_var', outer_chunk.local_variables)

  # ------------------------------------------------------------------
  # Parse errors
  # ------------------------------------------------------------------

  def test_parse_errors_on_broken_code(self):
    broken = '$$$ %%% @@@\ndef foo():\n    pass\n'
    testfile = self.create_tempfile('broken.py', content=broken)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    self.assertNotEmpty(results.parse_errors)
    self.assertEqual(results.parse_errors[0].line, 1)
    self.assertEqual(results.parse_errors[0].message, 'syntax error')

  def test_no_parse_errors_on_valid_code(self):
    results = python_parser.PythonParser(self.test_filename).get_chunks()
    self.assertEmpty(results.parse_errors)

  # ------------------------------------------------------------------
  # Walrus operator (named expression)
  # ------------------------------------------------------------------

  def test_walrus_operator_local_var(self):
    code = textwrap.dedent("""\
        def walrus_func(items):
            if (n := len(items)) > 0:
                return n
            return 0
    """)
    testfile = self.create_tempfile('walrus.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    chunk = self._get_chunk('walrus_func', results.function_chunks)
    self.assertIn('n', chunk.local_variables)

  # ------------------------------------------------------------------
  # Async functions
  # ------------------------------------------------------------------

  def test_async_function(self):
    code = textwrap.dedent("""\
        async def async_func(items):
            for item in items:
                process(item)
    """)
    testfile = self.create_tempfile('async.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    names = [c.name for c in results.function_chunks]
    self.assertIn('async_func', names)
    chunk = self._get_chunk('async_func', results.function_chunks)
    self.assertIn('item', chunk.local_variables)
    self.assertIn('process', chunk.called_functions)


if __name__ == '__main__':
  absltest.main()

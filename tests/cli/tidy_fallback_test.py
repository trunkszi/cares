import unittest
import asyncio
import sys
from pathlib import Path

from cli.cmd_tidy import run_tidy, _syntax_only_arguments, _check_all


class TidyFallbackTest(unittest.TestCase):
    diagnostic = (
        "/project/layout.hpp:1:1: error: expected expression [clang-diagnostic-error]\n"
        "  auto reflected = ^^int;\n"
        "/project/test.cc:5:1: error: static assertion failed [clang-diagnostic-error]\n"
    )

    def test_unverified_frontend_failure_remains_an_error(self):
        self.assertTrue(run_tidy(1, self.diagnostic, fallback=True)[0])

    def test_native_compiler_verifies_reflection_cascade(self):
        self.assertFalse(run_tidy(1, self.diagnostic, fallback=True, compiler_verified=True)[0])

    def test_named_lint_is_never_suppressed(self):
        output = self.diagnostic + "/project/test.cc:9:1: error: bad name [readability-identifier-naming]\n"
        self.assertTrue(run_tidy(1, output, fallback=True, compiler_verified=True)[0])

    def test_driver_failure_is_never_suppressed(self):
        output = self.diagnostic + "error: unknown argument: '-broken'\n"
        self.assertTrue(run_tidy(1, output, fallback=True, compiler_verified=True)[0])

    def test_crash_is_never_suppressed(self):
        self.assertTrue(run_tidy(-11, self.diagnostic, fallback=True, compiler_verified=True)[0])

    def test_real_cpp_error_without_reflection_is_never_suppressed(self):
        output = "/project/test.cc:1:1: error: unknown variable [clang-diagnostic-error]\n"
        self.assertTrue(run_tidy(1, output, fallback=True, compiler_verified=True)[0])

    def test_native_failure_blocks_even_an_already_classified_reflection_error(self):
        class Output:
            fmt = "json"
            def emit(self, *args, **kwargs):
                pass
        direct = "/project/layout.hpp:1:1: error: expected expression [clang-diagnostic-error]\n  auto value = ^^int;\n"
        command = [sys.executable, "-c", f"print({direct!r}); raise SystemExit(1)"]
        native = {"-c": ([sys.executable, "-c", "raise SystemExit(1)"], str(Path.cwd()))}
        with self.assertRaises(RuntimeError):
            asyncio.run(_check_all([command], 1, Output(), p2996_capable=False, native_commands=native))

    def test_native_command_preserves_language_and_writes_no_object(self):
        args = ["ccache", "clang++", "-std=c++26", "-freflection-latest", "-Werror", "-MD", "-MF", "x.d", "-MT", "x.o", "-c", "x.cc", "-o", "x.o"]
        self.assertEqual(_syntax_only_arguments(args), ["clang++", "-std=c++26", "-freflection-latest", "-Werror", "x.cc", "-fsyntax-only"])


if __name__ == "__main__":
    unittest.main()

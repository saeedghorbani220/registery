"""Robots must run under the interpreter that owns the shipped dependencies.

Regression cover for the v1.0.3 field failure: the panel spawned every robot
with a hardcoded `C:\\Program Files\\Python310\\python.exe`. On a machine where
that interpreter exists and has torch installed, the solver packages chose their
torch backend -- whose modules (`solver/predict.py`, `Hamta-solver/model.py`) are
deliberately NOT shipped in the release -- so every inquiry died with
`ModuleNotFoundError` before the browser opened.

Three independent contracts are pinned here:

1. The interpreter: robots run under the panel's own `sys.executable`.
2. The import path: `robot_launcher.py` works under an ISOLATED interpreter,
   which is what the embedded runtime in the bundle is (`-I` reproduces it: no
   script directory on `sys.path`, `PYTHONPATH` ignored).
3. Backend selection: a solver only takes its torch path when the torch-only
   modules are actually importable, so a stray torch install cannot break it.

Run:
    "C:/Program Files/Python310/python.exe" lab/scripts/run_panel_tests.py test_robot_interpreter
"""
import contextlib
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import panel

ROOT = os.path.dirname(os.path.abspath(panel.__file__))
LAUNCHER = os.path.join(ROOT, "robot_launcher.py")
# `_tmp_*` is one of the patterns panel.clean_project_root() removes, so a
# leftover fixture can never become a permanent file in the project root.
PROBE = os.path.join(ROOT, "_tmp_launcher_probe.py")
PROBE_SOURCE = (
    "import system_debug\n"
    "import panel\n"
    "print('PROBE_OK', system_debug.__name__, panel.PORT)\n"
)


class RobotInterpreterTests(unittest.TestCase):
    """The panel must never hand a robot to a foreign interpreter."""

    def test_default_robot_interpreter_is_the_panel_interpreter(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IRICA_ROBOT_PYTHON", None)
            self.assertEqual(panel._resolve_robot_python(), sys.executable)

    def test_override_is_honoured_only_when_it_points_at_a_real_file(self):
        with patch.dict(os.environ, {"IRICA_ROBOT_PYTHON": sys.executable}):
            self.assertEqual(panel._resolve_robot_python(), sys.executable)
        with patch.dict(os.environ, {"IRICA_ROBOT_PYTHON": os.path.join(ROOT, "no-such-python.exe")}):
            self.assertEqual(panel._resolve_robot_python(), sys.executable)
        with patch.dict(os.environ, {"IRICA_ROBOT_PYTHON": "   "}):
            self.assertEqual(panel._resolve_robot_python(), sys.executable)

    def test_module_level_interpreter_is_resolved_not_hardcoded(self):
        self.assertTrue(os.path.isfile(panel.ROBOT_PYTHON), panel.ROBOT_PYTHON)
        source = open(panel.__file__, encoding="utf-8").read()
        self.assertNotIn(r"ROBOT_PYTHON = r\"C:\Program Files", source)

    def test_every_spawn_helper_launches_the_resolved_interpreter(self):
        helpers = (
            ("start_profile_process", ("p1",)),
            ("start_profile2_process", ("p1",)),
            ("start_site2_manual_process", ()),
            ("start_exitban_process", ("p1",)),
            ("start_estelam_process", (None, "hamta")),
        )
        for name, args in helpers:
            with self.subTest(helper=name):
                with patch.object(panel.subprocess, "Popen") as popen:
                    popen.return_value = Mock(pid=1234)
                    getattr(panel, name)(*args)
                    command = popen.call_args.args[0]
                self.assertEqual(command[0], panel.ROBOT_PYTHON)
                self.assertEqual(command[0], sys.executable)
                self.assertIn("robot_launcher.py", command[1])

    def test_no_spawn_helper_reads_sys_executable_directly(self):
        """`sys.executable` belongs in _resolve_robot_python() and nowhere else.

        A helper reading it directly would drift out of sync with the override.
        """
        for name in ("start_profile_process", "start_profile2_process",
                     "start_site2_manual_process", "start_exitban_process",
                     "start_estelam_process", "start_profile_device_inquiry"):
            with self.subTest(helper=name):
                self.assertNotIn("executable", getattr(panel, name).__code__.co_names)


class LauncherBootstrapTests(unittest.TestCase):
    """robot_launcher.py must survive the bundle's isolated interpreter."""

    def setUp(self):
        with open(PROBE, "w", encoding="utf-8") as handle:
            handle.write(PROBE_SOURCE)

    def tearDown(self):
        try:
            os.remove(PROBE)
        except OSError:
            pass

    def _run(self, *flags):
        return subprocess.run([sys.executable, *flags, LAUNCHER, PROBE],
                              cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=120)

    def test_launcher_imports_project_modules_under_isolated_interpreter(self):
        """`-I` mirrors the shipped embedded python: no script dir on sys.path."""
        result = self._run("-I")
        self.assertEqual(result.returncode, 0, result.stdout[-800:])
        self.assertIn("PROBE_OK", result.stdout)

    def test_launcher_still_works_on_a_normal_interpreter(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout[-800:])
        self.assertIn("PROBE_OK", result.stdout)

    def test_launcher_bootstraps_before_importing_project_code(self):
        source = open(LAUNCHER, encoding="utf-8").read()
        self.assertLess(source.index("sys.path"), source.index("import system_debug"),
                        "sys.path must be repaired before the first project import")

    def test_panel_lazy_imports_survive_an_isolated_interpreter(self):
        """`import exitban` inside /exitban-inquiry runs at REQUEST time.

        run_panel.bat starts panel.py DIRECTLY (not through the launcher), so
        panel.py's own module body must repair sys.path -- otherwise that route
        500s on the user's machine while every unit test passes.

        The probe executes panel.py exactly as a script (`runpy.run_path`, so
        main() does not start the server) and then performs the lazy import. A
        control probe without that step proves the check can actually go red.
        """
        control = ("import exitban\n" "print('CONTROL_OK')\n")
        probe = ("import runpy\n"
                 f"runpy.run_path({os.path.join(ROOT, 'panel.py')!r}, run_name='panel_probe')\n"
                 "import exitban\n"
                 "print('LAZY_OK', bool(exitban.missing_identity_fields({})))\n")
        script = os.path.join(ROOT, "_tmp_panel_lazy_probe.py")

        def run(source):
            with open(script, "w", encoding="utf-8") as handle:
                handle.write(source)
            try:
                return subprocess.run([sys.executable, "-I", script], cwd=ROOT,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, timeout=120)
            finally:
                try:
                    os.remove(script)
                except OSError:
                    pass

        blank = run(control)
        self.assertNotEqual(blank.returncode, 0,
                            "isolated interpreter should not find project modules")
        self.assertIn("ModuleNotFoundError", blank.stdout)

        result = run(probe)
        self.assertEqual(result.returncode, 0, result.stdout[-800:])
        self.assertIn("LAZY_OK", result.stdout)


class ChildSpawnTests(unittest.TestCase):
    """Robots that spawn robots must go through the launcher too."""

    def test_estelam_all_runs_children_through_the_launcher(self):
        import estelam_all
        with patch.object(estelam_all.subprocess, "call", return_value=0) as call:
            estelam_all._run("estelam_gomrok.py", ["--device-id", "d1"])
            command = call.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertIn("robot_launcher.py", command[1])
        self.assertIn("estelam_gomrok.py", command[2])
        self.assertEqual(command[-2:], ["--device-id", "d1"])

    def test_profile_inquiry_runs_children_through_the_launcher(self):
        import profile_inquiry
        with patch.object(profile_inquiry.subprocess, "call", return_value=0) as call:
            profile_inquiry._run("estelam_hamta.py", ["--from-store"], "store.json")
            command = call.call_args.args[0]
            env = call.call_args.kwargs["env"]
        self.assertEqual(command[0], sys.executable)
        self.assertIn("robot_launcher.py", command[1])
        self.assertIn("estelam_hamta.py", command[2])
        self.assertEqual(command[-1], "--from-store")
        self.assertEqual(env["IRICA_ESTELAM_STORE"], "store.json")


class SolverBackendSelectionTests(unittest.TestCase):
    """A solver may only take its torch path when that path can actually load."""

    @contextlib.contextmanager
    def _live(self, package):
        """Import a solver package's live_solve with its directory on sys.path.

        The directory stays on `sys.path` for the whole block, mirroring
        `estelam_hamta.load_solver()` / `gomrok` at runtime: they insert the
        solver directory, call into it, and only restore the path afterwards.
        Sibling modules (`model`, `predict`, `onnx_solve`) are therefore
        resolvable exactly as they are in production.
        """
        import importlib

        names = ("live_solve", "config", "vocab", "preprocess", "utils",
                 "onnx_solve", "number_decode", "model", "predict")
        directory = os.path.join(ROOT, package)
        saved_path = list(sys.path)
        saved = {name: sys.modules.pop(name) for name in names if name in sys.modules}
        sys.path.insert(0, directory)
        try:
            yield importlib.import_module("live_solve")
        finally:
            for name in names:
                sys.modules.pop(name, None)
            sys.modules.update(saved)
            sys.path[:] = saved_path

    def test_hamta_solver_reports_its_torch_backend_availability(self):
        with self._live("Hamta-solver") as live:
            self.assertTrue(live._torch_backend_available())
            self.assertFalse(live._module_importable("no_such_backend_module_xyz"))

    def test_gomrok_solver_reports_its_torch_backend_availability(self):
        with self._live("solver") as live:
            self.assertTrue(live._torch_backend_available())
            self.assertFalse(live._module_importable("no_such_backend_module_xyz"))

    def test_backend_falls_back_to_onnx_when_torch_modules_are_absent(self):
        """The release ships no predict.py/model.py; that must select ONNX."""
        for package, marker in (("Hamta-solver", "OnnxHamtaSolver"), ("solver", "OnnxSolver")):
            with self.subTest(package=package), self._live(package) as live:
                # This test is about backend selection, not loading external
                # model artifacts. The packaged release verifies the real ONNX
                # weights separately, while clean source checkouts intentionally
                # contain neither .pt nor .onnx files.
                fake_module = type(sys)("onnx_solve")
                fake_solver = type(marker, (), {
                    "__init__": lambda self, *args, **kwargs: None,
                })
                setattr(fake_module, marker, fake_solver)
                with patch.dict(sys.modules, {"onnx_solve": fake_module}):
                    with patch.object(live, "_torch_backend_available",
                                      return_value=False):
                        solver = live.load_solver(device="cpu")
                self.assertEqual(type(solver).__name__, marker)

    def test_torch_alone_does_not_select_the_torch_backend(self):
        """Exactly the v1.0.3 failure: torch present, backend modules absent."""
        for package, module in (("Hamta-solver", "model"), ("solver", "predict")):
            with self.subTest(package=package), self._live(package) as live:
                self.assertTrue(live._module_importable(module), "dev tree must have it")
                with patch.object(live, "_module_importable",
                                  side_effect=lambda name, m=module: name != m):
                    self.assertFalse(live._torch_backend_available())


if __name__ == "__main__":
    unittest.main()

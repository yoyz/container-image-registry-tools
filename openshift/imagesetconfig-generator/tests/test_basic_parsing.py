"""Basic unit tests: synthetic FBC fixtures exercising one handling path each.

These tests never touch podman; they validate handle_parse_fbc and
write_image_set_config against small committed fixtures under tests/fixtures.
"""

import contextlib
import io
import os
import tempfile
import unittest
import unittest.mock

from helpers import assemble_combined_config, fixture_path, golden_path, load_generator

MOD = load_generator()

# Catalog image used by golden tests; value only affects the YAML header line.
FAKE_CATALOG = 'example.com/operators/test-catalog:v1'


def parse(config_dir, **kwargs):
    """Run handle_parse_fbc, silencing the status output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return MOD.handle_parse_fbc(config_dir, **kwargs)


def generate(config_dir, version='v1', **kwargs):
    """Run write_image_set_config to a temp file; return (path, yaml_text)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'output.yaml')
        with contextlib.redirect_stdout(io.StringIO()):
            MOD.write_image_set_config(out, FAKE_CATALOG, parse(config_dir),
                                       version=version, **kwargs)
        with open(out) as f:
            return out, f.read()


class TestParseBasic(unittest.TestCase):

    def test_prefix_collision_keeps_packages_separate(self):
        """amq-streams vs amq-streams-console must not bleed into each other."""
        pkg_map = parse(fixture_path('prefix-collision'))
        self.assertEqual(sorted(pkg_map.keys()), ['amq-streams', 'amq-streams-console'])
        self.assertEqual(pkg_map['amq-streams']['channels'], {'stable'})
        self.assertEqual(pkg_map['amq-streams-console']['channels'], {'alpha'})

    def test_versions_land_in_correct_package(self):
        pkg_map = parse(fixture_path('prefix-collision'))
        self.assertEqual(pkg_map['amq-streams']['versions']['stable'],
                         ['2.2.0', '2.10.0', '2.11.0'])
        self.assertEqual(pkg_map['amq-streams-console']['versions']['alpha'],
                         ['1.0.0', '1.1.0'])

    def test_versions_naturally_sorted(self):
        """2.2.0 < 2.10.0 < 2.11.0 (lexicographic would give 2.10.0 first)."""
        pkg_map = parse(fixture_path('prefix-collision'))
        versions = pkg_map['amq-streams']['versions']['stable']
        self.assertEqual(versions, ['2.2.0', '2.10.0', '2.11.0'])

    def test_quoted_yaml_channel_name(self):
        """A channel like '3.15' (quoted in YAML) is collected as-is."""
        pkg_map = parse(fixture_path('quoted-channel'))
        self.assertIn('3.15', pkg_map['local-storage-operator']['channels'])
        self.assertEqual(pkg_map['local-storage-operator']['default'], '3.15')
        self.assertEqual(pkg_map['local-storage-operator']['versions']['3.15'], ['3.15.0'])

    def test_quoted_channel_unquoted_in_output(self):
        """'3.15' is matched against the default but stays quoted in the YAML."""
        _, text = generate(fixture_path('quoted-channel'))
        self.assertIn("- name: '3.15'  # default", text)

    def test_bundle_version_falls_back_to_bundle_name(self):
        """Bundle without an olm.package property resolves version from its name."""
        pkg_map = parse(fixture_path('fallback-version'))
        self.assertEqual(pkg_map['sample-operator']['versions']['stable'], ['1.0.0'])
        self.assertEqual(pkg_map['sample-operator']['versions']['preview'], ['1.0.0'])

    def test_non_target_files_skipped(self):
        """README.txt and similar files must be ignored without errors."""
        pkg_map = parse(fixture_path('fallback-version'))
        self.assertEqual(set(pkg_map.keys()), {'sample-operator'})

    def test_default_channel_present_in_channels(self):
        pkg_map = parse(fixture_path('prefix-collision'))
        self.assertIn(pkg_map['amq-streams']['default'], pkg_map['amq-streams']['channels'])

    def test_v1_has_no_default_channel_key(self):
        _, text = generate(fixture_path('prefix-collision'))
        self.assertNotIn('defaultChannel', text)

    def test_v2_has_default_channel_key(self):
        _, text = generate(fixture_path('prefix-collision'), version='v2')
        self.assertIn('defaultChannel: stable', text)


class TestGenerateFormatting(unittest.TestCase):

    def _combined(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return assemble_combined_config(tmp.name)

    def test_golden_v1(self):
        """Full v1 output must match the committed golden file exactly."""
        _, text = generate(self._combined(), version='v1')
        with open(golden_path('combined-v1.yaml')) as f:
            self.assertEqual(text, f.read())

    def test_golden_v2(self):
        _, text = generate(self._combined(), version='v2')
        with open(golden_path('combined-v2.yaml')) as f:
            self.assertEqual(text, f.read())

    def test_min_max_version_keys(self):
        _, text = generate(self._combined(), version='v2', min_max_version=True)
        self.assertIn('minVersion: 2.2.0', text)
        self.assertIn('maxVersion: 2.11.0', text)
        self.assertIn('minVersion: 1.0.0', text)
        self.assertIn('maxVersion: 1.1.0', text)

    def test_version_comments(self):
        _, text = generate(self._combined(), version='v1', version_comments=True)
        self.assertIn('# versions: 2.2.0, 2.10.0, 2.11.0', text)
        self.assertIn('# versions: 1.0.0, 1.1.0', text)

    def test_min_max_with_comments_combined(self):
        _, text = generate(self._combined(), version='v2',
                           version_comments=True, min_max_version=True)
        self.assertIn('minVersion: 2.2.0', text)
        self.assertIn('# versions: 2.2.0, 2.10.0, 2.11.0', text)


class TestRefactoredHelpers(unittest.TestCase):
    """Direct coverage of the handle_parse_fbc refactor helpers."""

    def test_select_parser_json(self):
        self.assertIsNotNone(MOD._select_parser('catalog.json'))

    def test_select_parser_yaml_and_yml(self):
        self.assertIsNotNone(MOD._select_parser('catalog.yaml'))
        self.assertIsNotNone(MOD._select_parser('index.yml'))

    def test_select_parser_non_target_returns_none(self):
        self.assertIsNone(MOD._select_parser('README.txt'))

    def test_make_pkg_entry_returns_fresh_entry(self):
        a = MOD._make_pkg_entry()
        b = MOD._make_pkg_entry()
        a['channels'].add('x')
        self.assertEqual(b['channels'], set(), "entries must not share mutable state")
        self.assertEqual(b, {'channels': set(), 'default': None, 'versions': {}})

    def test_handle_doc_package(self):
        pkg_map = {}
        MOD._handle_doc({'schema': 'olm.package', 'name': 'p1',
                         'defaultChannel': 'stable'}, pkg_map, {}, verbose=True)
        self.assertEqual(pkg_map['p1']['default'], 'stable')

    def test_handle_doc_channel(self):
        pkg_map = {}
        doc = {'schema': 'olm.channel', 'package': 'p1', 'name': 'stable',
               'entries': [{'name': 'p1.v1.0.0'}, {'name': 'p1.v1.0.0'}]}
        MOD._handle_doc(doc, pkg_map, {}, verbose=True)
        self.assertEqual(pkg_map['p1']['channels'], {'stable'})
        self.assertEqual(pkg_map['p1']['versions']['stable'], ['p1.v1.0.0'])

    def test_handle_doc_bundle(self):
        bundle_versions = {}
        doc = {'schema': 'olm.bundle', 'name': 'p1.v1.0.0',
               'properties': [{'type': 'olm.package',
                               'value': {'version': '1.0.0'}}]}
        MOD._handle_doc(doc, {}, bundle_versions, verbose=True)
        self.assertEqual(bundle_versions['p1.v1.0.0'], '1.0.0')

    def test_resolve_versions_sorts_naturally(self):
        pkg_map = {'p1': {'versions': {'stable': ['p1.v2.10.0', 'p1.v2.2.0', 'p1.v2.11.0']}}}
        bundle_versions = {'p1.v2.2.0': '2.2.0', 'p1.v2.10.0': '2.10.0',
                           'p1.v2.11.0': '2.11.0'}
        MOD._resolve_versions(pkg_map, bundle_versions)
        self.assertEqual(pkg_map['p1']['versions']['stable'],
                         ['2.2.0', '2.10.0', '2.11.0'])

    def test_resolve_versions_falls_back_to_bundle_name(self):
        pkg_map = {'p1': {'versions': {'stable': ['p1.v1.0.0']}}}
        MOD._resolve_versions(pkg_map, {})
        self.assertEqual(pkg_map['p1']['versions']['stable'], ['1.0.0'])


class TestExtractTlsVerify(unittest.TestCase):
    """handle_extract must forward --tls-verify to podman create."""

    def _fake_run(self, container_id='abc123'):
        return lambda *args, **kwargs: type('R', (), {'stdout': container_id + '\n'})()

    def test_tls_verify_true_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, 'configs')
            with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
                run.side_effect = self._fake_run()
                with contextlib.redirect_stdout(io.StringIO()):
                    MOD.handle_extract('reg/catalog:v1', dst)
                self.assertIn('--tls-verify=true', run.call_args_list[0][0][0])
                self.assertEqual(run.call_args_list[0][0][0][1], 'create')

    def test_tls_verify_false_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, 'configs')
            with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
                run.side_effect = self._fake_run()
                with contextlib.redirect_stdout(io.StringIO()):
                    MOD.handle_extract('reg/catalog:v1', dst, tls_verify=False)
                self.assertIn('--tls-verify=false', run.call_args_list[0][0][0])
                self.assertEqual(run.call_args_list[0][0][0][1], 'create')


class TestFetchAuthHandling(unittest.TestCase):
    """handle_fetch must not use podman search and must hint at login on failure."""

    def _mock_success(self, *args, **kwargs):
        return type('R', (), {'returncode': 0})()

    def test_no_podman_search_called(self):
        with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
            run.side_effect = self._mock_success
            with contextlib.redirect_stdout(io.StringIO()):
                MOD.handle_fetch('reg/catalog:v1', True, 600, False)
            for args, _ in run.call_args_list:
                self.assertNotEqual(args[0][0], 'search',
                                    "handle_fetch must not use 'podman search'")

    def test_pull_failure_hints_login_and_exits(self):
        with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
            run.side_effect = MOD.subprocess.CalledProcessError(125, ['podman'])
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                with self.assertRaises(SystemExit) as cm:
                    MOD.handle_fetch('reg/catalog:v1', True, 600, False)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn('podman login reg', buf.getvalue())

    def test_pull_failure_hints_local_image_when_present(self):
        """When the image is already in podman, suggest dropping --fetch."""
        def fake_run(*args, **kwargs):
            if args[0][1] == 'images':
                return type('R', (), {'stdout': 'reg/catalog:v1\nreg/other:v2\n', 'returncode': 0})()
            raise MOD.subprocess.CalledProcessError(125, ['podman'])

        with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
            run.side_effect = fake_run
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                with self.assertRaises(SystemExit):
                    MOD.handle_fetch('reg/catalog:v1', True, 600, False)
            self.assertIn('podman images', buf.getvalue())
            self.assertIn('without --fetch', buf.getvalue())

    def test_pull_failure_no_local_image_hint(self):
        """No local copy -> only the login hint is shown."""
        def fake_run(*args, **kwargs):
            if args[0][1] == 'images':
                return type('R', (), {'stdout': 'reg/other:v2\n', 'returncode': 0})()
            raise MOD.subprocess.CalledProcessError(125, ['podman'])

        with unittest.mock.patch.object(MOD.subprocess, 'run') as run:
            run.side_effect = fake_run
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                with self.assertRaises(SystemExit):
                    MOD.handle_fetch('reg/catalog:v1', True, 600, False)
            self.assertNotIn('without --fetch', buf.getvalue())


class TestOutputWritable(unittest.TestCase):
    """_check_output_writable must fail fast on unwritable paths."""

    def test_writable_path_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'out.yaml')
            MOD._check_output_writable(out)
            self.assertTrue(os.path.exists(out))

    def test_unwritable_path_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'no-such-dir', 'out.yaml')
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                with self.assertRaises(SystemExit) as cm:
                    MOD._check_output_writable(out)
            self.assertEqual(cm.exception.code, 1)
            self.assertIn('Cannot write output file', buf.getvalue())


if __name__ == '__main__':
    unittest.main()

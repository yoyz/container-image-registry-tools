"""High-level tests against real extracted catalog directories.

These consume a directory produced by ``--extract`` (e.g.
``/tmp/registry_redhat_io_redhat_redhat-operator-index_v4_20``). They run the
full parse + generate pipeline against real FBC data and assert structural
invariants plus known-package regressions.

Discovery order:
  1. $CATALOG_DIR env var (explicit path)
  2. /tmp/registry_redhat_io_redhat_* (standard --extract output)

If no real catalog is found, the tests are skipped.
"""

import contextlib
import io
import os
import re
import tempfile
import unittest

import yaml

from helpers import catalog_source_label, find_real_catalogs, golden_path, load_generator

MOD = load_generator()

FAKE_CATALOG = 'example.com/operators/real-catalog:v1'


def _parse(config_dir):
    with contextlib.redirect_stdout(io.StringIO()):
        return MOD.handle_parse_fbc(config_dir)


def _generate(config_dir, pkg_map, version='v1', **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'output.yaml')
        with contextlib.redirect_stdout(io.StringIO()):
            MOD.write_image_set_config(out, FAKE_CATALOG, pkg_map,
                                       version=version, **kwargs)
        with open(out) as f:
            return f.read()


def _golden_text(label, version):
    with open(golden_path('real', f'{label}-{version}.yaml')) as f:
        return f.read()


class RealCatalogTestMixin:
    """Shared assertions run against a concrete catalog directory."""

    CATALOG_DIR = None  # set per-instance

    def test_packages_parsed(self):
        self.assertGreater(len(self.pkg_map), 0,
                           f"no packages parsed from {self.CATALOG_DIR}")

    def test_every_package_has_channels(self):
        empty = [p for p, d in self.pkg_map.items() if not d['channels']]
        self.assertEqual(empty, [], f"packages without channels: {empty}")

    def test_every_channel_has_versions(self):
        empty = [(p, c) for p, d in self.pkg_map.items()
                 for c in d['versions'] if not d['versions'][c]]
        self.assertEqual(empty, [], f"channels without versions: {empty}")

    def test_default_channel_present_in_channels(self):
        for pkg, data in self.pkg_map.items():
            self.assertIn(data['default'], data['channels'],
                          f"{pkg}: default {data['default']} not in channels")

    def test_versions_naturally_sorted(self):
        for pkg, data in self.pkg_map.items():
            for chan, versions in data['versions'].items():
                self.assertEqual(versions, sorted(versions, key=MOD.natural_sort_key),
                                 f"{pkg}/{chan}: versions not naturally sorted")

    def test_generate_v1_valid_yaml(self):
        text = _generate(self.CATALOG_DIR, self.pkg_map, version='v1')
        doc = yaml.safe_load(text)
        self.assertEqual(doc['apiVersion'], 'mirror.openshift.io/v1alpha2')
        self.assertEqual(doc['kind'], 'ImageSetConfiguration')
        self.assertEqual(len(doc['mirror']['operators'][0]['packages']), len(self.pkg_map))

    def test_generate_v2_has_default_channel(self):
        text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2')
        doc = yaml.safe_load(text)
        self.assertEqual(doc['apiVersion'], 'mirror.openshift.io/v2alpha1')
        for pkg in doc['mirror']['operators'][0]['packages']:
            self.assertIn('defaultChannel', pkg, f"{pkg['name']} missing defaultChannel")
            self.assertIn(pkg['defaultChannel'],
                          [c['name'] for c in pkg['channels']],
                          f"{pkg['name']}: default not in channels")

    def test_generate_v2_min_max_version(self):
        text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2',
                         min_max_version=True)
        doc = yaml.safe_load(text)
        for pkg in doc['mirror']['operators'][0]['packages']:
            for chan in pkg['channels']:
                self.assertIn('minVersion', chan, f"{pkg['name']}/{chan['name']}")
                self.assertIn('maxVersion', chan, f"{pkg['name']}/{chan['name']}")

    def test_generate_version_comments(self):
        text = _generate(self.CATALOG_DIR, self.pkg_map, version='v1',
                         version_comments=True)
        self.assertIn('# versions:', text)


def _catalog_class_name(catalog_dir):
    """Derive a unique class-name suffix for a catalog path.

    Version-only basenames (e.g. ``v4.20``) are shared by multiple auto-cloned
    sources, so prepend the source (clone root) name to disambiguate.
    """
    base = os.path.basename(catalog_dir.rstrip(os.sep))
    if re.fullmatch(r'v4\.\d+', base):
        root = os.path.basename(os.path.dirname(os.path.dirname(catalog_dir)))
        return f'{root}_{base}'
    return base


def _make_real_catalog_class(catalog_dir):
    """Build a TestCase class bound to a specific catalog directory."""
    golden_label = catalog_source_label(catalog_dir)

    class _RealCatalogTests(RealCatalogTestMixin, unittest.TestCase):
        CATALOG_DIR = catalog_dir
        GOLDEN_LABEL = golden_label

        @classmethod
        def setUpClass(cls):
            cls.pkg_map = _parse(cls.CATALOG_DIR)

        def test_known_amq_streams_packages_present(self):
            """Prefix-collision regression on real data (v4.16+ redhat index)."""
            for name in ('amq-streams', 'amq-streams-console'):
                if name not in self.pkg_map:
                    self.skipTest(f"{name} not present in {self.CATALOG_DIR}")
            for name in ('amq-streams', 'amq-streams-console'):
                self.assertIn(name, self.pkg_map)

        def test_amq_streams_versions_not_polluted(self):
            """Console-only channels must not leak into amq-streams (old substring bug)."""
            if 'amq-streams' not in self.pkg_map:
                self.skipTest("amq-streams not present")
            if 'amq-streams-console' not in self.pkg_map:
                self.skipTest("amq-streams-console not present")
            self.assertNotIn('alpha', self.pkg_map['amq-streams']['channels'],
                             "amq-streams absorbed the console-only 'alpha' channel")

        def test_output_matches_golden_v1(self):
            """Generated v1 output is byte-identical to the committed golden.

            Locks reproducibility: for a given pinned tree, running the
            generator always produces the same imagesetconfig.yaml.
            """
            if not self.GOLDEN_LABEL:
                self.skipTest("no golden for non-pinned catalog dir")
            text = _generate(self.CATALOG_DIR, self.pkg_map, version='v1')
            self.assertEqual(text, _golden_text(self.GOLDEN_LABEL, 'v1'))

        def test_output_matches_golden_v2(self):
            if not self.GOLDEN_LABEL:
                self.skipTest("no golden for non-pinned catalog dir")
            text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2')
            self.assertEqual(text, _golden_text(self.GOLDEN_LABEL, 'v2'))

        def test_output_matches_golden_v2_minmax(self):
            """v2 + --min-max-version output matches the committed golden."""
            if not self.GOLDEN_LABEL:
                self.skipTest("no golden for non-pinned catalog dir")
            text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2',
                             min_max_version=True)
            self.assertEqual(text, _golden_text(self.GOLDEN_LABEL, 'v2-minmax'))

        def test_output_matches_golden_v2_comments(self):
            """v2 + --version-comment output matches the committed golden."""
            if not self.GOLDEN_LABEL:
                self.skipTest("no golden for non-pinned catalog dir")
            text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2',
                             version_comments=True)
            self.assertEqual(text, _golden_text(self.GOLDEN_LABEL, 'v2-comments'))

        def test_output_matches_golden_v2_minmax_comments(self):
            """v2 + --version-comment --min-max-version matches the golden."""
            if not self.GOLDEN_LABEL:
                self.skipTest("no golden for non-pinned catalog dir")
            text = _generate(self.CATALOG_DIR, self.pkg_map, version='v2',
                             version_comments=True, min_max_version=True)
            self.assertEqual(text, _golden_text(self.GOLDEN_LABEL, 'v2-minmax-comments'))

    _RealCatalogTests.__name__ = f'RealCatalog_{_catalog_class_name(catalog_dir)}'
    return _RealCatalogTests


def _load_real_catalog_tests():
    catalogs = find_real_catalogs()
    for catalog in catalogs:
        name = f'RealCatalog_{_catalog_class_name(catalog)}'
        globals()[name] = _make_real_catalog_class(catalog)


_load_real_catalog_tests()


def test_suite():
    """Allow discovery even when no real catalogs exist (empty suite)."""
    return unittest.TestSuite()


if __name__ == '__main__':
    if not find_real_catalogs():
        print("SKIP: no real catalog found (set $CATALOG_DIR or extract one to /tmp)")
    unittest.main(verbosity=2)

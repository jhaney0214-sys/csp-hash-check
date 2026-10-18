"""The checker against what a browser did: python -m unittest test_browser_cases

browser-cases/pages/ holds one small page per question (built by
browser-cases/build.py), and browser-cases/observed.json records what a real
browser did with each piece of inline code on them. For every mark the
browser blocked, the checker must report an error on that line; for every
mark that ran, or that could never run at all, it must report none.
"""

import json
import os
import re
import shutil
import tempfile
import unittest

import csp_hash_check as c

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "browser-cases")
OBSERVED = json.load(open(os.path.join(CASES, "observed.json"), encoding="utf-8"))
MARK = re.compile(r"dataset\.(\w+)")


def verdicts(name):
    """{mark: True if the checker reports an error on its line}."""
    # Bytes, read as latin-1: the marks are ASCII, and one page is windows-1252.
    with open(os.path.join(CASES, "pages", name + ".html"), "rb") as fh:
        lines = fh.read().decode("latin-1").split("\n")
    root = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join(CASES, "pages", name + ".html"), os.path.join(root, "index.html"))
        errors, _, _, _ = c.check(root, styles=False)
    finally:
        shutil.rmtree(root)
    flagged = {line for _, line, _ in errors}
    out, marked = {}, {}
    for number, text in enumerate(lines, 1):
        for mark in MARK.findall(text):
            out[mark] = out.get(mark, False) or number in flagged
            marked.setdefault(number, []).append(mark)
    # An error on a line with no mark is about code the browser has no
    # opinion on here, such as a script cut short at the wrong </script>.
    out["(an unmarked line)"] = sorted(line for line in flagged if line not in marked)
    return out


class AgreesWithTheBrowser(unittest.TestCase):
    pass


def _make(name, observed):
    def test(self):
        found = verdicts(name)
        self.assertEqual(found.pop("(an unmarked line)"), [],
                         "%s: the checker reports lines no mark is on" % name)
        for mark, what in observed.items():
            self.assertIn(mark, found, "%s: no line marks %r" % (name, mark))
            self.assertEqual(found[mark], what == "blocked",
                             "%s: the browser says %r is %s; the checker %s"
                             % (name, mark, what, "reports it" if found[mark] else "says nothing"))
    return test


for _name, _observed in OBSERVED["cases"].items():
    setattr(AgreesWithTheBrowser, "test_" + _name.replace("-", "_"), _make(_name, _observed))


if __name__ == "__main__":
    unittest.main()

"""Tests: python -m unittest test_csp_hash_check"""

import os
import shutil
import tempfile
import unittest

import csp_hash_check as c

SCRIPT = "\n  console.log('hello');\n"
HASH = c.digest(SCRIPT)


class Site(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def page(self, rel, html):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(html)

    def headers(self, text):
        with open(os.path.join(self.root, "_headers"), "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_check(self):
        return c.check(self.root)


class TheHash(unittest.TestCase):
    def test_it_is_the_browsers_hash(self):
        # The example from the CSP specification: alert('Hello, world.');
        self.assertEqual(c.digest("alert('Hello, world.');"),
                         "'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng='")

    def test_whitespace_and_line_endings_count(self):
        self.assertNotEqual(c.digest("a\n"), c.digest("a\r\n"))
        self.assertNotEqual(c.digest("a"), c.digest(" a"))


class Scripts(Site):
    def test_an_allowed_script_passes(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % HASH)
        errors, warnings, _, pages = self.run_check()
        self.assertEqual((errors, warnings, pages), ([], [], 1))

    def test_a_page_saved_with_crlf_needs_the_hash_of_its_lf_text(self):
        # The HTML parser turns CRLF into LF before hashing; a browser refused
        # the CRLF hash and named the LF one (2026-10-18). Before that, this
        # check failed every CRLF page and suggested the hash the browser refuses.
        self.page("index.html", "<script>%s</script>" % SCRIPT.replace("\n", "\r\n"))
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % HASH)
        errors, warnings, _, _ = self.run_check()
        self.assertEqual((errors, warnings), ([], []))
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n"
                     % c.digest(SCRIPT.replace("\n", "\r\n")))
        errors, _, _, _ = self.run_check()
        self.assertEqual(len(errors), 1)
        self.assertIn(HASH, errors[0][2])

    def test_a_sha384_or_sha512_hash_allows_it_and_is_not_stale(self):
        # CSP accepts all three algorithms; only sha256 was recognised before 2026-10-18,
        # so a sha384 policy failed every page and called its own hash stale.
        for algorithm in ("sha384", "sha512"):
            self.page("index.html", "<script>%s</script>" % SCRIPT)
            self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % c.digest(SCRIPT, algorithm))
            errors, warnings, _, _ = self.run_check()
            self.assertEqual((errors, warnings), ([], []), algorithm)

    def test_the_algorithm_name_is_case_insensitive_but_the_hash_is_not(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        upper = HASH.replace("'sha256-", "'SHA256-")
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % upper)
        self.assertEqual(self.run_check()[:2], ([], []))
        body = HASH[len("'sha256-"):-1]
        self.headers("/*\n  Content-Security-Policy: script-src 'sha256-%s'\n" % body.swapcase())
        self.assertEqual(len(self.run_check()[0]), 1)

    def test_a_changed_script_fails_and_names_its_new_hash(self):
        self.page("index.html", "<p>\n<script>%s// edited\n</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % HASH)
        errors, warnings, _, _ = self.run_check()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][1], 2)                       # the line of the script
        self.assertIn(c.digest(SCRIPT + "// edited\n"), errors[0][2])
        self.assertEqual(len(warnings), 1)                      # the old hash is now stale

    def test_external_scripts_and_data_blocks_are_not_inline_scripts(self):
        self.page("index.html", '<script src="app.js"></script>'
                                '<script type="application/ld+json">{"@type": "Thing"}</script>'
                                '<script type="text/template"><b>x</b></script>')
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, _, _ = self.run_check()
        self.assertEqual(errors, [])

    def test_a_module_script_is_checked(self):
        self.page("index.html", '<script type="module">%s</script>' % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        self.assertEqual(len(self.run_check()[0]), 1)

    def test_default_src_governs_when_script_src_is_absent(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: default-src 'none'\n")
        self.assertEqual(len(self.run_check()[0]), 1)


class Policies(Site):
    def test_unsafe_inline_allows_scripts_until_a_hash_is_present(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline'\n")
        self.assertEqual(self.run_check()[0], [])
        # A browser ignores 'unsafe-inline' once a hash or nonce is listed.
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline' 'sha256-AAAA'\n")
        self.assertEqual(len(self.run_check()[0]), 1)

    def test_a_meta_policy_is_enforced_too(self):
        self.page("index.html", '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
                                "<script>%s</script>" % SCRIPT)
        errors, _, _, _ = self.run_check()
        self.assertEqual(len(errors), 1)
        self.assertIn("<meta>", errors[0][2])

    def test_every_policy_must_allow_it(self):
        self.page("index.html", '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
                                "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % HASH)
        self.assertEqual(len(self.run_check()[0]), 1)           # the meta policy still blocks it

    def test_a_nonce_is_noted_not_judged(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'nonce-abc'\n")
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertTrue(any("nonce" in n[2] for n in notes))

    def test_a_page_with_no_policy_is_noted(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertIn("no Content-Security-Policy", notes[0][2])


class Paths(Site):
    def test_patterns_follow_the_served_url(self):
        self.page("blog/post.html", "<script>%s</script>" % SCRIPT)
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/blog/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, notes, _ = self.run_check()
        self.assertEqual([e[0].replace(os.sep, "/") for e in errors], ["blog/post.html"])
        self.assertTrue(any(n[0] == "index.html" for n in notes))

    def test_a_placeholder_matches_one_segment(self):
        self.assertTrue(c.matches("/posts/:slug", "/posts/hello"))
        self.assertFalse(c.matches("/posts/:slug", "/posts/a/b"))

    def test_pretty_urls_are_matched(self):
        self.assertIn("/about", c.url_paths("about.html"))
        self.assertIn("/docs/", c.url_paths(os.path.join("docs", "index.html")))


class Handlers(Site):
    def test_an_inline_handler_is_blocked_by_a_hash_policy(self):
        self.page("index.html", '<form onsubmit="return false"></form>')
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, _, _ = self.run_check()
        self.assertEqual(len(errors), 1)
        self.assertIn("onsubmit", errors[0][2])

    def test_unsafe_hashes_needs_the_handlers_own_hash(self):
        # Until 1.2 any 'unsafe-hashes' passed every handler; a browser runs
        # only the handlers whose hash is listed (browser-cases/unsafe-hashes-*).
        self.page("index.html", '<button onclick="go()">x</button>')
        self.headers("/*\n  Content-Security-Policy: script-src 'self' 'unsafe-hashes' 'sha256-AAAA'\n")
        errors = self.run_check()[0]
        self.assertEqual(len(errors), 1)
        self.assertIn(c.digest("go()"), errors[0][2])           # and names the hash to add
        self.headers("/*\n  Content-Security-Policy: script-src 'self' 'unsafe-hashes' %s\n" % c.digest("go()"))
        self.assertEqual(self.run_check()[0], [])
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline'\n")
        self.assertEqual(self.run_check()[0], [])

    def test_strict_dynamic_switches_unsafe_inline_off(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline' 'strict-dynamic'\n")
        self.assertEqual(len(self.run_check()[0]), 1)

    def test_a_javascript_link_is_checked(self):
        self.page("index.html", '<a href="javascript:void(go())">x</a>')
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors = self.run_check()[0]
        self.assertEqual(len(errors), 1)
        self.assertIn("javascript: URL in href=", errors[0][2])

    def test_markup_inside_a_script_is_not_a_handler(self):
        js = "var s = '<img onerror=\"x()\" style=\"color:red\">';"
        self.page("index.html", "<script>%s</script>" % js)
        self.headers("/*\n  Content-Security-Policy: script-src %s; style-src 'self'\n" % c.digest(js))
        self.assertEqual(c.check(self.root, styles=True)[0], [])

    def test_a_meta_policy_governs_only_what_follows_it_in_head(self):
        self.page("index.html", "<script>%s</script>"
                                '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">'
                                "<script>%s</script>" % (SCRIPT, SCRIPT + " "))
        errors = self.run_check()[0]
        self.assertEqual([e[1] for e in errors], [3])          # the second script; SCRIPT spans lines 1-3
        self.page("index.html", "<body><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\">"
                                "<script>%s</script>" % SCRIPT)
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertTrue(any("outside <head>" in n[2] for n in notes))


class Stale(Site):
    def test_an_unused_hash_is_a_warning_or_an_error_on_request(self):
        self.page("index.html", "<p>no scripts</p>")
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % HASH)
        errors, warnings, _, _ = self.run_check()
        self.assertEqual((len(errors), len(warnings)), (0, 1))
        self.assertEqual(c.main([self.root]), 0)
        self.assertEqual(c.main([self.root, "--fail-on-stale"]), 1)


CSS = "\n  body { margin: 0 }\n"
CSS_HASH = c.digest(CSS)


class Styles(Site):
    """Off unless asked for: a site that hashes scripts may allow inline styles on purpose."""

    def policy(self, style_src):
        self.headers("/*\n  Content-Security-Policy: script-src 'self'; style-src %s\n" % style_src)

    def test_styles_are_not_looked_at_by_default(self):
        self.page("index.html", "<style>%s</style><p style=\"color:red\">x</p>" % CSS)
        self.policy("'self'")
        errors, warnings, _, _ = c.check(self.root)
        self.assertEqual((errors, warnings), ([], []))
        self.assertEqual(c.main([self.root]), 0)
        self.assertEqual(c.main([self.root, "--styles"]), 1)

    def test_a_hashed_style_element_passes_and_an_edited_one_is_told_its_hash(self):
        self.page("index.html", "<style>%s</style>" % CSS)
        self.page("other.html", "<style>%s </style>" % CSS)
        self.policy("'self' %s" % CSS_HASH)
        errors, warnings, _, _ = c.check(self.root, styles=True)
        self.assertEqual(warnings, [])
        self.assertEqual([e[0] for e in errors], ["other.html"])
        self.assertIn(c.digest(CSS + " "), errors[0][2])
        self.assertIn("style-src", errors[0][2])

    def test_a_hash_does_not_cover_a_style_attribute(self):
        self.page("index.html", "<style>%s</style><p style=\"color:red\">x</p>" % CSS)
        self.policy("'self' %s" % CSS_HASH)
        errors, _, _, _ = c.check(self.root, styles=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("style= attribute", errors[0][2])

    def test_unsafe_inline_allows_both_until_a_hash_sits_beside_it(self):
        self.page("index.html", "<style>%s</style><p style=\"color:red\">x</p>" % CSS)
        self.policy("'self' 'unsafe-inline'")
        self.assertEqual(c.check(self.root, styles=True)[0], [])
        self.policy("'self' 'unsafe-inline' %s" % c.digest("other"))
        self.assertEqual(len(c.check(self.root, styles=True)[0]), 2)

    def test_styles_fall_back_to_default_src(self):
        self.page("index.html", "<style>%s</style>" % CSS)
        self.headers("/*\n  Content-Security-Policy: default-src 'self'\n")
        errors, _, _, _ = c.check(self.root, styles=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("default-src", errors[0][2])

    def test_a_style_hash_nothing_uses_is_stale(self):
        self.page("index.html", "<p>plain</p>")
        self.policy("'self' %s" % CSS_HASH)
        _, warnings, _, _ = c.check(self.root, styles=True)
        self.assertEqual(len(warnings), 1)
        self.assertIn("matches no inline style", warnings[0][2])


if __name__ == "__main__":
    unittest.main()

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

    def test_a_script_without_the_files_nonce_is_blocked(self):
        # Until 1.2 this was only noted, as if a server added the nonce per
        # response; a policy read from a file is the same on every response,
        # and differential fuzzing in Chrome showed such scripts blocked.
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'nonce-abc'\n")
        errors = self.run_check()[0]
        self.assertEqual(len(errors), 1)
        self.assertIn("no nonce attribute", errors[0][2])

    def test_a_template_script_is_a_notice_not_an_error(self):
        self.page("index.html", "<template><script>%s</script></template>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertTrue(any(n[2].startswith("in <template>") and HASH in n[2] for n in notes))

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


class OtherHosts(Site):
    """Policies set in netlify.toml, vercel.json or firebase.json, found beside the site."""

    def write(self, name, text):
        with open(os.path.join(self.root, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_netlify_toml_with_a_multiline_policy(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("tomllib needs Python 3.11")
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.page("blog/post.html", "<script>%s// edited\n</script>" % SCRIPT)
        self.write("netlify.toml", '[build]\n  publish = "."\n\n[[headers]]\n  for = "/*"\n  [headers.values]\n'
                                   "    Content-Security-Policy = '''\n      default-src 'self';\n"
                                   "      script-src %s\n    '''\n" % HASH)
        errors, warnings, _, _ = self.run_check()
        self.assertEqual([e[0].replace(os.sep, "/") for e in errors], ["blog/post.html"])
        self.assertIn("netlify.toml", errors[0][2])
        self.assertEqual(warnings, [])

    def test_vercel_json_and_its_path_patterns(self):
        import json
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.page("docs/a/b.html", "<script>%s</script>" % SCRIPT)
        self.write("vercel.json", json.dumps({"headers": [
            {"source": "/docs/:path*", "headers": [
                {"key": "Content-Security-Policy", "value": "script-src 'self'"}]}]}, indent=2))
        errors, _, notes, _ = self.run_check()
        self.assertEqual([e[0].replace(os.sep, "/") for e in errors], ["docs/a/b.html"])
        self.assertIn("vercel.json", errors[0][2])
        rx = __import__("re").compile(c.vercel_regex("/blog/:slug"))
        self.assertTrue(rx.match("/blog/hello"))
        self.assertFalse(rx.match("/blog/a/b"))
        rx = __import__("re").compile(c.vercel_regex("/(.*)"))
        self.assertTrue(rx.match("/anything/at/all"))
        rx = __import__("re").compile(c.vercel_regex("/docs/:path*"))
        self.assertTrue(rx.match("/docs") and rx.match("/docs/a/b"))

    def test_firebase_json_globs(self):
        import json
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.page("app/page.html", "<script>%s</script>" % SCRIPT)
        self.write("firebase.json", json.dumps({"hosting": {"public": ".", "headers": [
            {"source": "/app/**", "headers": [
                {"key": "Content-Security-Policy", "value": "script-src 'self'"}]}]}}, indent=2))
        errors, _, _, _ = self.run_check()
        self.assertEqual([e[0].replace(os.sep, "/") for e in errors], ["app/page.html"])
        rx = __import__("re").compile(c.glob_regex("**/*.@(html|htm)"))
        self.assertTrue(rx.search("/a/b/page.htm"))
        self.assertFalse(rx.search("/a/b/page.png"))


class Options(Site):
    def test_exclude_skips_a_folder_or_a_glob(self):
        for rel in ("index.html", "drafts/a.html", "vendor/lib/demo.html", "notes.htm"):
            self.page(rel, "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, _, pages = c.check(self.root, exclude=["drafts", "vendor/*", "*.htm"])
        self.assertEqual(([e[0] for e in errors], pages), (["index.html"], 1))

    def test_json_writes_every_finding(self):
        import json
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self' %s\n" % c.digest("old"))
        out = os.path.join(self.root, "report.json")
        self.assertEqual(c.main([self.root, "--json", out]), 1)
        with open(out, encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertEqual((record["pages"], record["passed"]), (1, False))
        self.assertEqual(sorted(f["level"] for f in record["findings"]), ["error", "warning"])
        self.assertIn(HASH, record["findings"][0]["message"])


class Inherited(Site):
    def test_an_escaped_srcdoc_script_is_checked_against_the_page(self):
        inner = "parent.go()"
        self.page("index.html", '<iframe srcdoc="&lt;script&gt;%s&lt;/script&gt;"></iframe>' % inner)
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors = self.run_check()[0]
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0][2].startswith("in <iframe srcdoc>"))
        self.assertIn(c.digest(inner), errors[0][2])
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % c.digest(inner))
        self.assertEqual(self.run_check()[:2], ([], []))     # and its hash is not stale

    def test_a_nonce_in_the_file_is_judged_and_warned_about(self):
        self.page("index.html", '<script nonce="abc">a()</script>\n<script nonce="xyz">b()</script>')
        self.headers("/*\n  Content-Security-Policy: script-src 'nonce-abc'\n")
        errors, warnings, _, _ = self.run_check()
        self.assertEqual([e[1] for e in errors], [2])
        self.assertEqual(len(warnings), 1)
        self.assertIn("protects nothing", warnings[0][2])

    def test_an_attribute_that_only_starts_with_on_is_not_a_handler(self):
        self.page("index.html", '<div onboarding="step-1" onclick="go()">x</div>')
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        errors, _, notes, _ = self.run_check()
        self.assertEqual(len(errors), 1)
        self.assertIn("onclick", errors[0][2])
        self.assertTrue(any("onboarding=" in n[2] for n in notes))


class Suggest(Site):
    def test_it_lists_each_pages_hashes_and_one_line_that_allows_them_all(self):
        self.page("index.html", "<script>a()</script>\n<script>b()</script>\n<script>c()</script>\n"
                                '<button onclick="go()">x</button>')
        self.page("blog/post.html", "<script>a()</script>")
        text = c.suggestion(self.root)
        rows = [l for l in text.splitlines() if ", line " in l]
        self.assertEqual(len(rows), 5)
        self.assertEqual(sum(1 for l in rows if l.startswith("index.html")), 1)  # named once, on its first row
        directive = [l for l in text.splitlines() if l.startswith("script-src")][0]
        self.assertIn("'unsafe-hashes'", directive)
        for code in ("a()", "b()", "c()", "go()"):
            self.assertEqual(directive.count(c.digest(code)), 1)
        # And the line it suggests passes the check.
        self.headers("/*\n  Content-Security-Policy: %s\n" % directive)
        errors, warnings, _, _ = self.run_check()
        self.assertEqual((errors, warnings), ([], []))

    def test_a_site_with_no_inline_code_needs_no_hashes(self):
        self.page("index.html", "<p>plain</p>")
        self.assertIn("needs no hashes", c.suggestion(self.root))


class Prefilter(Site):
    """Pages with nothing a policy could block are not parsed; nothing real may slip past that."""

    def test_handlers_written_without_a_space_are_still_found(self):
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n")
        for html in ('<img/onerror=go()>', '<a href="x"onclick="go()">x</a>', "<a href='javascript:go()'>x</a>"):
            self.page("index.html", html)
            self.assertEqual(len(self.run_check()[0]), 1, html)

    def test_a_style_attribute_after_a_quote_is_found(self):
        self.headers("/*\n  Content-Security-Policy: style-src 'self'\n")
        self.page("index.html", '<p class="a"style="color:red">x</p>')
        self.assertEqual(len(c.check(self.root, styles=True)[0]), 1)


class Encodings(Site):
    """The hash is of the UTF-8 encoding of the text the browser decoded."""

    def raw_page(self, data):
        with open(os.path.join(self.root, "index.html"), "wb") as fh:
            fh.write(data)

    def test_a_windows_1252_page_is_decoded_not_fatal(self):
        js = "var café = 1;"
        self.raw_page(b'<meta charset="windows-1252"><script>' + js.encode("cp1252") + b"</script>")
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % c.digest(js))
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertTrue(any("windows-1252" in n[2] for n in notes))

    def test_latin1_is_read_as_windows_1252_as_a_browser_does(self):
        js = "var x = '’';"                    # 0x92 in windows-1252, a control code in latin-1
        self.raw_page(b'<meta charset="iso-8859-1"><script>' + js.encode("cp1252") + b"</script>")
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % c.digest(js))
        self.assertEqual(self.run_check()[0], [])

    def test_no_charset_and_not_utf8_is_guessed_and_said(self):
        self.raw_page(b"<script>var a = '\xe9';</script>")
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % c.digest("var a = 'é';"))
        errors, _, notes, _ = self.run_check()
        self.assertEqual(errors, [])
        self.assertTrue(any("declares no charset" in n[2] for n in notes))

    def test_a_utf8_bom_is_not_part_of_the_page(self):
        self.raw_page(b"\xef\xbb\xbf<script>" + SCRIPT.encode() + b"</script>")
        self.headers("/*\n  Content-Security-Policy: script-src %s\n" % HASH)
        errors, _, notes, _ = self.run_check()
        self.assertEqual((errors, notes), ([], []))


class HeaderFiles(Site):
    def test_cloudflares_detach_takes_the_policy_off(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.page("legacy/old.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'self'\n\n"
                     "/legacy/*\n  ! Content-Security-Policy\n")
        errors, _, notes, _ = self.run_check()
        self.assertEqual([e[0] for e in errors], ["index.html"])
        self.assertTrue(any(n[0].replace(os.sep, "/") == "legacy/old.html" for n in notes))

    def test_a_comma_joins_two_policies_and_both_are_enforced(self):
        self.page("index.html", "<script>%s</script>" % SCRIPT)
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline', script-src 'none'\n")
        self.assertEqual(len(self.run_check()[0]), 1)
        self.headers("/*\n  Content-Security-Policy: script-src 'unsafe-inline', img-src 'self'\n")
        self.assertEqual(self.run_check()[0], [])

    def test_a_stale_hash_is_reported_at_its_policys_line(self):
        self.page("index.html", "<p>none</p>")
        self.headers("# comment\n\n/*\n  X-Frame-Options: DENY\n  Content-Security-Policy: script-src %s\n" % HASH)
        _, warnings, _, _ = self.run_check()
        self.assertEqual([w[1] for w in warnings], [5])


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

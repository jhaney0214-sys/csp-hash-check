"""Write the browser cases: one small page per question about what a browser runs.

    python browser-cases/build.py        # writes browser-cases/pages/*.html

Each page carries its policy in a <meta> tag (or none), and every piece of
inline code on it marks the page when it runs: an inline script sets
data-<name> on <html>, a handler does the same from an image's onerror, a
javascript: link from a click. Open a page in a browser, click any link marked
"click", and read <html>'s data- attributes: present means it ran.

What each browser did is recorded by hand in observed.json, with the browser
and the date; test_browser_cases.py then requires the checker to agree with
every observation. The pages are the evidence, so they are committed.
"""

import base64
import hashlib
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
PAGES = HERE / "pages"


def sha(text):
    return "'sha256-%s'" % base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def mark(name):
    return "document.documentElement.dataset.%s='ran'" % name


def page(policy, body, head_extra=""):
    meta = ('<meta http-equiv="Content-Security-Policy" content="%s">\n' % policy) if policy else ""
    return ("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n%s%s</head>\n<body>\n%s\n</body>\n</html>\n"
            % (meta, head_extra, body))


def script(name):
    return "<script>%s</script>" % mark(name)


def handler(name, value=None):
    return '<img src="missing.png" alt="" onerror="%s">' % (value or mark(name))


CASES = {}


def case(name, html, expect, note):
    """`expect` maps each mark to what this file's author predicted (ran / blocked);
    observed.json, not this, is what the tests hold the checker to."""
    CASES[name] = {"expect": expect, "note": note}
    (PAGES / (name + ".html")).write_text(html, encoding="utf-8", newline="\n")


def build():
    PAGES.mkdir(exist_ok=True)
    s = mark("s")
    h = mark("h")

    case("strict-dynamic-unsafe-inline",
         page("script-src 'unsafe-inline' 'strict-dynamic'", script("s") + "\n" + handler("h")),
         {"s": "blocked", "h": "blocked"},
         "'strict-dynamic' switches 'unsafe-inline' off, for scripts and for handlers")

    case("strict-dynamic-hash",
         page("script-src 'strict-dynamic' %s" % sha(s), script("s")),
         {"s": "ran"}, "a hash still allows an inline script under 'strict-dynamic'")

    case("unsafe-hashes-without-the-handler-hash",
         page("script-src 'unsafe-hashes' %s" % sha(s), script("s") + "\n" + handler("h")),
         {"s": "ran", "h": "blocked"},
         "'unsafe-hashes' allows only handlers whose own hash is listed")

    case("unsafe-hashes-with-the-handler-hash",
         page("script-src 'unsafe-hashes' %s" % sha(h), handler("h")),
         {"h": "ran"}, "the handler's hash, over its attribute value")

    quoted = 'document.documentElement.dataset.q="ran"'
    case("unsafe-hashes-entity-decoded",
         page("script-src 'unsafe-hashes' %s" % sha(quoted),
              handler("q", quoted.replace('"', "&quot;"))),
         {"q": "ran"}, "the hash is of the attribute value after &quot; is decoded")

    # void(): a javascript: URL that returns a string replaces the document
    # with it, and the mark with it (the first run read as blocked for that).
    js_url = "javascript:void(%s)" % mark("j")
    case("javascript-url-hash-only",
         page("script-src %s" % sha(s), script("s") + '\n<a id="j" href="%s">click</a>' % js_url),
         {"s": "ran", "j": "blocked"}, "a javascript: link runs only under 'unsafe-inline'")

    case("javascript-url-unsafe-inline",
         page("script-src 'unsafe-inline'", '<a id="j" href="%s">click</a>' % js_url),
         {"j": "ran"}, "and does run under it")

    case("javascript-url-unsafe-hashes",
         page("script-src 'unsafe-hashes' %s" % sha(js_url), '<a id="j" href="%s">click</a>' % js_url),
         {"j": "blocked"}, "whether 'unsafe-hashes' and the URL's hash let a javascript: link run")

    case("meta-after-the-script",
         "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n%s\n"
         "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\">\n%s\n</head>\n<body></body>\n</html>\n"
         % (script("before"), script("after")),
         {"before": "ran", "after": "blocked"},
         "a meta policy governs only what is parsed after it")

    case("meta-in-the-body",
         "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n</head>\n<body>\n"
         "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\">\n%s\n</body>\n</html>\n"
         % script("s"),
         {"s": "ran"}, "a meta policy outside <head> is ignored")

    case("meta-report-only",
         "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
         "<meta http-equiv=\"Content-Security-Policy-Report-Only\" content=\"script-src 'none'\">\n</head>\n"
         "<body>\n%s\n</body>\n</html>\n" % script("s"),
         {"s": "ran"}, "report-only in a meta tag is ignored altogether")

    case("meta-comma",
         page("script-src 'none', script-src 'unsafe-inline'", script("s")),
         {"s": "blocked"},
         "a comma in a <meta> policy: two policies (blocked), or one with stray tokens?")

    case("meta-comma-reversed",
         page("script-src 'unsafe-inline', script-src 'none'", script("s")),
         {"s": "blocked"},
         "the same, the other way round: blocked again means both halves are enforced")

    case("noscript",
         page("script-src %s" % sha(s), script("s") + "\n<noscript>%s</noscript>" % script("n")),
         {"s": "ran", "n": "blocked"},
         "a script inside <noscript> is text when scripting is on; it never runs (and is never checked)")

    case("comment",
         page("script-src %s" % sha(s), script("s") + "\n<!-- %s -->" % script("c")),
         {"s": "ran", "c": "blocked"}, "a script inside a comment never runs")

    js = "var el = '<img onerror=\"x()\" style=\"color:red\">';" + mark("s")
    case("handler-text-inside-a-script",
         page("script-src %s" % sha(js), "<script>%s</script>" % js),
         {"s": "ran"}, "an onerror= inside a script's string is not a handler")

    legacy = "text/jscript"
    case("legacy-javascript-type",
         page("script-src %s" % sha(s), '<script type="%s">%s</script>' % (legacy, mark("t")) + "\n" + script("s")),
         {"s": "ran", "t": "blocked"},
         "text/jscript is a JavaScript type, so it runs and is checked like any script")

    case("legacy-javascript-type-no-policy",
         page(None, '<script type="%s">%s</script>' % (legacy, mark("t"))),
         {"t": "ran"}, "with no policy at all: does text/jscript run?")

    case("type-with-parameters",
         page(None, '<script type="text/javascript; charset=utf-8">%s</script>' % mark("p")),
         {"p": "blocked"},
         "a type with parameters is not a JavaScript MIME type essence match; with no policy at all, it does not run")

    case("static-nonce",
         page("script-src 'nonce-abc123'", '<script nonce="abc123">%s</script>' % mark("s")
              + "\n" + '<script nonce="other">%s</script>' % mark("o")),
         {"s": "ran", "o": "blocked"},
         "a nonce written into the page and the policy matches; it is no protection, but it runs")

    case("none-beside-a-hash",
         page("script-src 'none' %s" % sha(s), script("s")),
         {"s": "ran"}, "'none' is ignored once anything else is listed")

    inner = "<script>parent.document.documentElement.dataset.%s='ran'</script>"
    case("srcdoc-inherits-the-policy",
         page("script-src %s" % sha("parent.document.documentElement.dataset.d='ran'"),
              '<iframe srcdoc="%s"></iframe>\n<iframe srcdoc="%s"></iframe>'
              % ((inner % "d").replace('"', "&quot;"), (inner % "x").replace('"', "&quot;"))),
         {"d": "ran", "x": "blocked"},
         "an <iframe srcdoc> document inherits the page's policy; its scripts need their hashes there")

    # The page's bytes are windows-1252; the policy holds the hash of the
    # script's text encoded as UTF-8, which is what CSP says a browser hashes.
    latin = "var café = 1;" + mark("e")
    html = page("script-src %s" % sha(latin), "<script>%s</script>" % latin).replace(
        '<meta charset="utf-8">', '<meta charset="windows-1252">')
    CASES["windows-1252-page"] = {"expect": {"e": "ran"},
                                  "note": "a windows-1252 page: the hash is of the UTF-8 text, not the file's bytes"}
    (PAGES / "windows-1252-page.html").write_bytes(html.encode("cp1252"))

    (HERE / "cases.json").write_text(json.dumps(CASES, indent=1) + "\n", encoding="utf-8", newline="\n")
    return CASES


if __name__ == "__main__":
    print("%d cases -> %s" % (len(build()), PAGES))

"""Differential fuzzing: random pages, a browser's verdict, the checker's verdict.

    python browser-cases/fuzz.py make 300 --seed 1   # writes pages/fuzz/ and fuzz-manifest.json
    (load pages/fuzz/ in a browser with fuzz-runner.js; save what it prints as fuzz-results.json)
    python browser-cases/fuzz.py compare             # every disagreement, page by page

Each page mixes snippets of inline code (scripts with comments, nested tags,
entities, CRLF; unusual types; SVG scripts; handlers; javascript: links;
<noscript>, comments and <template>) under a random policy in a <meta> tag,
and has a twin with no policy. The browser decides; nothing here predicts it:

  - ran on the twin and not under the policy: blocked, so the checker must
    report that line;
  - ran under the policy, or never ran at all: the checker must not.

The hashes the generator lists are its own guesses at what a browser hashes,
right or wrong; a wrong guess only means the browser blocks the snippet, and
the checker has to agree. Disagreements become cases in build.py.
"""

import base64
import hashlib
import json
import os
import random
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pages", "fuzz")
MANIFEST = os.path.join(HERE, "fuzz-manifest.json")
RESULTS = os.path.join(HERE, "fuzz-results.json")
sys.path.insert(0, os.path.dirname(HERE))
# Round two (--styles) adds inline styles, srcdoc, nonces, foreignObject and
# more; a style mark is read from the marked element's computed width.
STYLES = "--styles" in sys.argv


def sha(text):
    return "'sha256-%s'" % base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def mark(m):
    return "document.documentElement.dataset.%s='ran'" % m


def snippet(r, m):
    """(html, guessed source text or None, kind) for one piece of inline code setting mark m."""
    body = mark(m)
    choice = r.randrange(24 if STYLES else 16)
    if choice == 16:
        css = "#%s{display:block;width:7px}" % m
        return '<style>%s</style><i id="%s"></i>' % (css, m), css, "style"
    if choice == 17:
        css = "display:block;width:7px"
        return '<i id="%s" style="%s"></i>' % (m, css), css, "style-attr"
    if choice == 18:
        inner = "parent.document.documentElement.dataset.%s='ran'" % m
        return '<iframe srcdoc="<script>%s</script>"></iframe>' % inner, inner, "script"
    if choice == 19:
        return '<script nonce="%s">%s</script>' % (r.choice(["x", "y"]), body), body, "script"
    if choice == 20:
        text = "/* &amp; */ %s" % body
        return "<svg><foreignObject><script>%s</script></foreignObject></svg>" % text, text, "script"
    if choice == 21:
        return "<SCRIPT>%s</SCRIPT >" % body, body, "script"
    if choice == 22:
        return '<img src="missing.png" alt="" onerror="%s" onerror="void 0">' % body, body, "handler"
    if choice == 23:
        text = "/* &amp; */ %s" % body
        return "<math><mtext><script>%s</script></mtext></math>" % text, text, "script"
    if choice == 0:
        return "<script>%s</script>" % body, body, "script"
    if choice == 1:
        text = '<!--\nvar s = "<script>x</script>";\n%s;\n//-->' % body
        return "<script>%s</script>" % text, text, "script"
    if choice == 2:
        text = "/* </scri" + "pt> */ %s" % body
        return "<script>%s</script>" % text.replace("</scri" + "pt>", "<\\/script>"), \
            text.replace("</scri" + "pt>", "<\\/script>"), "script"
    if choice == 3:
        t = r.choice(["module", "text/jscript", "application/x-javascript", "text/plain",
                      "text/javascript; charset=utf-8", "", "JavaScript", "TEXT/JAVASCRIPT"])
        return '<script type="%s">%s</script>' % (t, body), body, "script"
    if choice == 4:
        return '<script language="%s">%s</script>' % (r.choice(["javascript", "vbscript", "JavaScript1.2"]), body), \
            body, "script"
    if choice == 5:
        text = "if (1 &lt; 2) { %s }" % body
        return "<svg><script>%s</script></svg>" % text, "if (1 < 2) { %s }" % body, "script"
    if choice == 6:
        text = "<![CDATA[ %s ]]>" % body
        return "<svg><script>%s</script></svg>" % text, " %s " % body, "script"
    if choice == 7:
        value = body.replace("'", r.choice(["&#39;", "&apos;", "'"]))
        return '<img src="missing.png" alt="" %s="%s">' % (r.choice(["onerror", "ONERROR", "OnError"]), value), \
            body, "handler"
    if choice == 8:
        return "<img/src=missing.png/onerror=\"%s\">" % body, body, "handler"
    if choice == 9:
        url = "%sjavascript:void(%s)" % (r.choice(["", " ", "\t"]), body)
        return '<a id="j%s" href="%s">click</a>' % (m, url), url.strip(), "url"
    if choice == 10:
        return "<noscript><script>%s</script></noscript>" % body, body, "script"
    if choice == 11:
        return "<!-- <script>%s</script> -->" % body, body, "script"
    if choice == 12:
        return "<template><script>%s</script></template>" % body, body, "script"
    if choice == 13:
        return "<textarea><script>%s</script></textarea>" % body, body, "script"
    if choice == 14:
        text = "\n  %s;\n" % body
        return "<script>%s</script>" % text.replace("\n", "\r\n"), text, "script"
    return '<script>%s</script>' % ("var a = '&amp;'; " + body), "var a = '&amp;'; " + body, "script"


def policy(r, guesses):
    parts = []
    for text, kind in guesses:
        if text is not None and r.random() < 0.6:
            parts.append(sha(text))
    keywords = ["'unsafe-inline'", "'strict-dynamic'", "'unsafe-hashes'", "'none'", "'self'", "'nonce-x'"]
    parts += [k for k in keywords if r.random() < 0.25]
    r.shuffle(parts)
    directive = r.choice(["script-src", "script-src", "default-src", "script-src-elem", "script-src-attr"])
    value = "%s %s" % (directive, " ".join(parts))
    if STYLES and r.random() < 0.7:
        extra = [p for p in parts if r.random() < 0.6]
        extra += [k for k in ("'unsafe-inline'", "'unsafe-hashes'", "'nonce-x'") if r.random() < 0.3]
        value += "; %s %s" % (r.choice(["style-src", "style-src-elem", "style-src-attr"]), " ".join(extra))
    if r.random() < 0.15:
        value += ", script-src 'unsafe-inline'"
    return value


def page(policy_value, snippets, crlf):
    meta = '<meta http-equiv="Content-Security-Policy" content="%s">\n' % policy_value if policy_value else ""
    html = "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n%s</head>\n<body>\n%s\n</body>\n</html>\n" \
        % (meta, "\n".join(snippets))
    return html.replace("\n", "\r\n") if crlf else html


def make(count, seed):
    r = random.Random(seed)
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    manifest = {}
    for n in range(count):
        marks = ["m%d" % k for k in range(r.randint(1, 4))]
        made = [snippet(r, m) for m in marks]
        value = policy(r, [(text, kind) for _, text, kind in made])
        crlf = r.random() < 0.2
        name = "f%03d" % n
        for suffix, pv in (("", value), ("-free", None)):
            with open(os.path.join(OUT, name + suffix + ".html"), "w", encoding="utf-8", newline="") as fh:
                fh.write(page(pv, [h for h, _, _ in made], crlf))
        manifest[name] = {"marks": marks, "policy": value, "crlf": crlf}
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump({"seed": seed, "styles": STYLES, "pages": manifest}, fh, indent=1)
    print("%d pages (and their twins) -> %s" % (count, OUT))


def compare():
    import csp_hash_check as c
    import re
    import tempfile
    loaded = json.load(open(MANIFEST, encoding="utf-8"))
    manifest, styles = loaded["pages"], loaded.get("styles", False)
    results = json.load(open(RESULTS, encoding="utf-8"))
    bad = 0
    for name, info in sorted(manifest.items()):
        ran, free = set(results[name]), set(results[name + "-free"])
        root = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(OUT, name + ".html"), os.path.join(root, "index.html"))
            errors = c.check(root, styles=styles)[0]
        finally:
            shutil.rmtree(root)
        with open(os.path.join(OUT, name + ".html"), "rb") as fh:
            lines = fh.read().decode("utf-8").replace("\r\n", "\n").split("\n")
        where = {}
        for number, text in enumerate(lines, 1):
            for m in re.findall(r"dataset\.(m\d+)|id=\"(m\d+)\"", text):
                m = m[0] or m[1]
                where[m] = number
        # An error is reported at the line its element starts on; a script
        # spanning lines carries its mark further down, so an error belongs
        # to the first mark at or after its line.
        mark_lines = sorted(where.values())
        flagged = set()
        stray = []
        for _, line, _ in errors:
            after = [l for l in mark_lines if l >= line]
            (flagged.add(after[0]) if after else stray.append(line))
        problems = []
        for m in info["marks"]:
            blocked = m in free and m not in ran
            reported = where.get(m) in flagged
            if blocked != reported:
                problems.append("%s: browser %s, checker %s" % (
                    m, "blocked it" if blocked else ("ran it" if m in ran else "never runs it"),
                    "reports it" if reported else "says nothing"))
        if stray:
            problems.append("errors on unmarked lines %s" % stray)
        if problems:
            bad += 1
            print("%s  %s\n    policy: %s\n    %s" % (name, "CRLF" if info["crlf"] else "", info["policy"],
                                                    "\n    ".join(problems)))
    print("%d pages, %d disagree" % (len(manifest), bad))
    return 1 if bad else 0


def results_from(compact):
    """fuzz-results.json from the runner's compact string: two hex digits a
    page, low four bits the marks that ran under the policy, high four the
    marks that ran on the twin with none."""
    names = sorted(json.load(open(MANIFEST, encoding="utf-8"))["pages"])
    pairs = [int(compact[i:i + 2], 16) for i in range(0, len(compact), 2)]
    if len(pairs) != len(names):
        raise SystemExit("%d results for %d pages" % (len(pairs), len(names)))
    out = {}
    for name, bits in zip(names, pairs):
        out[name] = ["m%d" % k for k in range(4) if bits & (1 << k)]
        out[name + "-free"] = ["m%d" % k for k in range(4) if bits & (16 << k)]
    with open(RESULTS, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("%d pages' results -> %s" % (len(names), RESULTS))


if __name__ == "__main__":
    if sys.argv[1:2] == ["results"]:
        results_from(sys.argv[2])
    elif sys.argv[1:2] == ["make"]:
        seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
        make(int(sys.argv[2]), seed)
    elif sys.argv[1:2] == ["compare"]:
        sys.exit(compare())
    else:
        print(__doc__)

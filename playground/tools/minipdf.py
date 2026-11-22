"""A tiny PDF writer (standard library only) for seeded test documents.

Streams are left uncompressed on purpose, so you can open the files in a text editor and
see exactly where a token sits: in the page text, in a link annotation, or in the metadata.
Real-world PDFs are usually compressed; try the exercise with a "real" PDF library later.
"""


def _esc(s):
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(path, title, lines, link_url=None, link_line=None, metadata=None):
    """Write a one-page A4 PDF.

    title      heading printed at the top
    lines      body text lines
    link_url   if set, a clickable URI annotation is placed over line number `link_line`
               (the URL itself does not have to appear in the text)
    metadata   dict for the document information dictionary (Title, Author, Subject, Keywords ...)
    """
    top, lead = 770, 16
    content = ["BT", "/F1 16 Tf", "72 %d Td" % top, "(%s) Tj" % _esc(title), "ET", "BT", "/F1 11 Tf",
               "72 %d Td" % (top - 30), "%d TL" % lead]
    for ln in lines:
        content.append("(%s) Tj T*" % _esc(ln))
    content.append("ET")
    stream = "\n".join(content).encode("latin-1")

    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    annots = b" /Annots [6 0 R]" if link_url else b""
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R" + annots + b" >>")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    if link_url:
        y = top - 30 - lead * (link_line or 0)
        rect = "72 %d 400 %d" % (y - 4, y + 12)
        objs.append(("<< /Type /Annot /Subtype /Link /Rect [%s] /Border [0 0 0] "
                     "/A << /S /URI /URI (%s) >> >>" % (rect, _esc(link_url))).encode("latin-1"))
    else:
        objs.append(b"<< >>")  # placeholder keeps object numbers stable
    info = metadata or {}
    info_s = " ".join("/%s (%s)" % (k, _esc(str(v))) for k, v in info.items())
    objs.append(("<< %s >>" % info_s).encode("latin-1"))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, len(objs), xref)
    with open(path, "wb") as f:
        f.write(out)

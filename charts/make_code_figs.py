"""Code listings and console captures for Chapter 6, rendered as images."""
import inspect
import os
import sys

from PIL import Image, ImageDraw, ImageFont
from pygments import highlight
from pygments.formatters import ImageFormatter
from pygments.lexers import PythonLexer, get_lexer_by_name
from pygments.style import Style
from pygments.token import (Comment, Keyword, Name, Number, Operator, String, Text)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import hylehr.anchoring as anchoring
import hylehr.crypto_utils as cu
import hylehr.ledger as ledger
import hylehr.transmission as tr

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
MONO = "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"


class Paper(Style):
    background_color = "#fbfbf9"
    styles = {
        Text: "#1a1a1a", Comment: "italic #6f6e69", Keyword: "bold #1c5cab",
        Keyword.Namespace: "bold #1c5cab", Name.Function: "#a8431a", Name.Class: "bold #a8431a",
        Name.Builtin: "#4a3aa7", String: "#0b6b47", String.Doc: "italic #6f6e69",
        Number: "#8a4b00", Operator: "#1a1a1a", Name.Decorator: "#4a3aa7",
    }


def code_png(src, name, lexer=None, title=None, size=21):
    fmt = ImageFormatter(style=Paper, font_name="Liberation Mono", font_size=size,
                         line_numbers=True, line_number_bg="#efeeea", line_number_fg="#8a8983",
                         line_number_separator=False, line_number_pad=10, image_pad=16,
                         line_pad=5)
    path = f"{OUT}/{name}.png"
    with open(path, "wb") as fh:
        fh.write(highlight(src, lexer or PythonLexer(), fmt))
    frame(path, title)


def frame(path, title):
    """Add a title bar and a hairline border."""
    im = Image.open(path).convert("RGB")
    bar = 44
    out = Image.new("RGB", (im.width + 2, im.height + bar + 2), "#b9b8b2")
    d = ImageDraw.Draw(out)
    d.rectangle([1, 1, im.width, bar], fill="#e4e3de")
    for i, c in enumerate(("#d9655a", "#d9a441", "#5aa868")):
        d.ellipse([16 + i * 26, 15, 30 + i * 26, 29], fill=c)
    d.text((104, 11), title or "", fill="#3a3a38", font=ImageFont.truetype(MONO, 20))
    out.paste(im, (1, bar + 1))
    out.save(path)


def console_png(text, name, title, size=20, width=None):
    font = ImageFont.truetype(MONO, size)
    lines = text.rstrip("\n").split("\n")
    cw = font.getlength("M")
    w = int(cw * (width or max(len(l) for l in lines)) + 44)
    lh = size + 8
    im = Image.new("RGB", (w, lh * len(lines) + 34), "#f6f5f1")
    d = ImageDraw.Draw(im)
    for i, l in enumerate(lines):
        col = "#1a1a1a"
        if "PASS" in l:
            d.text((22, 17 + i * lh), l, fill=col, font=font)
            j = l.index("PASS")
            d.text((22 + cw * j, 17 + i * lh), "PASS", fill="#0b6b47", font=font)
            continue
        if l.startswith("$"):
            col = "#1c5cab"
        d.text((22, 17 + i * lh), l, fill=col, font=font)
    path = f"{OUT}/{name}.png"
    im.save(path)
    frame(path, title)


def src(*objs):
    import textwrap
    return "\n\n\n".join(textwrap.dedent(inspect.getsource(o)).rstrip() for o in objs) + "\n"


code_png(src(tr._session_keys, tr._anchor_ref, tr.Sender.respond),
         "fig6_1_cbkd_sender", title="hylehr/transmission.py  --  key derivation and custodian side")
code_png(src(tr.Receiver.finish), "fig6_2_cbkd_receiver",
         title="hylehr/transmission.py  --  requester side")
code_png(inspect.getsource(anchoring.SAAA), "fig6_3_saaa",
         title="hylehr/anchoring.py  --  SAAA policy and budget controller")
code_png(src(ledger.PrivateLedger.commit_block, ledger.PrivateLedger.consent_digest),
         "fig6_4_ledger", title="hylehr/ledger.py  --  block commit and consent digest")
code_png(src(cu.merkle_proof, cu.merkle_verify, cu.encrypt_record), "fig6_5_record_crypto",
         title="hylehr/crypto_utils.py  --  Merkle paths and record encryption")
sol = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contracts", "AnchorRegistry.sol")).read()
sol = sol[sol.index("    function _advance"):]
code_png(sol, "fig6_6_contract", lexer=get_lexer_by_name("solidity"),
         title="contracts/AnchorRegistry.sol  --  anchoring and on-chain proof check")

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
console_png("$ python3 experiments/demo.py\n" + open(f"{R}/demo.txt").read(), "fig6_7_demo",
            "terminal  --  end-to-end walk-through")
sec = open(f"{R}/e6_security.txt").read()
console_png("$ python3 experiments/e6_security.py\n" + sec, "fig6_8_security",
            "terminal  --  security test suite", size=17)
console_png("$ node evm/measure_gas.js\n" + open(f"{R}/e7_gas.txt").read(), "fig6_9_gas",
            "terminal  --  contract compiled and executed on a local EVM", size=17)
for f in sorted(os.listdir(OUT)):
    if f.startswith("fig6"):
        im = Image.open(f"{OUT}/{f}")
        print(f, im.size)

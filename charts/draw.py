"""Tiny diagram helpers on top of matplotlib."""
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon
from style import *


def canvas(w, h, scale=1.0):
    fig, ax = plt.subplots(figsize=(w * scale, h * scale))
    ax.set_xlim(0, w); ax.set_ylim(0, h); ax.set_aspect("equal"); ax.axis("off")
    ax.grid(False)
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    return fig, ax


def box(ax, x, y, w, h, text="", fc=T_GREY, ec=INK2, fs=10, bold=False, lw=1.0, r=0.07,
        tc=INK, ha="center", va="center", ls="-", italic=False, pad=0.12, zorder=2, lsp=1.25):
    ax.add_patch(FancyBboxPatch((x + r, y + r), w - 2 * r, h - 2 * r,
                                boxstyle=f"round,pad={r},rounding_size={r}", fc=fc, ec=ec,
                                lw=lw, ls=ls, zorder=zorder))
    tx = x + w / 2 if ha == "center" else (x + pad if ha == "left" else x + w - pad)
    ty = y + h / 2 if va == "center" else (y + h - pad if va == "top" else y + pad)
    if text:
        ax.text(tx, ty, text, ha=ha, va=va, fontsize=fs, color=tc, zorder=zorder + 1,
                fontweight="bold" if bold else "normal", linespacing=lsp,
                fontstyle="italic" if italic else "normal")


def arrow(ax, x1, y1, x2, y2, text=None, color=INK2, lw=1.2, rad=0.0, fs=9, style="-|>",
          ls="-", tpos=0.5, toff=(0, 0.1), tha="center", tva="bottom", tc=INK2, zorder=4,
          bg=True):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=11,
                                 color=color, lw=lw, ls=ls, zorder=zorder,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0))
    if text:
        ax.text(x1 + (x2 - x1) * tpos + toff[0], y1 + (y2 - y1) * tpos + toff[1], text,
                ha=tha, va=tva, fontsize=fs, color=tc, zorder=zorder + 1, linespacing=1.2,
                bbox=dict(fc="white", ec="none", pad=1.2) if bg else None)


def label(ax, x, y, text, fs=10, bold=False, color=INK, ha="center", va="center", italic=False,
          rot=0, lsp=1.25):
    ax.text(x, y, text, ha=ha, va=va, fontsize=fs, color=color, rotation=rot, linespacing=lsp,
            fontweight="bold" if bold else "normal", fontstyle="italic" if italic else "normal",
            zorder=6)


def diamond(ax, cx, cy, w, h, text, fc=T_YELLOW, ec=INK2, fs=9.5):
    ax.add_patch(Polygon([(cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2), (cx - w / 2, cy)],
                         closed=True, fc=fc, ec=ec, lw=1.0, zorder=2))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs, color=INK, zorder=3,
            linespacing=1.2)

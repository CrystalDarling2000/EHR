import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7"
INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8983", "#e3e2de"
T_BLUE, T_ORANGE, T_AQUA, T_GREY, T_YELLOW = "#e6f0fb", "#fdebe3", "#e3f6ee", "#f0efec", "#fdf3d7"

plt.rcParams.update({
    "font.family": "Liberation Serif", "font.size": 11,
    "axes.edgecolor": MUTED, "axes.linewidth": 0.8, "axes.labelcolor": INK2,
    "axes.titlesize": 11.5, "axes.titleweight": "bold", "axes.titlecolor": INK,
    "axes.spines.top": False, "axes.spines.right": False,
    "xtick.color": INK2, "ytick.color": INK2, "xtick.labelsize": 10, "ytick.labelsize": 10,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.7, "grid.linestyle": "-",
    "axes.axisbelow": True, "legend.frameon": False, "legend.fontsize": 10,
    "lines.linewidth": 2.0, "lines.markersize": 7,
    "figure.dpi": 100, "savefig.dpi": 220, "savefig.bbox": "tight", "savefig.pad_inches": 0.08,
    "figure.facecolor": "white", "axes.facecolor": "white",
    "mathtext.fontset": "custom", "mathtext.rm": "Liberation Serif",
    "mathtext.it": "Liberation Serif:italic", "mathtext.bf": "Liberation Serif:bold",
    "mathtext.cal": "Liberation Serif:italic", "mathtext.sf": "Liberation Sans", "mathtext.tt": "Liberation Mono",
})

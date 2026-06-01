"""
SASTify System Architecture Diagram Generator
Generates the high-level system architecture diagram with CI/CD capabilities
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe
import numpy as np


def create_system_architecture():
    """Generate the SASTify System Architecture diagram including CI/CD capabilities"""
    fig, ax = plt.subplots(figsize=(20, 16))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 16)
    ax.axis('off')
    fig.patch.set_facecolor('white')

    # ============================================================
    # Title
    # ============================================================
    ax.text(10, 15.4, 'SASTify System Architecture', fontsize=30, fontweight='bold',
            ha='center', color='#2c3e50', family='sans-serif')
    ax.text(10, 14.9, 'with CI/CD Integration', fontsize=16, ha='center',
            color='#7f8c8d', family='sans-serif', style='italic')

    # ============================================================
    # Helper functions
    # ============================================================
    def draw_rounded_box(x, y, w, h, color, label, sublabel=None, fontsize=14, icon=None):
        """Draw a rounded rectangle component box"""
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.06",
                             facecolor=color, edgecolor='white', linewidth=2,
                             alpha=0.95, zorder=3)
        box.set_path_effects([pe.withStroke(linewidth=0, foreground='white'),
                              pe.SimplePatchShadow(offset=(2, -2), shadow_rgbFace='#cccccc', alpha=0.3)])
        ax.add_patch(box)

        # Icon
        if icon:
            ax.text(x + w/2, y + h/2 + 0.25, icon, fontsize=22, ha='center', va='center',
                    color='white', zorder=4)
            label_y = y + h/2 - 0.15
        else:
            label_y = y + h/2 + 0.1

        # Label
        ax.text(x + w/2, label_y, label, fontsize=fontsize, fontweight='bold',
                ha='center', va='center', color='white', zorder=4, family='sans-serif')

        # Sublabel
        if sublabel:
            ax.text(x + w/2, label_y - 0.35, sublabel, fontsize=10, ha='center',
                    va='center', color=(1, 1, 1, 0.85), zorder=4, family='sans-serif')

    def draw_sub_box(x, y, w, h, label, parent_color, fontsize=10):
        """Draw a smaller sub-component box inside a parent"""
        lighter = '#ffffff'
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.03",
                             facecolor='white', edgecolor=parent_color, linewidth=1.5,
                             alpha=0.92, zorder=5)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, label, fontsize=fontsize, fontweight='bold',
                ha='center', va='center', color=parent_color, zorder=6, family='sans-serif')

    def draw_arrow(start, end, label="", color='#555555', style='->', lw=2):
        """Draw a labeled arrow between components"""
        ax.annotate('', xy=end, xytext=start,
                    arrowprops=dict(arrowstyle=style, color=color, lw=lw,
                                   connectionstyle='arc3,rad=0'))
        if label:
            mid_x = (start[0] + end[0]) / 2
            mid_y = (start[1] + end[1]) / 2
            ax.text(mid_x, mid_y + 0.2, label, fontsize=10, ha='center', va='center',
                    color=color, fontweight='bold', family='sans-serif',
                    bbox=dict(boxstyle='round,pad=0.15', facecolor='white', edgecolor='none', alpha=0.85),
                    zorder=7)

    # ============================================================
    # Component Colors
    # ============================================================
    BLUE = '#2196F3'        # VS Code Extension
    GREEN = '#2E7D32'       # FastAPI Backend
    ORANGE = '#E65100'      # Analysis Engine
    PURPLE = '#6A1B9A'      # Cross-File Taint Engine
    RED = '#C62828'         # DeepSeek AI
    CI_ORANGE = '#F57C00'   # GitHub Actions CI/CD
    TEAL = '#00838F'        # Web Dashboard
    REPORT_GRAY = '#455A64' # Reports

    # ============================================================
    # VS Code Extension (top-left)
    # ============================================================
    draw_rounded_box(0.5, 11.5, 3, 2, BLUE, 'VS Code', sublabel='Extension')

    # ============================================================
    # GitHub Actions CI/CD (bottom-left) — NEW
    # ============================================================
    draw_rounded_box(0.5, 7.5, 3, 3, CI_ORANGE, 'GitHub Actions', sublabel='CI/CD Pipeline')
    # Sub-boxes inside CI/CD
    draw_sub_box(0.7, 8.5, 1.3, 0.65, 'Composite\nAction', CI_ORANGE, fontsize=8)
    draw_sub_box(2.1, 8.5, 1.2, 0.65, 'SARIF\nUpload', CI_ORANGE, fontsize=8)
    draw_sub_box(0.7, 7.7, 2.6, 0.65, 'PR Comments & Reports', CI_ORANGE, fontsize=8)

    # ============================================================
    # FastAPI Backend (center)
    # ============================================================
    draw_rounded_box(5.5, 9.5, 3.5, 3, GREEN, 'FastAPI', sublabel='Backend')

    # ============================================================
    # Analysis Engine (top-right)
    # ============================================================
    # Outer container
    engine_box = FancyBboxPatch((11, 11), 8, 3.5, boxstyle="round,pad=0.08",
                                facecolor=ORANGE, edgecolor='white', linewidth=2,
                                alpha=0.95, zorder=3)
    engine_box.set_path_effects([pe.SimplePatchShadow(offset=(2, -2), shadow_rgbFace='#cccccc', alpha=0.3)])
    ax.add_patch(engine_box)
    ax.text(15, 14.1, 'Analysis Engine', fontsize=16, fontweight='bold',
            ha='center', color='white', zorder=4, family='sans-serif')

    # Sub-boxes
    draw_sub_box(11.3, 12.7, 2.3, 1, 'Python AST\nScanner', ORANGE, fontsize=10)
    draw_sub_box(13.8, 12.7, 2.5, 1, 'JavaScript AST\nScanner', ORANGE, fontsize=10)
    draw_sub_box(16.5, 12.7, 2.2, 1, 'TypeScript\nAnalyzer', ORANGE, fontsize=10)
    draw_sub_box(11.3, 11.3, 2.3, 1, 'EdTech\nRules (57)', ORANGE, fontsize=10)
    draw_sub_box(13.8, 11.3, 4.9, 1, 'Pattern Matcher', ORANGE, fontsize=10)

    # ============================================================
    # Cross-File Taint Engine (right-middle)
    # ============================================================
    taint_box = FancyBboxPatch((11, 6.5), 8, 3.5, boxstyle="round,pad=0.08",
                               facecolor=PURPLE, edgecolor='white', linewidth=2,
                               alpha=0.95, zorder=3)
    taint_box.set_path_effects([pe.SimplePatchShadow(offset=(2, -2), shadow_rgbFace='#cccccc', alpha=0.3)])
    ax.add_patch(taint_box)
    ax.text(15, 9.6, 'Cross-File Taint Engine', fontsize=16, fontweight='bold',
            ha='center', color='white', zorder=4, family='sans-serif')

    # Sub-boxes
    draw_sub_box(11.3, 8.2, 3.5, 1, 'Project Indexer', PURPLE, fontsize=10)
    draw_sub_box(15.1, 8.2, 3.6, 1, 'Call Graph Builder', PURPLE, fontsize=10)
    draw_sub_box(11.3, 6.9, 3.5, 1, 'Function Summaries', PURPLE, fontsize=10)
    draw_sub_box(15.1, 6.9, 3.6, 1, 'Taint Propagator', PURPLE, fontsize=10)

    # ============================================================
    # DeepSeek AI (bottom-center)
    # ============================================================
    draw_rounded_box(5.5, 3.5, 3.5, 2, RED, 'DeepSeek', sublabel='AI')

    # ============================================================
    # Web Dashboard (bottom-right) — NEW
    # ============================================================
    draw_rounded_box(11, 3.5, 3.5, 2, TEAL, 'Web Dashboard', sublabel='React')

    # ============================================================
    # Reports Output (far bottom-right) — NEW
    # ============================================================
    draw_rounded_box(15.5, 3.5, 3.5, 2, REPORT_GRAY, 'Reports', sublabel='SARIF · HTML · JSON')

    # ============================================================
    # Arrows / Connections
    # ============================================================
    # VS Code → FastAPI (REST API)
    draw_arrow((3.5, 12.5), (5.5, 11.5), 'REST API', color='#1976D2')

    # GitHub Actions CI/CD → FastAPI (CLI Trigger)
    draw_arrow((3.5, 9.5), (5.5, 10.5), 'CLI Trigger', color='#E65100')

    # FastAPI → Analysis Engine (Code Analysis)
    draw_arrow((9, 12), (11, 12.5), 'Code Analysis', color='#2E7D32')

    # FastAPI → Cross-File Taint Engine (Project Scan)
    draw_arrow((9, 10.2), (11, 8.5), 'Project Scan', color='#2E7D32')

    # FastAPI → DeepSeek AI (AI Explanations)
    draw_arrow((7.25, 9.5), (7.25, 5.5), 'AI Explanations', color='#C62828')

    # FastAPI → Web Dashboard (Analytics API)
    draw_arrow((9, 10), (11.5, 5.2), 'Analytics API', color='#00838F')

    # FastAPI → Reports (Generate)
    draw_arrow((9, 10.5), (15.5, 5.2), 'Generate Reports', color='#455A64')

    # ============================================================
    # Legend
    # ============================================================
    legend_y = 2.0
    legend_items = [
        (BLUE, 'IDE Integration'),
        (CI_ORANGE, 'CI/CD Pipeline'),
        (GREEN, 'Backend API'),
        (ORANGE, 'Analysis Engine'),
        (PURPLE, 'Taint Engine'),
        (RED, 'AI Service'),
        (TEAL, 'Web Dashboard'),
        (REPORT_GRAY, 'Output Reports'),
    ]

    ax.text(1, legend_y + 0.6, 'Legend:', fontsize=12, fontweight='bold', color='#2c3e50',
            family='sans-serif')

    for i, (color, label) in enumerate(legend_items):
        col = i % 4
        row = i // 4
        x = 1 + col * 4.7
        y = legend_y - row * 0.6
        box = FancyBboxPatch((x, y - 0.05), 0.35, 0.3,
                             boxstyle="round", facecolor=color, edgecolor='white', zorder=3)
        ax.add_patch(box)
        ax.text(x + 0.5, y + 0.1, label, fontsize=10,
                va='center', color='#2c3e50', family='sans-serif')

    # ============================================================
    # "NEW" badges on CI/CD components
    # ============================================================
    for (bx, by) in [(3.1, 10.3), (14.1, 5.3), (18.6, 5.3)]:
        ax.text(bx, by, 'NEW', fontsize=7, fontweight='bold', color='white',
                bbox=dict(boxstyle='round,pad=0.15', facecolor='#e74c3c', edgecolor='none'),
                ha='center', va='center', zorder=8)

    plt.tight_layout()
    output_path = r'c:\Users\Abdullah\OneDrive\Documents\sastify\SASTify_System_Architecture.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"System architecture diagram saved to: {output_path}")
    return output_path


if __name__ == '__main__':
    create_system_architecture()

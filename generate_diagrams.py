"""
SASTify Architecture Diagrams Generator
Creates Class Diagram, Sequence Diagram, and C4 Architecture Diagram
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle
import matplotlib.lines as mlines
import numpy as np

def create_class_diagram():
    """Generate Class Diagram for SASTify"""
    fig, ax = plt.subplots(figsize=(18, 14))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 14)
    ax.set_aspect('equal')
    ax.axis('off')
    
    # Title
    # Title
    ax.text(9, 13.5, 'SASTify Class Diagram', fontsize=32, fontweight='bold', 
            ha='center', color='#2c3e50')
    
    def draw_class(x, y, width, height, name, attributes, methods, color='#e8f4fd'):
        # Main box
        box = FancyBboxPatch((x, y), width, height, boxstyle="round,pad=0.02",
                             facecolor=color, edgecolor='#2c3e50', linewidth=2)
        ax.add_patch(box)
        
        # Class name section
        name_height = height * 0.2
        ax.plot([x, x + width], [y + height - name_height, y + height - name_height], 
                color='#2c3e50', linewidth=1)
        ax.text(x + width/2, y + height - name_height/2, name, 
                fontsize=16, fontweight='bold', ha='center', va='center')
        
        # Attributes section
        attr_height = height * 0.35
        ax.plot([x, x + width], [y + height - name_height - attr_height, y + height - name_height - attr_height], 
                color='#2c3e50', linewidth=1)
        
        attr_y = y + height - name_height - 0.15
        for attr in attributes[:4]:  # Limit to 4 attributes
            ax.text(x + 0.1, attr_y, f"- {attr}", fontsize=12, va='top')
            attr_y -= 0.25
        
        # Methods section
        method_y = y + height - name_height - attr_height - 0.15
        for method in methods[:4]:  # Limit to 4 methods
            ax.text(x + 0.1, method_y, f"+ {method}()", fontsize=12, va='top')
            method_y -= 0.25
    
    def draw_arrow(start, end, style='->'):
        ax.annotate('', xy=end, xytext=start,
                   arrowprops=dict(arrowstyle=style, color='#2c3e50', lw=1.5))
    
    def draw_diamond_arrow(start, end):
        ax.annotate('', xy=end, xytext=start,
                   arrowprops=dict(arrowstyle='-|>', color='#2c3e50', lw=1.5))
        # Diamond at start
        diamond = plt.Polygon([(start[0], start[1]), 
                               (start[0]+0.15, start[1]+0.15),
                               (start[0]+0.3, start[1]),
                               (start[0]+0.15, start[1]-0.15)],
                             facecolor='white', edgecolor='#2c3e50', linewidth=1.5)
        ax.add_patch(diamond)
    
    # Main Classes
    
    # EnhancedRuleEngine (Central)
    draw_class(7, 8, 4, 2.5, 'EnhancedRuleEngine',
               ['python_scanner', 'js_scanner', 'edtech_engine', 'taint_tracker'],
               ['scan_with_ast_analysis()', 'scan_file()', '_deduplicate()'],
               '#d4edda')
    
    # TaintTracker
    draw_class(1, 10, 3.5, 2, 'TaintTracker',
               ['sources: Dict', 'sinks: Dict', 'sanitizers: Dict'],
               ['__init__()'],
               '#fff3cd')
    
    # PythonASTScanner
    draw_class(1, 6.5, 3.5, 2.2, 'PythonASTScanner',
               ['taint_tracker', 'tainted_vars: Set', 'issues: List'],
               ['scan()', '_visit()', '_check_call()'],
               '#e8f4fd')
    
    # JavascriptASTScanner
    draw_class(1, 3.5, 3.5, 2.2, 'JavascriptASTScanner',
               ['taint_tracker', 'tainted_vars: Set', 'issues: List'],
               ['scan()', '_traverse()', '_check_call()'],
               '#e8f4fd')
    
    # EdTechRuleEngine
    draw_class(12.5, 8, 4, 2.5, 'EdTechRuleEngine',
               ['rules: Dict[str, EdTechRule]'],
               ['scan_code()', 'get_statistics()', '_register_all_rules()'],
               '#f8d7da')
    
    # EdTechRule
    draw_class(12.5, 4.5, 4, 2.8, 'EdTechRule',
               ['id: str', 'name: str', 'pattern: str', 'severity: Severity', 
                'ferpa_relevant: bool'],
               [],
               '#f5c6cb')
    
    # ProjectAnalyzer
    draw_class(7, 4.5, 4, 2.2, 'ProjectAnalyzer',
               ['project_path', 'index: ProjectIndex'],
               ['analyze()', '_parse_file()', '_build_symbol_table()'],
               '#d1ecf1')
    
    # CallGraphBuilder
    draw_class(1, 0.5, 3.5, 2, 'CallGraphBuilder',
               ['index: ProjectIndex', 'graph: CallGraph'],
               ['build()', '_resolve_call()'],
               '#d1ecf1')
    
    # CrossFileTaintAnalyzer
    draw_class(7, 1, 4, 2.2, 'CrossFileTaintAnalyzer',
               ['call_graph', 'summaries', 'vulnerabilities'],
               ['analyze()', '_propagate_taint()'],
               '#d1ecf1')
    
    # SecureDeepSeekAPI
    draw_class(12.5, 1, 4, 2, 'SecureDeepSeekAPI',
               ['api_key', 'client'],
               ['analyze_vulnerability()', 'get_explanation()'],
               '#e2d5f1')
    
    # Draw relationships
    # EnhancedRuleEngine has TaintTracker, scanners, edtech
    draw_arrow((7, 9.5), (4.5, 10.5))  # to TaintTracker
    draw_arrow((7, 8.5), (4.5, 7.5))   # to PythonAST
    draw_arrow((7, 8), (4.5, 4.5))     # to JavascriptAST
    draw_arrow((11, 9), (12.5, 9))     # to EdTechRuleEngine
    
    # EdTechRuleEngine has EdTechRules
    draw_arrow((14.5, 8), (14.5, 7.3))
    
    # ProjectAnalyzer used by CrossFile
    draw_arrow((9, 4.5), (9, 3.2))
    
    # CallGraphBuilder used by CrossFile
    draw_arrow((4.5, 1.5), (7, 2))
    
    # CrossFile uses DeepSeek
    draw_arrow((11, 2), (12.5, 2))
    
    # Scanners use TaintTracker
    draw_arrow((2.5, 8.7), (2.5, 10))
    draw_arrow((2.5, 5.7), (2.5, 6.5))
    
    # Legend - positioned in bottom-left corner to avoid overlap
    legend_box = FancyBboxPatch((5.5, 0.2), 3.5, 2.4, boxstyle="round,pad=0.02",
                                facecolor='#fafafa', edgecolor='#2c3e50', linewidth=2)
    ax.add_patch(legend_box)
    ax.text(7.25, 2.4, 'Legend', fontsize=16, fontweight='bold', ha='center')
    ax.plot([5.6, 8.9], [2.2, 2.2], color='#2c3e50', linewidth=1)
    
    colors = [('#d4edda', 'Core Engine'), 
              ('#fff3cd', 'Taint Tracker'),
              ('#e8f4fd', 'AST Scanners'), 
              ('#f8d7da', 'EdTech Rules'), 
              ('#d1ecf1', 'Cross-File Analysis'), 
              ('#e2d5f1', 'AI Module')]
    
    for i, (color, label) in enumerate(colors):
        rect = FancyBboxPatch((5.7, 1.85 - i*0.28), 0.4, 0.22, 
                              facecolor=color, edgecolor='#2c3e50', linewidth=1)
        ax.add_patch(rect)
        ax.text(6.25, 1.95 - i*0.28, label, fontsize=14, va='center')
    
    plt.tight_layout()
    output_path = r'c:\Users\Abdullah\OneDrive\Documents\sastify\SASTify_Class_Diagram.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Class diagram saved to: {output_path}")
    return output_path


def create_sequence_diagram():
    """Generate Sequence Diagram for SASTify scan flow"""
    fig, ax = plt.subplots(figsize=(16, 12))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 12)
    ax.axis('off')
    
    # Title
    ax.text(8, 11.5, 'SASTify Scan Sequence Diagram', fontsize=30, fontweight='bold', 
            ha='center', color='#2c3e50')
    
    # Actors/Objects
    actors = [
        (2, 'User/VS Code'),
        (5, 'Extension'),
        (8, 'FastAPI\nBackend'),
        (11, 'Rule\nEngine'),
        (14, 'DeepSeek\nAI')
    ]
    
    # Draw actor boxes at top
    for x, name in actors:
        box = FancyBboxPatch((x-0.7, 10.5), 1.4, 0.8, boxstyle="round,pad=0.02",
                             facecolor='#e8f4fd', edgecolor='#2c3e50', linewidth=2)
        ax.add_patch(box)
        ax.text(x, 10.9, name, fontsize=14, fontweight='bold', ha='center', va='center')
        
        # Lifeline
        ax.plot([x, x], [10.5, 1], color='#2c3e50', linestyle='--', linewidth=1)
    
    def draw_message(x1, x2, y, label, is_return=False):
        style = '<-' if is_return else '->'
        color = '#27ae60' if is_return else '#2c3e50'
        linestyle = '--' if is_return else '-'
        ax.annotate('', xy=(x2, y), xytext=(x1, y),
                   arrowprops=dict(arrowstyle=style, color=color, lw=1.5, 
                                  linestyle=linestyle))
        offset = 0.1 if x2 > x1 else -0.1
        ax.text((x1+x2)/2, y+0.15, label, fontsize=12, ha='center', 
               color=color, style='italic' if is_return else 'normal')
    
    def draw_activation(x, y_start, y_end):
        rect = Rectangle((x-0.15, y_end), 0.3, y_start-y_end,
                         facecolor='#d5e8d4', edgecolor='#2c3e50', linewidth=1)
        ax.add_patch(rect)
    
    # Draw activations
    draw_activation(5, 10, 2)    # Extension
    draw_activation(8, 9.5, 3)   # Backend
    draw_activation(11, 9, 4)    # Engine
    draw_activation(14, 5.5, 5)  # AI
    
    # Messages
    y = 10
    draw_message(2, 5, y, '1. Trigger Scan')
    
    y = 9.5
    draw_message(5, 8, y, '2. POST /api/scan (code, language)')
    
    y = 9
    draw_message(8, 11, y, '3. scan_with_ast_analysis()')
    
    y = 8.5
    ax.text(11.5, y, '4. Layer 1: AST Taint Analysis', fontsize=12, 
           bbox=dict(boxstyle='round', facecolor='#fff3cd', edgecolor='#ffc107'))
    
    y = 7.8
    ax.text(11.5, y, '5. Layer 2: EdTech Rules (57)', fontsize=12,
           bbox=dict(boxstyle='round', facecolor='#fff3cd', edgecolor='#ffc107'))
    
    y = 7.1
    ax.text(11.5, y, '6. Layer 3: Pattern Matching', fontsize=12,
           bbox=dict(boxstyle='round', facecolor='#fff3cd', edgecolor='#ffc107'))
    
    y = 6.3
    draw_message(11, 8, y, '7. vulnerabilities[]', is_return=True)
    
    y = 5.5
    draw_message(8, 14, y, '8. analyze_vulnerability() [optional]')
    
    y = 5
    draw_message(14, 8, y, '9. AI explanation + fix', is_return=True)
    
    y = 4
    draw_message(8, 11, y, '10. Apply false positive detection')
    
    y = 3.5
    draw_message(11, 8, y, '11. filtered results', is_return=True)
    
    y = 3
    draw_message(8, 5, y, '12. JSON response', is_return=True)
    
    y = 2.5
    draw_message(5, 2, y, '13. Display in Results Panel', is_return=True)
    
    # Notes
    note_box = FancyBboxPatch((0.5, 1), 4, 0.8, boxstyle="round,pad=0.02",
                              facecolor='#ffeeba', edgecolor='#856404', linewidth=1)
    ax.add_patch(note_box)
    ax.text(2.5, 1.4, 'Note: Steps 8-9 only executed\nwhen user clicks "Analyze with AI"', 
           fontsize=12, ha='center', va='center')
    
    plt.tight_layout()
    output_path = r'c:\Users\Abdullah\OneDrive\Documents\sastify\SASTify_Sequence_Diagram.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Sequence diagram saved to: {output_path}")
    return output_path


def create_c4_diagram():
    """Generate C4 Context and Container Diagram for SASTify"""
    fig, ax = plt.subplots(figsize=(18, 14))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 14)
    ax.axis('off')
    
    # Title
    ax.text(9, 13.5, 'SASTify C4 Architecture Diagram', fontsize=32, fontweight='bold', 
            ha='center', color='#2c3e50')
    ax.text(9, 13, '(Context + Container Level)', fontsize=18, ha='center', color='#7f8c8d')
    
    def draw_person(x, y, name, desc):
        # Head
        head = Circle((x, y+0.6), 0.25, facecolor='#08427b', edgecolor='#052e56')
        ax.add_patch(head)
        # Body
        body = FancyBboxPatch((x-0.4, y-0.3), 0.8, 0.7, boxstyle="round,pad=0.02",
                              facecolor='#08427b', edgecolor='#052e56', linewidth=2)
        ax.add_patch(body)
        ax.text(x, y-0.6, name, fontsize=14, fontweight='bold', ha='center', color='white',
               bbox=dict(boxstyle='round', facecolor='#08427b', edgecolor='none'))
        ax.text(x, y-1, desc, fontsize=12, ha='center', color='#2c3e50', style='italic')
    
    def draw_system(x, y, width, height, name, desc, is_external=False):
        color = '#999999' if is_external else '#1168bd'
        box = FancyBboxPatch((x, y), width, height, boxstyle="round,pad=0.05",
                             facecolor=color, edgecolor='#052e56', linewidth=2)
        ax.add_patch(box)
        ax.text(x + width/2, y + height - 0.4, name, fontsize=16, fontweight='bold', 
               ha='center', color='white')
        # Wrap description
        words = desc.split()
        lines = []
        line = ""
        for word in words:
            if len(line + word) < 25:
                line += word + " "
            else:
                lines.append(line.strip())
                line = word + " "
        lines.append(line.strip())
        
        for i, line in enumerate(lines[:3]):
            ax.text(x + width/2, y + height - 0.8 - i*0.3, line, fontsize=12, 
                   ha='center', color='white')
    
    def draw_container(x, y, width, height, name, tech, desc, color='#438dd5'):
        box = FancyBboxPatch((x, y), width, height, boxstyle="round,pad=0.03",
                             facecolor=color, edgecolor='#2c3e50', linewidth=2)
        ax.add_patch(box)
        ax.text(x + width/2, y + height - 0.3, name, fontsize=14, fontweight='bold', 
               ha='center', color='white')
        ax.text(x + width/2, y + height - 0.55, f'[{tech}]', fontsize=11, 
               ha='center', color='#d4e6f1')
        
        # Description
        words = desc.split()
        line = ""
        y_pos = y + height - 0.85
        for word in words:
            if len(line + word) < 20:
                line += word + " "
            else:
                ax.text(x + width/2, y_pos, line.strip(), fontsize=11, ha='center', color='white')
                y_pos -= 0.22
                line = word + " "
        ax.text(x + width/2, y_pos, line.strip(), fontsize=11, ha='center', color='white')
    
    def draw_arrow(start, end, label=""):
        ax.annotate('', xy=end, xytext=start,
                   arrowprops=dict(arrowstyle='->', color='#2c3e50', lw=1.5))
        if label:
            mid_x = (start[0] + end[0]) / 2
            mid_y = (start[1] + end[1]) / 2
            ax.text(mid_x, mid_y + 0.2, label, fontsize=11, ha='center', 
                   color='#2c3e50', style='italic')
    
    # ===== Context Level (Top) =====
    ax.text(9, 12.3, '— Context Level —', fontsize=16, ha='center', 
           color='#7f8c8d', style='italic')
    
    # Developer (Person)
    draw_person(3, 11, 'Developer', '[Person]')
    
    # SASTify System
    draw_system(6, 10, 6, 2, 'SASTify', 
                'EdTech-focused SAST tool for security analysis')
    
    # External Systems
    draw_system(14, 10.5, 3, 1.5, 'DeepSeek AI', 
                'AI explanations', is_external=True)
    
    # Context arrows
    draw_arrow((4, 11), (6, 11), 'Scans code')
    draw_arrow((12, 11), (14, 11), 'API calls')
    
    # ===== Container Level (Bottom) =====
    ax.plot([0.5, 17.5], [9, 9], color='#bdc3c7', linestyle='--', linewidth=1)
    ax.text(9, 8.7, '— Container Level —', fontsize=16, ha='center', 
           color='#7f8c8d', style='italic')
    
    # VS Code Extension
    draw_container(1, 5.5, 3, 2.5, 'VS Code Extension', 'TypeScript',
                   'Provides UI for scanning, results display, inline diagnostics',
                   '#2d7d9a')
    
    # FastAPI Backend
    draw_container(5.5, 5.5, 3.5, 2.5, 'FastAPI Backend', 'Python',
                   'REST API endpoints for scan, analyze, health check',
                   '#438dd5')
    
    # Analysis Engine
    draw_container(10, 5.5, 3.5, 2.5, 'Analysis Engine', 'Python',
                   'Multi-layer scanning: AST, EdTech rules, patterns',
                   '#438dd5')
    
    # Cross-File Engine
    draw_container(5.5, 2, 3.5, 2.5, 'Cross-File Engine', 'Python',
                   'Project indexing, call graph, taint propagation',
                   '#85c1e9')
    
    # AI Module
    draw_container(10, 2, 3.5, 2.5, 'AI Module', 'Python',
                   'DeepSeek integration, vulnerability explanations',
                   '#a569bd')
    
    # EdTech Rules
    draw_container(14.5, 5.5, 2.5, 2.5, 'EdTech Rules', 'Python',
                   '57 rules for student data, exams, AI security',
                   '#e74c3c')
    
    # Container arrows
    draw_arrow((4, 6.5), (5.5, 6.5), 'HTTP')
    draw_arrow((9, 6.5), (10, 6.5), 'calls')
    draw_arrow((13.5, 6.5), (14.5, 6.5), 'uses')
    draw_arrow((7.25, 5.5), (7.25, 4.5), 'uses')
    draw_arrow((11.75, 5.5), (11.75, 4.5), 'uses')
    draw_arrow((9, 3.25), (10, 3.25), 'calls')
    
    # External arrow
    draw_arrow((11.75, 2), (14.5, 1), 'API')
    draw_system(14.5, 0.3, 2.5, 1.2, 'DeepSeek', 'External AI', is_external=True)
    
    # Legend
    ax.text(1, 1.5, 'Legend:', fontsize=14, fontweight='bold')
    
    person_legend = Circle((1.3, 1), 0.15, facecolor='#08427b', edgecolor='#052e56')
    ax.add_patch(person_legend)
    ax.text(1.6, 1, 'Person', fontsize=12, va='center')
    
    sys_legend = FancyBboxPatch((1, 0.5), 0.4, 0.3, boxstyle="round",
                                facecolor='#1168bd', edgecolor='#052e56')
    ax.add_patch(sys_legend)
    ax.text(1.6, 0.65, 'System/Container', fontsize=12, va='center')
    
    ext_legend = FancyBboxPatch((3, 0.5), 0.4, 0.3, boxstyle="round",
                                facecolor='#999999', edgecolor='#052e56')
    ax.add_patch(ext_legend)
    ax.text(3.6, 0.65, 'External System', fontsize=12, va='center')
    
    plt.tight_layout()
    output_path = r'c:\Users\Abdullah\OneDrive\Documents\sastify\SASTify_C4_Diagram.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"C4 diagram saved to: {output_path}")
    return output_path


if __name__ == '__main__':
    print("Generating SASTify Architecture Diagrams...")
    create_class_diagram()
    create_sequence_diagram()
    create_c4_diagram()
    print("\nAll diagrams generated successfully!")

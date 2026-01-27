"""
SASTify Updated Gantt Chart Generator
Includes new phases for Test Case Suggestions, GitHub Actions/CI Integration, and Further Testing
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

def create_gantt_chart():
    # Define project phases with (name, start_week, duration, color, status)
    # Status: 'complete', 'in_progress', 'planned'
    phases = [
        ("Initiation", 0, 2, '#87CEEB', 'complete'),
        ("Core Engine Development", 2, 5, '#87CEEB', 'complete'),
        ("AI Integration", 7, 5, '#87CEEB', 'complete'),
        ("IDE Plugin Development", 12, 5, '#87CEEB', 'complete'),
        ("Web Dashboard Development", 17, 6, '#87CEEB', 'complete'),
        ("Testing & Iteration", 23, 5, '#87CEEB', 'complete'),
        ("Test Case Suggestions", 28, 4, '#4169E1', 'in_progress'),  # New - Royal Blue
        ("GitHub Actions/CI Integration", 32, 5, '#4169E1', 'planned'),  # New
        ("Further Testing & QA", 37, 4, '#4169E1', 'planned'),  # New
        ("Deployment & Handover", 41, 4, '#2E8B57', 'planned'),  # Green for final
    ]
    
    # Create figure with larger size
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Set background color
    fig.patch.set_facecolor('#f8f9fa')
    ax.set_facecolor('#ffffff')
    
    # Add border
    for spine in ax.spines.values():
        spine.set_edgecolor('#4B0082')
        spine.set_linewidth(2)
    
    # Plot each phase
    y_positions = list(range(len(phases), 0, -1))
    
    for i, (name, start, duration, color, status) in enumerate(phases):
        y = y_positions[i]
        
        # Add pattern for different statuses
        if status == 'complete':
            bar = ax.barh(y, duration, left=start, height=0.6, color=color, 
                         edgecolor='#2c3e50', linewidth=1, alpha=0.9)
        elif status == 'in_progress':
            bar = ax.barh(y, duration, left=start, height=0.6, color=color, 
                         edgecolor='#1a5276', linewidth=2, alpha=0.85,
                         hatch='///')
        else:  # planned
            bar = ax.barh(y, duration, left=start, height=0.6, color=color, 
                         edgecolor='#1a5276', linewidth=1.5, alpha=0.7)
    
    # Customize y-axis
    ax.set_yticks(y_positions)
    ax.set_yticklabels([p[0] for p in phases], fontsize=11, fontweight='medium')
    
    # Customize x-axis
    ax.set_xlabel('Weeks', fontsize=12, fontweight='bold')
    ax.set_xlim(0, 48)
    ax.set_xticks(range(0, 50, 5))
    
    # Add grid
    ax.xaxis.grid(True, linestyle='--', alpha=0.4, color='#95a5a6')
    ax.set_axisbelow(True)
    
    # Add title
    plt.title('SASTify Gantt Chart\n', fontsize=18, fontweight='bold', 
              color='#4B0082', style='italic')
    plt.suptitle('Project Gantt Chart', fontsize=14, y=0.88, color='#2c3e50')
    
    # Add legend
    legend_elements = [
        mpatches.Patch(facecolor='#87CEEB', edgecolor='#2c3e50', label='Completed Phases'),
        mpatches.Patch(facecolor='#4169E1', edgecolor='#1a5276', label='New Development (Agent Features)'),
        mpatches.Patch(facecolor='#2E8B57', edgecolor='#1a5276', label='Final Deployment'),
    ]
    
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10, 
             framealpha=0.95, edgecolor='#4B0082')
    
    # Add annotations for new phases
    ax.annotate('NEW', xy=(30, 4), fontsize=8, fontweight='bold', color='white',
               bbox=dict(boxstyle='round', facecolor='#e74c3c', edgecolor='none', alpha=0.9))
    ax.annotate('NEW', xy=(34.5, 3), fontsize=8, fontweight='bold', color='white',
               bbox=dict(boxstyle='round', facecolor='#e74c3c', edgecolor='none', alpha=0.9))
    ax.annotate('NEW', xy=(39, 2), fontsize=8, fontweight='bold', color='white',
               bbox=dict(boxstyle='round', facecolor='#e74c3c', edgecolor='none', alpha=0.9))
    
    # Add current week marker (middle of Web Dashboard Development)
    current_week = 20
    ax.axvline(x=current_week, color='#e74c3c', linestyle='--', linewidth=2, alpha=0.7)
    ax.annotate('Current\nWeek', xy=(current_week, 10.5), fontsize=9, 
               ha='center', color='#e74c3c', fontweight='bold')
    
    # Adjust layout
    plt.tight_layout()
    plt.subplots_adjust(top=0.85)
    
    # Save as PNG
    output_path = r'c:\Users\Abdullah\OneDrive\Documents\sastify\SASTify_Gantt_Chart_Updated.png'
    plt.savefig(output_path, dpi=150, bbox_inches='tight', 
                facecolor=fig.get_facecolor(), edgecolor='none')
    
    print(f"Gantt chart saved to: {output_path}")
    plt.close()
    
    return output_path

if __name__ == '__main__':
    create_gantt_chart()

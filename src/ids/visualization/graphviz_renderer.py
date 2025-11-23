# src/ids/visualization/graphviz_renderer.py

import subprocess
import shutil
import os

def render_dot_to_svg(dot_source: str) -> str:
    """
    Renders DOT source code to SVG XML using the system 'dot' command.
    Returns the SVG string.
    """
    # Check if graphviz is installed
    if not shutil.which("dot"):
        return _create_error_svg("GraphViz 'dot' executable not found in PATH.")

    try:
        process = subprocess.run(
            ["dot", "-Tsvg"],
            input=dot_source,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return process.stdout
    except subprocess.CalledProcessError as e:
        return _create_error_svg(f"GraphViz Error: {e.stderr}")
    except Exception as e:
        return _create_error_svg(f"Rendering Error: {str(e)}")

def _create_error_svg(msg: str) -> str:
    """Fallback SVG to show errors inline."""
    return f'''
    <svg width="400" height="100" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#fee"/>
      <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="red" font-family="monospace">
        {msg}
      </text>
    </svg>
    '''
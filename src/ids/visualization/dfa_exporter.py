# src/ids/visualization/dfa_exporter.py

import html
from collections import deque
from typing import Dict, Any, List, Set
from ids.matcher.ac_automaton import AhoCorasick

def export_ac_to_dot(ac: AhoCorasick, include_fail_links: bool = True) -> str:
    """
    Exports the Aho-Corasick automaton to GraphViz DOT format.
    
    Args:
        ac: The built AhoCorasick instance.
        include_fail_links: Whether to draw dashed failure edges (can be messy for large graphs).
    
    Returns:
        A string containing the DOT graph definition.
    """
    if not ac._built:
        return 'digraph "IDS_DFA" { label="Error: Automaton not built"; }'

    lines = [
        'digraph "IDS_DFA" {',
        '  rankdir=LR;',
        '  node [shape=circle, fontname="Arial", fontsize=10];',
        '  edge [fontname="Arial", fontsize=9];',
        '  start [shape=point];',
    ]

    # We need to map object references (Nodes) to integer IDs for GraphViz
    node_to_id = {}
    id_counter = 0
    
    # BFS Queue: (node, id)
    queue = deque([(ac._root, 0)])
    node_to_id[ac._root] = 0
    
    visited_nodes = {ac._root}

    # First pass: Assign IDs and generate Node definitions
    # Re-initialize queue for processing
    queue = deque([ac._root])
    
    while queue:
        curr_node = queue.popleft()
        curr_id = node_to_id[curr_node]
        
        # Determine node attributes
        attrs = []
        
        # Highlight accepting states
        if curr_node.output:
            # Get patterns for this state
            matched_patterns = [ac._patterns[idx] for idx in curr_node.output]
            # Escape for DOT label
            pat_str = "\\n".join(matched_patterns)
            # Truncate if too long
            if len(pat_str) > 20:
                pat_str = pat_str[:18] + "..."
            
            attrs.append('shape=doublecircle')
            attrs.append('color=red')
            attrs.append('style=filled')
            attrs.append('fillcolor="#ffe6e6"')
            # Use HTML-like label for color control
            attrs.append(f'xlabel=<<FONT COLOR="darkred"><B>{html.escape(pat_str)}</B></FONT>>')
        
        if curr_id == 0:
            attrs.append('style=filled')
            attrs.append('fillcolor="#e6ffe6"')
            attrs.append('xlabel="ROOT"')

        # FIXED: Always add label to the attrs list, preventing leading comma issues
        attrs.append(f'label="{curr_id}"')
        
        attr_str = ", ".join(attrs)
        lines.append(f'  {curr_id} [{attr_str}];')

        # Process children
        for char, child in sorted(curr_node.next.items()):
            if child not in node_to_id:
                id_counter += 1
                node_to_id[child] = id_counter
                visited_nodes.add(child)
                queue.append(child)
    
    lines.append('  start -> 0;')

    # Second pass: Generate Edges (Transitions)
    for node, src_id in node_to_id.items():
        # 1. Forward Transitions
        for char, child in sorted(node.next.items()):
            dst_id = node_to_id[child]
            # Escape printable chars
            label = char
            if not char.isprintable() or char == '"' or char == '\\':
                label = f"0x{ord(char):02X}"
            
            lines.append(f'  {src_id} -> {dst_id} [label="{label}"];')

        # 2. Failure Links (Optional)
        if include_fail_links and node.fail:
            fail_target = node.fail
            if fail_target in node_to_id:
                dst_id = node_to_id[fail_target]
                # Don't draw fail links back to root (too much noise) unless specifically desired
                # Filtering strict root fails helps readability significantly
                if dst_id != 0:
                    lines.append(f'  {src_id} -> {dst_id} [color="grey", style="dashed", constraint=false];')

    lines.append('}')
    return "\n".join(lines)


def export_ac_to_json(ac: AhoCorasick) -> Dict[str, Any]:
    """
    Export the automaton structure as JSON (nodes/edges lists).
    Useful for D3.js or other client-side renderers.
    """
    if not ac._built:
        return {"error": "Automaton not built"}

    nodes = []
    edges = []
    
    node_to_id = {}
    id_counter = 0
    queue = deque([ac._root])
    node_to_id[ac._root] = 0
    visited = {ac._root}

    while queue:
        curr = queue.popleft()
        cid = node_to_id[curr]
        
        # Node info
        patterns = [ac._patterns[i] for i in curr.output] if curr.output else []
        nodes.append({
            "id": cid,
            "accepting": bool(curr.output),
            "patterns": patterns,
            "fail": node_to_id.get(curr.fail, None) if curr.fail else None
        })

        for char, child in curr.next.items():
            if child not in visited:
                id_counter += 1
                node_to_id[child] = id_counter
                visited.add(child)
                queue.append(child)
            
            edges.append({
                "source": cid,
                "target": node_to_id[child],
                "label": char
            })

    return {"nodes": nodes, "edges": edges}
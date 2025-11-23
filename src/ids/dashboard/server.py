from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import os

# Imports for on-demand DFA loading
from ids.rules.parser import parse_rules_file
from ids.rules.compiler import compile_rules
from ids.visualization.dfa_exporter import export_ac_to_dot, export_ac_to_json
from ids.visualization.graphviz_renderer import render_dot_to_svg

# Initialize SocketIO
socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")

# Store app reference globally so emit_alert can access it
_app = None

# Defines where to look for rules if not passed explicitly (fallback)
DEFAULT_RULES_PATH = os.path.join("data", "sample_rules.rules")

def create_app():
    global _app
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config['SECRET_KEY'] = 'ids-dashboard-secret'
    socketio.init_app(app)
    _app = app

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/dfa")
    def dfa_view():
        """Render the DFA Visualization page."""
        return render_template("dfa.html")

    @app.route("/api/dfa/svg")
    def get_dfa_svg():
        """
        API Endpoint: Returns the SVG representation of the AC Automaton.
        Compiles rules on-the-fly to ensure freshness.
        """
        try:
            # We load the rules specifically for visualization
            # In a prod environment, we might want to cache this or share memory with the runner
            rules_path = request.args.get("rules", DEFAULT_RULES_PATH)
            
            if not os.path.exists(rules_path):
                # Try relative to CWD if absolute failed
                if os.path.exists(os.path.join(os.getcwd(), rules_path)):
                    rules_path = os.path.join(os.getcwd(), rules_path)
                else:
                    return f"<svg><text y='20'>Rules file not found: {rules_path}</text></svg>", 404

            rules = parse_rules_file(rules_path)
            compiled = compile_rules(rules)
            
            # Generate DOT
            dot_data = export_ac_to_dot(compiled.ac, include_fail_links=True)
            
            # Render to SVG
            svg_data = render_dot_to_svg(dot_data)
            return svg_data, 200, {'Content-Type': 'image/svg+xml'}

        except Exception as e:
            return f"<svg><text y='20'>Error: {str(e)}</text></svg>", 500

    @app.route("/api/dfa/dot")
    def get_dfa_dot():
        """API Endpoint: Returns the raw DOT source."""
        try:
            rules_path = DEFAULT_RULES_PATH
            rules = parse_rules_file(rules_path)
            compiled = compile_rules(rules)
            dot_data = export_ac_to_dot(compiled.ac)
            return dot_data, 200, {'Content-Type': 'text/plain'}
        except Exception as e:
            return str(e), 500

    @app.route("/test")
    def test():
        return {"status": "ok", "message": "Server is running"}

    return app

def emit_alert(alert):
    """
    Emit alert to all connected clients
    Called from background thread, so needs app context
    """
    global _app
    if _app is None:
        print("[emit_alert] ERROR: App not initialized")
        return
    
    try:
        # print(f"[emit_alert] Emitting alert: {alert}")
        # Use app context when emitting from background thread
        with _app.app_context():
            socketio.emit('new_alert', alert, namespace='/')
    except Exception as e:
        print(f"[emit_alert] ERROR emitting alert: {e}")
        import traceback
        traceback.print_exc()
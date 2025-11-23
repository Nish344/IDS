from flask import Flask, render_template
from flask_socketio import SocketIO

# Initialize SocketIO
socketio = SocketIO(cors_allowed_origins="*", async_mode="eventlet")

# Store app reference globally so emit_alert can access it
_app = None

def create_app():
    global _app
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config['SECRET_KEY'] = 'ids-dashboard-secret'
    socketio.init_app(app)
    _app = app

    @app.route("/")
    def index():
        return render_template("dashboard.html")

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
        print(f"[emit_alert] Emitting alert: {alert}")
        # Use app context when emitting from background thread
        with _app.app_context():
            socketio.emit('new_alert', alert, namespace='/')
        print(f"[emit_alert] Alert emitted successfully")
    except Exception as e:
        print(f"[emit_alert] ERROR emitting alert: {e}")
        import traceback
        traceback.print_exc()
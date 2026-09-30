import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
import json
from typing import Dict, Any

logger = logging.getLogger("APIServer")

app = FastAPI(title="AI Cyber Shield Dashboard")

# Active connection manager for websockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

# Global state reference to query data in endpoints
system_orchestrator = None

def set_orchestrator(orchestrator):
    global system_orchestrator
    system_orchestrator = orchestrator

@app.get("/api/status")
def get_status():
    if system_orchestrator:
        return system_orchestrator.get_telemetry()
    return {"status": "offline", "message": "Orchestrator not initialized"}

@app.post("/api/simulate/{attack_type}")
def post_simulate_attack(attack_type: str):
    """Triggers simulated attack features to test training/dashboard validation."""
    if system_orchestrator:
        if attack_type == "None":
            system_orchestrator.trigger_simulation(None)
            return {"status": "success", "message": "Cleared simulation"}
        elif attack_type in ["DDoS", "SQL Injection", "Brute Force", "Ransomware", "Zero-day Exploit"]:
            system_orchestrator.trigger_simulation(attack_type)
            return {"status": "success", "message": f"Injected simulated {attack_type} patterns"}
        return {"status": "error", "message": "Unknown attack simulation type"}
    return {"status": "error", "message": "Orchestrator not initialized"}

@app.post("/api/simulate/failure/{failed}")
def post_simulate_failure(failed: bool):
    """Toggles simulated prevention failure state."""
    if system_orchestrator:
        system_orchestrator.set_prevention_failure(failed)
        return {"status": "success", "message": f"Prevention failure state set to {failed}"}
    return {"status": "error", "message": "Orchestrator not initialized"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Keep connection open and receive user command actions
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")
            
            if action == "trigger_simulation":
                attack_type = cmd.get("attack_type")
                if system_orchestrator:
                    system_orchestrator.trigger_simulation(attack_type if attack_type != "None" else None)
            elif action == "toggle_prevention_failure":
                failed = bool(cmd.get("failed", False))
                if system_orchestrator:
                    system_orchestrator.set_prevention_failure(failed)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# Microsoft Account Authentication Integration
try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False

CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI Client ID (works for device flow)
AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = ["User.Read"]

active_device_flows = {}

@app.post("/api/auth/device-flow")
def start_device_flow():
    if not MSAL_AVAILABLE:
        return {"status": "error", "message": "MSAL library is not installed in the environment."}
    try:
        pca = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        flow = pca.initiate_device_flow(scopes=SCOPES)
        if "user_code" in flow:
            user_code = flow["user_code"]
            active_device_flows[user_code] = flow
            return {
                "status": "success",
                "user_code": user_code,
                "verification_uri": flow["verification_uri"],
                "message": flow["message"],
                "expires_in": flow["expires_in"]
            }
        return {"status": "error", "message": "Failed to initiate Microsoft device code flow"}
    except Exception as e:
        logger.error(f"Error starting device flow: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/auth/poll/{user_code}")
def poll_device_flow(user_code: str):
    if not MSAL_AVAILABLE:
        return {"status": "error", "message": "MSAL library is not installed."}
    flow = active_device_flows.get(user_code)
    if not flow:
        return {"status": "error", "message": "Invalid or expired authorization code"}
        
    try:
        pca = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        result = pca.acquire_token_by_device_flow(flow)
        if "access_token" in result:
            active_device_flows.pop(user_code, None)
            
            # Query Profile Info from Microsoft Graph
            import urllib.request
            import json
            req = urllib.request.Request(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {result['access_token']}"}
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    profile = json.loads(response.read().decode())
                    user_info = {
                        "name": profile.get("displayName", "Microsoft User"),
                        "email": profile.get("mail") or profile.get("userPrincipalName", "user@outlook.com"),
                        "id": profile.get("id", "0000")
                    }
            except Exception as graph_err:
                logger.warning(f"Failed to query Microsoft Graph API: {graph_err}")
                id_token_claims = result.get("id_token_claims", {})
                user_info = {
                    "name": id_token_claims.get("name", "Microsoft User"),
                    "email": id_token_claims.get("preferred_username") or id_token_claims.get("email", "user@outlook.com"),
                    "id": id_token_claims.get("oid", "0000")
                }
            
            if system_orchestrator:
                system_orchestrator.authenticate_and_start_protection(user_info)
                return {
                    "status": "success",
                    "user_info": user_info
                }
            return {"status": "error", "message": "System orchestrator not initialized"}
        else:
            return {"status": "pending", "message": "Awaiting user authentication"}
    except Exception as e:
        logger.error(f"Authentication poll error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/auth/demo-login")
def demo_login(payload: dict = None):
    email = "security.officer@outlook.com"
    name = "Security Officer"
    if payload:
        email = payload.get("email", email)
        name = payload.get("name", name)
        
    user_info = {
        "name": name,
        "email": email,
        "id": "demo-id-12345"
    }
    
    if system_orchestrator:
        system_orchestrator.authenticate_and_start_protection(user_info)
        return {"status": "success", "user_info": user_info}
    return {"status": "error", "message": "System orchestrator not initialized"}

@app.post("/api/auth/password-login")
def password_login(payload: dict):
    if not MSAL_AVAILABLE:
        return {"status": "error", "message": "MSAL library is not installed."}
    
    email = payload.get("email")
    password = payload.get("password")
    if not email or not password:
        return {"status": "error", "message": "Email and password are required."}
        
    try:
        pca = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
        result = pca.acquire_token_by_username_password(username=email, password=password, scopes=SCOPES)
        if "access_token" in result:
            # Query Profile Info from Microsoft Graph
            import urllib.request
            import json
            req = urllib.request.Request(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {result['access_token']}"}
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    profile = json.loads(response.read().decode())
                    user_info = {
                        "name": profile.get("displayName", "Microsoft User"),
                        "email": profile.get("mail") or profile.get("userPrincipalName", email),
                        "id": profile.get("id", "0000")
                    }
            except Exception as graph_err:
                logger.warning(f"Failed to query Microsoft Graph API: {graph_err}")
                id_token_claims = result.get("id_token_claims", {})
                user_info = {
                    "name": id_token_claims.get("name", "Microsoft User"),
                    "email": id_token_claims.get("preferred_username") or id_token_claims.get("email", email),
                    "id": id_token_claims.get("oid", "0000")
                }
            
            if system_orchestrator:
                system_orchestrator.authenticate_and_start_protection(user_info)
                return {
                    "status": "success",
                    "user_info": user_info
                }
            return {"status": "error", "message": "System orchestrator not initialized"}
        else:
            error_description = result.get("error_description", "Invalid email or password.")
            if "mfa" in error_description.lower() or "interaction_required" in result.get("error", "").lower():
                error_description = "Multi-Factor Authentication (MFA) is required on this account. Please use the Device Code Flow / Verification Code login option instead."
            return {"status": "error", "message": error_description}
    except Exception as e:
        logger.error(f"Password authentication error: {e}")
        error_str = str(e)
        if "wstrust" in error_str.lower() or "mex" in error_str.lower() or "msa" in error_str.lower():
            error_msg = "Direct password sign-in is not supported for personal Microsoft accounts (like @gmail.com, @outlook.com, @hotmail.com) or accounts with Multi-Factor Authentication (MFA). Please use the 'Device Flow' option instead."
        else:
            error_msg = str(e)
        return {"status": "error", "message": error_msg}

@app.post("/api/auth/logout")
def user_logout():
    if system_orchestrator:
        system_orchestrator.logout()
        return {"status": "success"}
    return {"status": "error", "message": "System orchestrator not initialized"}

# Mount static frontend assets
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse(content="<h1>AI Cyber Shield Dashboard Frontend files missing</h1>", status_code=404)

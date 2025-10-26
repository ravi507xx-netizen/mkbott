from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Dict, List
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
import os

app = FastAPI(
    title="Pollinations API Key Manager",
    description="Secure API key management system with Pollinations.ai integration",
    version="2.0.0"
)

# Database initialization
def init_db():
    conn = sqlite3.connect('api_keys.db')
    c = conn.cursor()
    
    # API keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            requests_count INTEGER DEFAULT 0,
            last_used TIMESTAMP,
            expires_at TIMESTAMP
        )
    ''')
    
    # Admin users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Insert default admin if not exists
    password_hash = hashlib.sha256("mk123".encode()).hexdigest()
    c.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash) 
        VALUES (?, ?)
    ''', ('mk', password_hash))
    
    conn.commit()
    conn.close()

init_db()

# Response models
class StandardResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict] = None
    timestamp: str

class KeyUsageStats(BaseModel):
    total_requests: int
    active_keys: int
    total_keys: int
    today_requests: int

# Utility functions
def generate_api_key(prefix="pk"):
    return f"{prefix}_{secrets.token_urlsafe(24)}"

def get_db_connection():
    conn = sqlite3.connect('api_keys.db')
    conn.row_factory = sqlite3.Row
    return conn

def verify_admin(username: str, password: str) -> bool:
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT password_hash FROM admin_users WHERE username = ?', 
        (username,)
    ).fetchone()
    conn.close()
    
    if not admin:
        return False
    
    return hashlib.sha256(password.encode()).hexdigest() == admin['password_hash']

def format_response(success: bool, message: str, data: Optional[Dict] = None):
    return {
        "success": success,
        "message": message,
        "data": data or {},
        "timestamp": datetime.utcnow().isoformat()
    }

# API Routes
@app.get("/")
async def root():
    return format_response(
        True,
        "🔑 API Key Management System - Secure key management with Pollinations.ai integration",
        {
            "endpoints": {
                "GET /": "This welcome message",
                "GET /keys/create": "Create new API key (admin required)",
                "GET /keys": "List all API keys (admin required)",
                "GET /keys/stats": "Get usage statistics",
                "GET /key/{api_key}/prompt": "Use API key with Pollinations.ai",
                "GET /key/{api_key}/info": "Get key information and usage",
                "GET /keys/revoke": "Revoke/delete API key (admin required)"
            },
            "usage_example": "https://your-app.onrender.com/key/pk_abc123/prompt?text=Hello+World"
        }
    )

@app.get("/keys/create")
async def create_api_key(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password"),
    key_name: Optional[str] = Query(None, description="Optional name for the key"),
    expires_days: Optional[int] = Query(30, description="Key expiration in days")
):
    """Create a new API key using query parameters"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    new_key = generate_api_key()
    expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days else None
    
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO api_keys (key, name, expires_at) VALUES (?, ?, ?)',
            (new_key, key_name, expires_at)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Key generation failed, please try again")
    
    # Get the created key info
    key_info = conn.execute(
        'SELECT * FROM api_keys WHERE key = ?', (new_key,)
    ).fetchone()
    conn.close()
    
    return format_response(
        True,
        f"✅ API key '{key_name or 'Unnamed'}' created successfully",
        {
            "api_key": new_key,
            "key_name": key_name,
            "key_id": key_info['id'],
            "expires_at": key_info['expires_at'],
            "created_at": key_info['created_at'],
            "security_warning": "Store this key securely - it won't be shown again!",
            "usage_url": f"/key/{new_key}/prompt?text=Your+message+here"
        }
    )

@app.get("/key/{api_key}/prompt")
async def use_api_key_prompt(
    api_key: str,
    text: str = Query(..., description="Text to send to Pollinations.ai"),
    max_length: Optional[int] = Query(500, description="Maximum text length")
):
    """Use API key to access Pollinations.ai service"""
    if len(text) > max_length:
        raise HTTPException(status_code=400, detail=f"Text too long. Maximum {max_length} characters.")
    
    conn = get_db_connection()
    key_data = conn.execute(
        'SELECT * FROM api_keys WHERE key = ? AND is_active = 1',
        (api_key,)
    ).fetchone()
    
    if not key_data:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    
    # Check if key is expired
    if key_data['expires_at'] and datetime.fromisoformat(key_data['expires_at']) < datetime.utcnow():
        conn.close()
        raise HTTPException(status_code=401, detail="API key has expired")
    
    # Here you would integrate with Pollinations.ai
    # For now, we'll simulate a response
    try:
        # Simulate AI processing
        ai_response = f"Processed: {text} (Simulated Pollinations.ai response)"
        
        # Update usage statistics
        conn.execute(
            '''UPDATE api_keys 
               SET requests_count = requests_count + 1, 
                   last_used = CURRENT_TIMESTAMP 
               WHERE key = ?''',
            (api_key,)
        )
        conn.commit()
        
        current_usage = key_data['requests_count'] + 1
        
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Service error: {str(e)}")
    
    conn.close()
    
    return format_response(
        True,
        ai_response,
        {
            "original_prompt": text,
            "api_key_used": f"{api_key[:8]}...{api_key[-4:]}",
            "usage_count": current_usage,
            "key_name": key_data['name'],
            "last_used": datetime.utcnow().isoformat()
        }
    )

@app.get("/key/{api_key}/info")
async def get_key_info(api_key: str):
    """Get information about a specific API key"""
    conn = get_db_connection()
    key_data = conn.execute(
        'SELECT * FROM api_keys WHERE key = ?',
        (api_key,)
    ).fetchone()
    
    if not key_data:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    conn.close()
    
    is_expired = False
    if key_data['expires_at']:
        is_expired = datetime.fromisoformat(key_data['expires_at']) < datetime.utcnow()
    
    return format_response(
        True,
        f"🔑 Key information for '{key_data['name'] or 'Unnamed'}'",
        {
            "key_id": key_data['id'],
            "key_name": key_data['name'],
            "is_active": bool(key_data['is_active']),
            "is_expired": is_expired,
            "requests_count": key_data['requests_count'],
            "created_at": key_data['created_at'],
            "last_used": key_data['last_used'],
            "expires_at": key_data['expires_at'],
            "status": "active" if key_data['is_active'] and not is_expired else "inactive"
        }
    )

@app.get("/keys")
async def list_all_keys(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password"),
    show_inactive: bool = Query(False, description="Include inactive keys")
):
    """List all API keys (admin only)"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    
    if show_inactive:
        keys = conn.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    else:
        keys = conn.execute('SELECT * FROM api_keys WHERE is_active = 1 ORDER BY created_at DESC').fetchall()
    
    total_keys = conn.execute('SELECT COUNT(*) FROM api_keys').fetchone()[0]
    active_keys = conn.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1').fetchone()[0]
    total_requests = conn.execute('SELECT SUM(requests_count) FROM api_keys').fetchone()[0] or 0
    
    conn.close()
    
    keys_list = []
    for key in keys:
        is_expired = False
        if key['expires_at']:
            is_expired = datetime.fromisoformat(key['expires_at']) < datetime.utcnow()
        
        keys_list.append({
            "id": key['id'],
            "name": key['name'],
            "key_preview": f"{key['key'][:8]}...{key['key'][-4:]}",
            "is_active": bool(key['is_active']),
            "is_expired": is_expired,
            "requests_count": key['requests_count'],
            "created_at": key['created_at'],
            "last_used": key['last_used'],
            "expires_at": key['expires_at']
        })
    
    return format_response(
        True,
        f"Found {len(keys_list)} API keys",
        {
            "stats": {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "total_requests": total_requests
            },
            "keys": keys_list
        }
    )

@app.get("/keys/stats")
async def get_usage_stats(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password")
):
    """Get comprehensive usage statistics"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    
    # Get basic stats
    total_keys = conn.execute('SELECT COUNT(*) FROM api_keys').fetchone()[0]
    active_keys = conn.execute('SELECT COUNT(*) FROM api_keys WHERE is_active = 1').fetchone()[0]
    total_requests = conn.execute('SELECT SUM(requests_count) FROM api_keys').fetchone()[0] or 0
    
    # Get today's requests
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_requests = conn.execute(
        'SELECT SUM(requests_count) FROM api_keys WHERE last_used >= ?',
        (today_start,)
    ).fetchone()[0] or 0
    
    # Get top used keys
    top_keys = conn.execute(
        'SELECT name, requests_count FROM api_keys ORDER BY requests_count DESC LIMIT 5'
    ).fetchall()
    
    conn.close()
    
    top_keys_list = [
        {"name": key['name'] or 'Unnamed', "requests": key['requests_count']}
        for key in top_keys
    ]
    
    return format_response(
        True,
        "📊 API Usage Statistics",
        {
            "total_keys": total_keys,
            "active_keys": active_keys,
            "total_requests": total_requests,
            "today_requests": today_requests,
            "top_keys": top_keys_list,
            "average_requests_per_key": round(total_requests / max(total_keys, 1), 2)
        }
    )

@app.get("/keys/revoke")
async def revoke_api_key(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password"),
    key_id: int = Query(..., description="ID of the key to revoke")
):
    """Revoke/delete an API key"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM api_keys WHERE id = ?', (key_id,)).fetchone()
    
    if not key_data:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    
    return format_response(
        True,
        f"✅ API key '{key_data['name'] or 'Unnamed'}' has been revoked and deleted",
        {
            "revoked_key_id": key_id,
            "key_name": key_data['name'],
            "final_request_count": key_data['requests_count']
        }
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    conn = get_db_connection()
    db_status = conn.execute('SELECT 1').fetchone() is not None
    conn.close()
    
    return format_response(
        True,
        "✅ Service is healthy",
        {
            "status": "healthy",
            "database": "connected" if db_status else "disconnected",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

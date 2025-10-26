from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
import httpx
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
import os

app = FastAPI()

# Database initialization
def init_db():
    conn = sqlite3.connect('api_keys.db')
    c = conn.cursor()
    
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
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    password_hash = hashlib.sha256("mk123".encode()).hexdigest()
    c.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash) 
        VALUES (?, ?)
    ''', ('mk', password_hash))
    
    conn.commit()
    conn.close()

init_db()

# Utility functions
def generate_api_key():
    return f"pk_{secrets.token_urlsafe(24)}"

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
    return admin and hashlib.sha256(password.encode()).hexdigest() == admin['password_hash']

@app.get("/")
async def root():
    return RedirectResponse("/docs")

@app.get("/key/{api_key}/prompt")
async def proxy_to_pollinations(
    api_key: str,
    text: str = Query(..., description="Text to send to Pollinations.ai")
):
    """Direct proxy to Pollinations.ai - returns only their response"""
    
    # Validate API key
    conn = get_db_connection()
    key_data = conn.execute(
        'SELECT * FROM api_keys WHERE key = ? AND is_active = 1',
        (api_key,)
    ).fetchone()
    
    if not key_data:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check expiration
    if key_data['expires_at'] and datetime.fromisoformat(key_data['expires_at']) < datetime.utcnow():
        conn.close()
        raise HTTPException(status_code=401, detail="API key expired")
    
    # Call Pollinations.ai directly
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            pollinations_url = f"https://text.pollinations.ai/prompt/{text}"
            response = await client.get(pollinations_url)
            response.raise_for_status()
            pollinations_response = response.text
            
    except httpx.TimeoutException:
        conn.close()
        raise HTTPException(status_code=504, detail="Pollinations.ai timeout")
    except httpx.HTTPStatusError as e:
        conn.close()
        raise HTTPException(status_code=502, detail=f"Pollinations.ai error: {e.response.status_code}")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Service error: {str(e)}")
    
    # Update usage stats
    conn.execute(
        '''UPDATE api_keys 
           SET requests_count = requests_count + 1, 
               last_used = CURRENT_TIMESTAMP 
           WHERE key = ?''',
        (api_key,)
    )
    conn.commit()
    conn.close()
    
    # Return ONLY the Pollinations.ai response (no wrapper)
    return pollinations_response

@app.get("/keys/create")
async def create_api_key(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password"),
    key_name: str = Query("Unnamed", description="Name for the key")
):
    """Create new API key"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    new_key = generate_api_key()
    expires_at = datetime.utcnow() + timedelta(days=365)  # 1 year expiry
    
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO api_keys (key, name, expires_at) VALUES (?, ?, ?)',
            (new_key, key_name, expires_at)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Key generation failed")
    
    conn.close()
    
    return {
        "api_key": new_key,
        "key_name": key_name,
        "expires_at": expires_at.isoformat(),
        "usage_url": f"/key/{new_key}/prompt?text=Your+message+here"
    }

@app.get("/keys")
async def list_keys(
    admin_username: str = Query(..., description="Admin username"),
    admin_password: str = Query(..., description="Admin password")
):
    """List all API keys"""
    if not verify_admin(admin_username, admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    conn = get_db_connection()
    keys = conn.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    conn.close()
    
    keys_list = []
    for key in keys:
        keys_list.append({
            "id": key['id'],
            "name": key['name'],
            "key": key['key'],
            "is_active": bool(key['is_active']),
            "requests_count": key['requests_count'],
            "created_at": key['created_at'],
            "last_used": key['last_used']
        })
    
    return keys_list

@app.get("/key/{api_key}/info")
async def get_key_info(api_key: str):
    """Get key information"""
    conn = get_db_connection()
    key_data = conn.execute('SELECT * FROM api_keys WHERE key = ?', (api_key,)).fetchone()
    conn.close()
    
    if not key_data:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return {
        "name": key_data['name'],
        "is_active": bool(key_data['is_active']),
        "requests_count": key_data['requests_count'],
        "created_at": key_data['created_at'],
        "last_used": key_data['last_used'],
        "expires_at": key_data['expires_at']
    }

@app.get("/health")
async def health_check():
    """Health check"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

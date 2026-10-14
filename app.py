import os, time, hmac, hashlib, secrets, csv, io
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session as DBSession

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./proxyproof.db')
SECRET_KEY = os.getenv('PROXYPROOF_SECRET', 'CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT')
TOKEN_WINDOW_SECONDS = 5
SESSION_DURATION_SECONDS = 300
RSSI_THRESHOLD = int(os.getenv('RSSI_THRESHOLD', '-80'))
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    device_id = Column(String, nullable=True)
    device_change_pending = Column(String, nullable=True)

class AttendanceSession(Base):
    __tablename__ = 'attendance_sessions'
    id = Column(Integer, primary_key=True)
    organiser_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    title = Column(String, nullable=False)
    starts_at = Column(DateTime(timezone=True), nullable=False)
    ends_at = Column(DateTime(timezone=True), nullable=False)
    active = Column(Boolean, default=True, nullable=False)

class Attendance(Base):
    __tablename__ = 'attendance'
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('attendance_sessions.id'), nullable=False)
    student_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    marked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    rssi = Column(Integer, nullable=False)
    source = Column(String, default='ble')
    __table_args__ = (UniqueConstraint('session_id', 'student_id', name='uq_session_student'),)

Base.metadata.create_all(bind=engine)
app = FastAPI(title='ProxyProof API', version='1.0.0')

# Demo authentication helpers: PBKDF2 password hashes and signed, expiring bearer tokens.
def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 180_000).hex()
    return f'{salt}${digest}'

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split('$', 1)
        return hmac.compare_digest(hash_password(password, salt).split('$', 1)[1], digest)
    except Exception:
        return False

def b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def issue_token(user: User) -> str:
    import json
    now = int(time.time())
    payload = b64(__import__('json').dumps({'uid': user.id, 'role': user.role, 'exp': now + 12*3600}, separators=(',', ':')).encode())
    sig = b64(hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest())
    return payload + '.' + sig

def current_user(authorization: Optional[str] = Header(None), db: DBSession = Depends(lambda: None)):
    # This placeholder is replaced by the dependency below; retained for readable OpenAPI naming.
    raise RuntimeError('Dependency override expected')

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def auth_user(authorization: Optional[str] = Header(None), db: DBSession = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Missing bearer token')
    token = authorization[7:]
    try:
        payload, sig = token.split('.', 1)
        expected = b64(hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected): raise ValueError('bad signature')
        import base64, json
        data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        if data['exp'] < int(time.time()): raise ValueError('expired')
        user = db.get(User, int(data['uid']))
        if not user: raise ValueError('unknown user')
        return user
    except Exception:
        raise HTTPException(401, 'Invalid or expired token')

def require_role(role: str):
    def checker(user: User = Depends(auth_user)):
        if user.role != role: raise HTTPException(403, f'{role} role required')
        return user
    return checker

class LoginIn(BaseModel):
    username: str
    password: str
    device_id: str = Field(min_length=6, max_length=128)
class SessionIn(BaseModel):
    title: str = Field(min_length=2, max_length=100)
    duration_seconds: int = Field(default=SESSION_DURATION_SECONDS, ge=30, le=1800)
class MarkIn(BaseModel):
    session_id: int
    token: str = Field(min_length=16, max_length=16)
    device_id: str = Field(min_length=6, max_length=128)
    rssi: int = Field(ge=-127, le=20)
class ManualIn(BaseModel):
    student_username: str

@app.on_event('startup')
def seed_demo_users():
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(username='organiser').first():
            db.add(User(username='organiser', password_hash=hash_password('organiser123'), role='organiser'))
        if not db.query(User).filter_by(username='student1').first():
            db.add(User(username='student1', password_hash=hash_password('student123'), role='student'))
        if not db.query(User).filter_by(username='student2').first():
            db.add(User(username='student2', password_hash=hash_password('student123'), role='student'))
        if not db.query(User).filter_by(username='admin').first():
            db.add(User(username='admin', password_hash=hash_password('admin12345'), role='admin'))
        db.commit()
    finally: db.close()

@app.get('/', response_class=HTMLResponse)
def dashboard():
    return '''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>ProxyProof</title><style>body{font-family:system-ui;background:#f4f7fb;color:#172033;margin:0;padding:24px}main{max-width:850px;margin:auto}.card{background:white;border-radius:16px;padding:20px;margin:14px 0;box-shadow:0 4px 18px #10204012}input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #ccd3df}button{background:#1746a2;color:white;border:0;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #e5e9f0}.muted{color:#64748b}</style></head><body><main><h1>ProxyProof <span class="muted">/ organiser dashboard</span></h1><p class="muted">Sign in with the demo organiser account to manage sessions.</p><section class="card"><h2>Login</h2><input id="user" value="organiser" aria-label="username"><input id="pass" type="password" value="organiser123" aria-label="password"><button onclick="login()">Sign in</button><span id="status"></span></section><section class="card"><h2>Start attendance session</h2><input id="title" value="CSE Lecture" aria-label="session title"><button onclick="startSession()">Start 5-minute session</button><button onclick="refresh()">Refresh dashboard</button><p id="sessionInfo"></p></section><section class="card"><h2>Live attendance</h2><div id="sessions">Sign in to load sessions.</div><p><a id="csv" href="#">Export selected session CSV</a></p></section><p class="muted">Demo only. Change the secret, add HTTPS, rate limits, and production authentication before real use.</p></main><script>let tok='',selected='';async function api(path,opts={}){opts.headers={...(opts.headers||{}),...(tok?{Authorization:'Bearer '+tok}:{}),'Content-Type':'application/json'};let r=await fetch(path,opts);let d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}async function login(){try{let d=await api('/api/login',{method:'POST',body:JSON.stringify({username:document.querySelector('#user').value,password:document.querySelector('#pass').value,device_id:'web-dashboard-organiser-device'})});tok=d.access_token;document.querySelector('#status').textContent=' Signed in';await refresh()}catch(e){document.querySelector('#status').textContent=e.message}}async function startSession(){try{let d=await api('/api/sessions',{method:'POST',body:JSON.stringify({title:document.querySelector('#title').value,duration_seconds:300})});selected=d.id;document.querySelector('#sessionInfo').textContent='Session #'+d.id+' is active until '+d.ends_at;document.querySelector('#csv').href='/api/sessions/'+d.id+'/csv?token='+encodeURIComponent(tok);await refresh()}catch(e){alert(e.message)}}async function refresh(){try{let d=await api('/api/sessions');document.querySelector('#sessions').innerHTML=d.map(s=>`<div><b>#${s.id} — ${s.title}</b> ${s.active?'🟢 Active':'⚪ Closed'} <button onclick="loadMarks(${s.id})">View marks</button> <button onclick="closeSession(${s.id})">Close</button> <a href="/api/sessions/${s.id}/csv?token=${encodeURIComponent(tok)}">CSV</a><div id="marks-${s.id}"></div></div><hr>`).join('')||'No sessions yet.'}catch(e){document.querySelector('#sessions').textContent=e.message}}async function loadMarks(id){try{let d=await api('/api/sessions/'+id+'/attendance');document.querySelector('#marks-'+id).innerHTML='<table><tr><th>Student</th><th>Marked at</th><th>RSSI</th><th>Action</th></tr>'+d.map(a=>`<tr><td>${a.username}</td><td>${a.marked_at}</td><td>${a.rssi}</td><td><button onclick="removeMark(${id},'${a.username}')">Remove</button></td></tr>`).join('')+'</table><input id="add-'+id+'" placeholder="student username"><button onclick="addMark('+id+')">Manual add</button>'}catch(e){alert(e.message)}}async function closeSession(id){try{await api('/api/sessions/'+id+'/close',{method:'POST'});await refresh()}catch(e){alert(e.message)}}async function addMark(id){try{await api('/api/sessions/'+id+'/manual-add',{method:'POST',body:JSON.stringify({student_username:document.querySelector('#add-'+id).value})});await loadMarks(id)}catch(e){alert(e.message)}}async function removeMark(id,username){try{await api('/api/sessions/'+id+'/attendance/'+encodeURIComponent(username),{method:'DELETE'});await loadMarks(id)}catch(e){alert(e.message)}}</script></body></html>'''

@app.post('/api/login')
def login(data: LoginIn, db: DBSession = Depends(get_db)):
    user = db.query(User).filter_by(username=data.username).first()
    if not user or not verify_password(data.password, user.password_hash): raise HTTPException(401, 'Incorrect username or password')
    # Device binding is enforced for students. Organisers may use the web dashboard and a broadcast phone.
    if user.role == 'student':
        if user.device_id is None:
            user.device_id = data.device_id
            db.commit()
        elif user.device_id != data.device_id:
            user.device_change_pending = data.device_id
            db.commit()
            raise HTTPException(403, 'This account is bound to another device. Ask an admin to approve the device change.')
    return {'access_token': issue_token(user), 'token_type': 'bearer', 'role': user.role, 'username': user.username, 'device_id': user.device_id}

def token_for(session_id: int, bucket: int) -> str:
    raw = hmac.new(SECRET_KEY.encode(), f'{session_id}:{bucket}'.encode(), hashlib.sha256).hexdigest()[:16]
    return raw

@app.post('/api/sessions')
def create_session(data: SessionIn, user: User = Depends(require_role('organiser')), db: DBSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    s = AttendanceSession(organiser_id=user.id, title=data.title, starts_at=now, ends_at=datetime.fromtimestamp(now.timestamp()+data.duration_seconds, timezone.utc), active=True)
    db.add(s); db.commit(); db.refresh(s)
    return {'id': s.id, 'title': s.title, 'starts_at': s.starts_at.isoformat(), 'ends_at': s.ends_at.isoformat(), 'active': s.active}

@app.get('/api/sessions')
def list_sessions(user: User = Depends(auth_user), db: DBSession = Depends(get_db)):
    rows = db.query(AttendanceSession).order_by(AttendanceSession.id.desc()).limit(100).all()
    return [{'id':s.id,'title':s.title,'starts_at':s.starts_at.isoformat(),'ends_at':s.ends_at.isoformat(),'active':s.active} for s in rows]

@app.get('/api/sessions/{session_id}/token')
def get_ble_token(session_id: int, user: User = Depends(require_role('organiser')), db: DBSession = Depends(get_db)):
    s = db.get(AttendanceSession, session_id)
    if not s or s.organiser_id != user.id: raise HTTPException(404, 'Session not found')
    if not s.active or datetime.now(timezone.utc).timestamp() > s.ends_at.timestamp(): raise HTTPException(400, 'Session is closed or expired')
    bucket = int(time.time()) // TOKEN_WINDOW_SECONDS
    return {'session_id': s.id, 'token': token_for(s.id, bucket), 'valid_for_seconds': TOKEN_WINDOW_SECONDS}

@app.post('/api/attendance/mark')
def mark_attendance(data: MarkIn, user: User = Depends(require_role('student')), db: DBSession = Depends(get_db)):
    if user.device_id != data.device_id: raise HTTPException(403, 'Unregistered device')
    s = db.get(AttendanceSession, data.session_id)
    now = datetime.now(timezone.utc)
    if not s or not s.active or now.timestamp() > s.ends_at.timestamp(): raise HTTPException(400, 'Session is not active')
    if data.rssi < RSSI_THRESHOLD: raise HTTPException(403, f'Signal too weak (RSSI {data.rssi}; need at least {RSSI_THRESHOLD})')
    bucket = int(time.time()) // TOKEN_WINDOW_SECONDS
    valid = {token_for(s.id, bucket), token_for(s.id, bucket-1)}
    if not any(hmac.compare_digest(data.token, t) for t in valid): raise HTTPException(403, 'Token expired or invalid')
    existing = db.query(Attendance).filter_by(session_id=s.id, student_id=user.id).first()
    if existing: return {'status':'already_marked','marked_at':existing.marked_at.isoformat()}
    a = Attendance(session_id=s.id, student_id=user.id, rssi=data.rssi, source='ble')
    db.add(a); db.commit(); db.refresh(a)
    return {'status':'marked','session_id':s.id,'student':user.username,'marked_at':a.marked_at.isoformat()}

@app.post('/api/sessions/{session_id}/close')
def close_session(session_id: int, user: User = Depends(require_role('organiser')), db: DBSession = Depends(get_db)):
    s = db.get(AttendanceSession, session_id)
    if not s or s.organiser_id != user.id: raise HTTPException(404, 'Session not found')
    s.active = False; db.commit(); return {'status':'closed','id':s.id}

@app.get('/api/sessions/{session_id}/attendance')
def get_attendance(session_id: int, user: User = Depends(auth_user), db: DBSession = Depends(get_db)):
    s = db.get(AttendanceSession, session_id)
    if not s: raise HTTPException(404, 'Session not found')
    rows = db.query(Attendance, User).join(User, User.id == Attendance.student_id).filter(Attendance.session_id==session_id).order_by(Attendance.marked_at.asc()).all()
    return [{'username':u.username,'marked_at':a.marked_at.isoformat(),'rssi':a.rssi,'source':a.source} for a,u in rows]

@app.post('/api/sessions/{session_id}/manual-add')
def manual_add(session_id: int, data: ManualIn, user: User = Depends(require_role('organiser')), db: DBSession = Depends(get_db)):
    s=db.get(AttendanceSession,session_id)
    if not s or s.organiser_id != user.id: raise HTTPException(404,'Session not found')
    student=db.query(User).filter_by(username=data.student_username,role='student').first()
    if not student: raise HTTPException(404,'Student not found')
    a=db.query(Attendance).filter_by(session_id=session_id,student_id=student.id).first()
    if not a:
        a=Attendance(session_id=session_id,student_id=student.id,rssi=0,source='manual');db.add(a);db.commit()
    return {'status':'added','student':student.username}

@app.delete('/api/sessions/{session_id}/attendance/{username}')
def remove_attendance(session_id: int, username: str, user: User = Depends(require_role('organiser')), db: DBSession = Depends(get_db)):
    s=db.get(AttendanceSession,session_id)
    if not s or s.organiser_id != user.id: raise HTTPException(404,'Session not found')
    student=db.query(User).filter_by(username=username,role='student').first()
    if student: db.query(Attendance).filter_by(session_id=session_id,student_id=student.id).delete();db.commit()
    return {'status':'removed','student':username}

@app.get('/api/sessions/{session_id}/csv')
def export_csv(session_id: int, token: Optional[str] = None, authorization: Optional[str] = Header(None), db: DBSession = Depends(get_db)):
    # Browser-friendly token query is supported for the dashboard's download link.
    if token and not authorization: authorization = 'Bearer ' + token
    user = auth_user(authorization, db)
    if user.role != 'organiser': raise HTTPException(403,'organiser role required')
    s=db.get(AttendanceSession,session_id)
    if not s or s.organiser_id != user.id: raise HTTPException(404,'Session not found')
    rows=db.query(Attendance,User).join(User,User.id==Attendance.student_id).filter(Attendance.session_id==session_id).order_by(User.username).all()
    out=io.StringIO(); w=csv.writer(out);w.writerow(['session_id','session_title','student_username','marked_at_utc','rssi','source'])
    for a,u in rows:w.writerow([s.id,s.title,u.username,a.marked_at.isoformat(),a.rssi,a.source])
    return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename=proxyproof-session-{session_id}.csv'})

@app.get('/api/students/me/history')
def student_history(user: User = Depends(require_role('student')), db: DBSession = Depends(get_db)):
    rows=db.query(Attendance,AttendanceSession).join(AttendanceSession,AttendanceSession.id==Attendance.session_id).filter(Attendance.student_id==user.id).order_by(Attendance.marked_at.desc()).all()
    total=db.query(AttendanceSession).filter(AttendanceSession.active==False).count()
    return {'marked_sessions':[{'session_id':s.id,'title':s.title,'marked_at':a.marked_at.isoformat(),'source':a.source} for a,s in rows], 'marked_count':len(rows), 'closed_sessions_count':total, 'note':'Percentage needs the student’s eligible-session roster; this demo reports marks and closed session count only.'}


@app.get('/api/admin/device-requests')
def list_device_requests(user: User = Depends(require_role('admin')), db: DBSession = Depends(get_db)):
    rows = db.query(User).filter(User.role == 'student', User.device_change_pending.isnot(None)).order_by(User.username).all()
    return [{'username': u.username, 'current_device_id': u.device_id, 'requested_device_id': u.device_change_pending} for u in rows]

class DeviceApprovalIn(BaseModel):
    username: str
    device_id: str = Field(min_length=6, max_length=128)

@app.post('/api/admin/device-approval')
def approve_device_change(data: DeviceApprovalIn, user: User = Depends(require_role('admin')), db: DBSession = Depends(get_db)):
    student = db.query(User).filter_by(username=data.username, role='student').first()
    if not student: raise HTTPException(404, 'Student not found')
    if not student.device_change_pending or student.device_change_pending != data.device_id:
        raise HTTPException(409, 'No matching pending device change request')
    student.device_id = student.device_change_pending
    student.device_change_pending = None
    db.commit()
    return {'status':'approved','username':student.username,'device_id':student.device_id}

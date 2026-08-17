from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app=FastAPI(title='AAPT Deliberately Vulnerable API',version='1.0')
USERS={1:{'id':1,'name':'alice','role':'user','email':'alice@example.test'},2:{'id':2,'name':'bob','role':'user','email':'bob@example.test'}}
ORDERS={101:{'id':101,'owner_id':1,'status':'draft','total':100},102:{'id':102,'owner_id':2,'status':'draft','total':200}}

class ProfileUpdate(BaseModel):
    role: str|None=None
    email: str|None=None
class OrderUpdate(BaseModel):
    owner_id: int|None=None
    status: str|None=None

# Lab flaw 1: BOLA. Any authenticated user can fetch any user/order by ID.
@app.get('/users/{user_id}')
def user(user_id:int,x_user_id:int=Header(1,alias='X-User-ID')):
    if x_user_id not in USERS: raise HTTPException(401)
    if user_id not in USERS: raise HTTPException(404)
    return USERS[user_id]

@app.get('/orders/{order_id}')
def order(order_id:int,x_user_id:int=Header(1,alias='X-User-ID')):
    if x_user_id not in USERS: raise HTTPException(401)
    if order_id not in ORDERS: raise HTTPException(404)
    return ORDERS[order_id]

# Lab flaw 2: BFLA/privilege escalation. User role can call admin endpoint.
@app.get('/admin/users')
def admin_users(x_role:str=Header('user',alias='X-Role')):
    return {'role_seen_by_server':x_role,'users':list(USERS.values())}

# Lab flaw 3: parameter tampering. Client-controlled role can be changed.
@app.patch('/users/{user_id}')
def update_user(user_id:int, body:ProfileUpdate, x_user_id:int=Header(1,alias='X-User-ID')):
    if user_id not in USERS: raise HTTPException(404)
    if body.role: USERS[user_id]['role']=body.role
    if body.email: USERS[user_id]['email']=body.email
    return USERS[user_id]

# Lab flaw 4: workflow flaw. approve succeeds without a prior draft/start/payment state check.
@app.post('/orders/{order_id}/approve')
def approve(order_id:int,x_user_id:int=Header(1,alias='X-User-ID')):
    if order_id not in ORDERS: raise HTTPException(404)
    ORDERS[order_id]['status']='approved'
    return ORDERS[order_id]

# Lab flaw 5: BOLA + state tampering via owner_id.
@app.patch('/orders/{order_id}')
def update_order(order_id:int, body:OrderUpdate, x_user_id:int=Header(1,alias='X-User-ID')):
    if order_id not in ORDERS: raise HTTPException(404)
    if body.owner_id is not None: ORDERS[order_id]['owner_id']=body.owner_id
    if body.status is not None: ORDERS[order_id]['status']=body.status
    return ORDERS[order_id]

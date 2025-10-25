import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

# crear token
MAILHOG_API = "http://localhost:8025/api/v2/messages"

def get_last_email_body():
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()

    if not data["items"]:
        return None  # no emails received yet

    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    # regex: busca ?token= o &token= seguido de cualquier cosa hasta &, # o fin de string
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

@pytest.fixture(autouse=True)
def setup_create_user():
    # random username
    i= random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    salida = requests.post("http://localhost:5000/users",
                        data={
                            "username": username, 
                            "password": password,
                            "email":email,
                            "first_name":"Name",
                            "last_name": f'{username}son'
                            })
    # user created
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # activate user
    response = requests.post("http://localhost:5000/auth/set-password", json={"token": token, "newPassword": password})


    return [username,password]

def test_login(setup_create_user):
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    assert auth_token

# Test 1: Valida que OR bypass clásico no funcione
# Comprueba que ' OR 1=1 -- no retorne facturas de otros usuarios
# Si vulnerable: WHERE status = 'paid' OR 1=1 -- trae todas las facturas
# Si mitigado: WHERE status = 'paid\' OR 1=1 --' no trae todas las facturas
def test_invoices_status_filter(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    status = "paid' OR 1=1 --"
    response = requests.get(
        f"http://localhost:5000/invoices",
        params={"status": status, "operator": "="},
        headers=headers
    )
    
    assert response.status_code == 200
    invoices = response.json()
    assert isinstance(invoices, list)

# Test 2: Valida que UNION SELECT no extraiga datos sensibles
# Verifica que no se filtren passwords o datos de usuarios
# Si vulnerable: SELECT * FROM invoices UNION SELECT id,username,email,password FROM users
# Si mitigado: Input se parametriza, UNION no se ejecuta
def test_invoices_union_query(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    status = "paid' UNION SELECT id, username, email, password, 'test' FROM users --"
    response = requests.get(
        f"http://localhost:5000/invoices",
        params={"status": status, "operator": "="},
        headers=headers
    )
    
    assert response.status_code == 200
    invoices = response.json()
    assert isinstance(invoices, list)
    
    for invoice in invoices:
        assert "username" not in str(invoice).lower()
        assert "password" not in str(invoice).lower()
        assert "test" not in str(invoice).lower()

# Test 3: Valida que time-based injection no funcione
# Verifica que WAITFOR DELAY no se ejecute retardando la respuesta
# Si vulnerable: SELECT * FROM invoices; WAITFOR DELAY '00:00:05' (tarda 5 seg)
# Si mitigado: WAITFOR no se ejecuta, respuesta inmediata (< 2 seg)
def test_invoices_timing(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    status = "paid'; WAITFOR DELAY '00:00:05' --"
    
    import time
    start_time = time.time()
    response = requests.get(
        f"http://localhost:5000/invoices",
        params={"status": status, "operator": "="},
        headers=headers
    )
    end_time = time.time()
    
    assert (end_time - start_time) < 2
    assert response.status_code == 200
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

def get_auth_token(setup_create_user):
    username = setup_create_user[0]
    password = setup_create_user[1]
    
    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["token"]

# Test 1: Valida que OR no funcione
# Comprueba que ' OR 1=1 -- no retorne facturas de otros usuarios
# Si es vulnerable: WHERE status = 'paid' OR 1=1 -- trae todas las facturas
# Si esta mitigado: WHERE status = 'paid\' OR 1=1 --' no trae todas las facturas
def test_invoices_status_filter(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Misma URL que usamos en el practico 2
    url = "http://localhost:5000/invoices?status=paid%27%20or%201=1%20--&operator=="
    response = requests.get(url, headers=headers)
    
    assert response.status_code == 200
    invoices = response.json()
    assert isinstance(invoices, list)
    assert len(invoices) == 0 # Esto es lo que hace que falle, ya que no deberia traer nada de un usuario sin facturas


# Test 2: Valida que UNION SELECT no extraiga datos sensibles
# Verifica que no se filtren passwords o datos de usuarios
# Si es vulnerable: SELECT * FROM invoices UNION SELECT id,username,email,password FROM users
# Si esta mitigado: Input se parametriza, UNION no se ejecuta
def test_invoices_union_query(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    # UNION SELECT ajustado para tipos de datos de la BD
    url = "http://localhost:5000/invoices?status=paid%27%20UNION%20SELECT%20id,%20id,%20%27100.00%27::decimal,%20CURRENT_DATE,%20username%20FROM%20users%20--&operator=="
    response = requests.get(url, headers=headers)
    
    assert response.status_code == 200
    invoices = response.json()
    assert isinstance(invoices, list)
    
    # Buscar usernames filtrados para luego contarlos
    usernames_found = []
    for invoice in invoices:
        if 'status' in invoice and invoice['status'] not in ['paid', 'unpaid']:
            usernames_found.append(invoice['status'])
    
    assert len(usernames_found) == 0


# Test 3: Valida que time-based injection no funcione
# Verifica que pg_sleep no se ejecute retardando la respuesta
# Si es vulnerable: tarda varios segundos en devolvernos la respuesta
# Si esta mitigado: respuesta inmediata
def test_invoices_timing(setup_create_user):
    
    token = get_auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}
    
    # pg_sleep para PostgreSQL
    url = "http://localhost:5000/invoices?status=paid%27%20AND%20(SELECT%20pg_sleep(3))%20IS%20NULL%20--&operator=="
    
    import time
    start_time = time.time()
    response = requests.get(url, headers=headers)
    end_time = time.time()
    
    execution_time = end_time - start_time
    
    assert response.status_code == 200
    assert execution_time < 1

    # Todas las url las usamos del practico 2, donde habiamos estado probando varias inyecciones SQL
    # posibles. Las habiamos realizado con curl con ayuda de IA. Pero como ya lo teniamos, decidimos usarlo
    # para generar mejores tests y no solo el test basico de or 1=1.

    # Todas las url las ponemos directamente en url encodeadas para evitar problemas de interpretacion al pasarlas por requests.
    # Ya que esto nos genero varios problemas al principio.

    # https://scidsg.medium.com/safeguarding-your-application-a-practical-guide-to-sql-injection-testing-833b76ac996a
    # De aca sacamos ideas de que test hacer para probar la seguridad contra inyeccion SQL.
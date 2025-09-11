import io, pytest
from server.src.server import create_app as _create_app

@pytest.fixture
def app(tmp_path, monkeypatch):
    app = _create_app()
    app.config["SECRET_KEY"] = "test"
    app.config["STORAGE_DIR"] = tmp_path / "storage"
    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def _auth(client, email="a@ex.com", login="a", password="p"):
    client.post("/api/create-user", json={"email": email, "login": login, "password": password})
    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.get_json()['token']}"}

def _pdf_bytes():
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"

def test_upload_rejects_non_pdf(client):
    headers = _auth(client)
    r = client.post("/api/upload-document", headers=headers, data={"file": (io.BytesIO(b'NOPE'), "x.txt")}, content_type="multipart/form-data")
    assert r.status_code == 400

def test_plugin_loader_403_by_default(client):
    headers = _auth(client)
    r = client.post("/api/load-plugin", headers=headers, json={"filename": "anything.pkl"})
    assert r.status_code in (400, 403, 404)

def test_owner_checks(client):
    a = _auth(client, "a1@ex.com", "a1")
    b = _auth(client, "b1@ex.com", "b1")
    r = client.post("/api/upload-document", headers=a, data={"file": (io.BytesIO(_pdf_bytes()), "d.pdf")}, content_type="multipart/form-data")
    assert r.status_code == 201
    did = r.get_json()["id"]
    r = client.post("/api/read-watermark", headers=b, json={"id": did, "method": "meta-hmac-v1", "key": "k"})
    assert r.status_code in (400, 403, 404)
    r = client.delete(f"/api/delete-document/{did}", headers=b)
    assert r.status_code in (400, 403, 404)

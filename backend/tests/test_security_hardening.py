import io


def test_security_headers_present(client):
    r = client.get('/')
    assert r.status_code == 200

    # Core headers
    assert 'content-security-policy' in r.headers
    assert r.headers.get('x-frame-options') == 'DENY'
    assert r.headers.get('x-content-type-options') == 'nosniff'
    assert r.headers.get('referrer-policy') == 'no-referrer'


def test_origin_guard_blocks_cross_site_posts(client):
    payload = {
        'role': 'doktor',
        'seniority': 'Orta Seviye',
        'language': 'Türkçe',
        'n_questions': 1,
        'cv_text': ''
    }

    r = client.post('/api/start', json=payload, headers={'Origin': 'https://evil.example'})
    assert r.status_code == 403
    assert 'request_id' in r.json()


def test_parse_pdf_rejects_non_pdf_upload(client):
    fake = io.BytesIO(b'not-a-pdf')
    files = {'file': ('notpdf.txt', fake, 'text/plain')}
    r = client.post('/api/parse_pdf', files=files)
    assert r.status_code == 400


def test_security_txt_route(client):
    r = client.get('/.well-known/security.txt')
    assert r.status_code == 200
    assert 'Contact:' in r.text

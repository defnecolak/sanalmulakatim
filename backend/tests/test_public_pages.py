def test_public_config_contains_compliance_fields(client):
    r = client.get('/api/public_config')
    assert r.status_code == 200
    j = r.json()
    assert 'pro_price_try' in j
    assert 'pro_title' in j
    assert 'company' in j
    assert isinstance(j['company'], dict)
    assert 'legal_name' in j['company']
    assert 'address' in j['company']


def test_about_page_exists(client):
    r = client.get('/about')
    assert r.status_code == 200
    assert 'Hakkımızda' in r.text

from http import HTTPStatus

from jwt import decode

from fast_zero.security import SECRET_KEY, create_access_token


def test_jwt():
    data = {'test': 'test'}
    token = create_access_token(data)

    decoded = decode(token, SECRET_KEY, algorithms=['HS256'])

    assert decoded['test'] == data['test']
    assert decoded['exp']


def test_jwt_missing_token(client, user):
    data = {}
    token = create_access_token(data)

    response = client.delete(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}
    assert response.headers['WWW-Authenticate'] == 'Bearer'


def test_jwt_invalid_token(client):
    response = client.delete(
        '/users/1', headers={'Authorization': 'Bearer token-invalid'}
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}


def test_jwt_wrong_email(client, user, token):
    user.email = 'failemail@test.com'
    response = client.delete(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json() == {'detail': 'Could not validate credentials'}
    assert response.headers['WWW-Authenticate'] == 'Bearer'

from http import HTTPStatus

from fast_zero.schemas import UserPublic


def test_root_deve_retornar_ok_e_ola_mundo(client):
    response = client.get('/')

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {'message': 'Hello World'}


def test_create_user(client):
    response = client.post(
        '/users/',
        json={
            'username': 'alice',
            'email': 'alice@example.com',
            'password': 'secret',
        },
    )

    assert response.status_code == HTTPStatus.CREATED
    assert response.json() == {
        'username': 'alice',
        'email': 'alice@example.com',
        'id': 1,
    }


def test_read_users(client):
    response = client.get('/users')

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {'users': []}


def test_read_users_with_users(client, user):
    user_schema = UserPublic.model_validate(user).model_dump()
    response = client.get('/users/')
    assert response.json() == {'users': [user_schema]}


def test_update_user(client, user, token):
    response = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
        json={
            'username': 'bob',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {
        'username': 'bob',
        'email': 'bob@example.com',
        'id': user.id,
    }


# def test_update_user_not_found(client):
#     response = client.put(
#         '/users/100',
#         json={
#             'username': 'bob',
#             'email': 'bob@example.com',
#             'password': 'mynewpassword',
#         },
#     )
#     assert response.status_code == HTTPStatus.NOT_FOUND
#     assert response.json() == {'detail': 'User not found'}


def test_update_integrity_error(client, user, token):
    client.post(
        '/users',
        json={
            'username': 'fausto',
            'email': 'fausto@example.com',
            'password': 'secret',
        },
    )

    response_update = client.put(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
        json={
            'username': 'fausto',
            'email': 'bob@example.com',
            'password': 'mynewpassword',
        },
    )

    assert response_update.status_code == HTTPStatus.CONFLICT
    assert response_update.json() == {
        'detail': 'Username or email already exists'
    }


def test_delete_user(client, user, token):
    response = client.delete(
        f'/users/{user.id}',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {'message': 'User deleted'}


# def test_delete_user_not_found(client):
#     response = client.delete('/users/100')

#     assert response.status_code == HTTPStatus.NOT_FOUND
#     assert response.json() == {'detail': 'User not found'}


# def test_find_user(client, user):
#     response = client.get('/users/1')

#     assert response.status_code == HTTPStatus.OK
#     assert response.json() == {
#         'id': 1,
#         'username': 'Teste',
#         'email': 'teste@test.com',
#     }


# def test_find_user_not_found(client):
#     response = client.get('/users/100')

#     assert response.status_code == HTTPStatus.NOT_FOUND
#     assert response.json() == {'detail': 'User not found'}


# def test_create_user_with_username_already(client, user):
#     client.post(
#         '/users',
#         json={
#             'username': 'fausto',
#             'email': 'fausto@example.com',
#             'password': 'secret',
#         },
#     )

#     response_other_user = client.post(
#         '/users',
#         json={
#             'username': 'fausto',
#             'email': 'fausto2@example.com',
#             'password': 'secret',
#         },
#     )

#     assert response_other_user.status_code == HTTPStatus.BAD_REQUEST
#     assert response_other_user.json() == {
# 'detail': 'Username already exists'}


# def test_create_user_with_email_already(client, user):
#     client.post(
#         '/users',
#         json={
#             'username': 'fausto',
#             'email': 'fausto@example.com',
#             'password': 'secret',
#         },
#     )

#     response_other_user = client.post(
#         '/users',
#         json={
#             'username': 'fausto2',
#             'email': 'fausto@example.com',
#             'password': 'secret',
#         },
#     )

#     assert response_other_user.status_code == HTTPStatus.BAD_REQUEST
#     assert response_other_user.json() ==
# {'detail': 'Email already exists'}


def test_get_token(client, user):
    response = client.post(
        '/token',
        data={'username': user.email, 'password': user.clean_password},
    )
    token = response.json()

    assert response.status_code == HTTPStatus.OK
    assert 'access_token' in token
    assert token['token_type']

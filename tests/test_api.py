import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

User = get_user_model()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def test_user():
    return User.objects.create_user(username='testuser', password='testpassword')


@pytest.mark.django_db
def test_obtain_token_success(api_client, test_user):
    url = reverse('token_obtain_pair')
    response = api_client.post(url, {'username': 'testuser', 'password': 'testpassword'}, format='json')
    assert response.status_code == 200
    assert 'access' in response.data
    assert 'refresh' in response.data


@pytest.mark.django_db
def test_obtain_token_fail(api_client, test_user):
    url = reverse('token_obtain_pair')
    response = api_client.post(url, {'username': 'testuser', 'password': 'wrongpassword'}, format='json')
    assert response.status_code == 401


@pytest.mark.django_db
def test_refresh_token(api_client, test_user):
    url = reverse('token_obtain_pair')
    response = api_client.post(url, {'username': 'testuser', 'password': 'testpassword'}, format='json')
    refresh_token = response.data['refresh']

    refresh_url = reverse('token_refresh')
    response = api_client.post(refresh_url, {'refresh': refresh_token}, format='json')
    assert response.status_code == 200
    assert 'access' in response.data


@pytest.mark.django_db
def test_verify_token(api_client, test_user):
    url = reverse('token_obtain_pair')
    response = api_client.post(url, {'username': 'testuser', 'password': 'testpassword'}, format='json')
    access_token = response.data['access']

    verify_url = reverse('token_verify')
    response = api_client.post(verify_url, {'token': access_token}, format='json')
    assert response.status_code == 200


@pytest.mark.django_db
def test_logout(api_client, test_user):
    url = reverse('token_obtain_pair')
    response = api_client.post(url, {'username': 'testuser', 'password': 'testpassword'}, format='json')
    refresh_token = response.data['refresh']
    access_token = response.data['access']

    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

    logout_url = reverse('logout')
    response = api_client.post(logout_url, {'refresh': refresh_token}, format='json')
    assert response.status_code == 205

    # Verify the token is blacklisted
    with pytest.raises(TokenError):
        RefreshToken(refresh_token)

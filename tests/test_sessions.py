import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from django_myuser.models import UserSession

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def test_user():
    return User.objects.create_user(username='testuser', password='testpassword')

@pytest.mark.django_db
def test_list_sessions(api_client, test_user):
    UserSession.objects.create(user=test_user, ip_address='127.0.0.1', user_agent='test-agent', refresh_token='token1')
    UserSession.objects.create(user=test_user, ip_address='127.0.0.2', user_agent='test-agent-2', refresh_token='token2')
    
    url = reverse('sessions_list')
    api_client.force_authenticate(user=test_user)
    response = api_client.get(url)
    assert response.status_code == 200
    assert len(response.data) == 2

@pytest.mark.django_db
def test_delete_session(api_client, test_user):
    session = UserSession.objects.create(user=test_user, ip_address='127.0.0.1', user_agent='test-agent', refresh_token='token1')
    
    url = reverse('sessions_detail', kwargs={'pk': session.id})
    api_client.force_authenticate(user=test_user)
    response = api_client.delete(url)
    assert response.status_code == 204
    assert UserSession.objects.filter(user=test_user).count() == 0

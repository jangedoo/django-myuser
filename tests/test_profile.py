import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def test_user():
    return User.objects.create_user(username='testuser', password='testpassword')

@pytest.mark.django_db
def test_get_profile(api_client, test_user):
    url = reverse('profile')
    api_client.force_authenticate(user=test_user)
    response = api_client.get(url)
    assert response.status_code == 200
    assert response.data['marketing_consent'] is False

@pytest.mark.django_db
def test_update_profile(api_client, test_user):
    url = reverse('profile')
    api_client.force_authenticate(user=test_user)
    response = api_client.patch(url, {'marketing_consent': True}, format='json')
    assert response.status_code == 200
    assert response.data['marketing_consent'] is True
    test_user.profile.refresh_from_db()
    assert test_user.profile.marketing_consent is True

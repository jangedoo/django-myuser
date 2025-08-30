import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from django_myuser.models import DataRequest

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def test_user():
    return User.objects.create_user(username='testuser', password='testpassword')

@pytest.mark.django_db
def test_create_data_request(api_client, test_user):
    url = reverse('data_requests')
    api_client.force_authenticate(user=test_user)
    response = api_client.post(url, {'request_type': 'EXPORT'}, format='json')
    assert response.status_code == 201
    assert response.data['request_type'] == 'EXPORT'
    assert response.data['status'] == 'PENDING'
    assert DataRequest.objects.filter(user=test_user).count() == 1

@pytest.mark.django_db
def test_list_data_requests(api_client, test_user):
    DataRequest.objects.create(user=test_user, request_type='EXPORT')
    DataRequest.objects.create(user=test_user, request_type='DELETE')
    
    url = reverse('data_requests')
    api_client.force_authenticate(user=test_user)
    response = api_client.get(url)
    assert response.status_code == 200
    assert len(response.data) == 2

# API Reference

This document provides detailed information about all API endpoints available in the django-myuser package.

## Authentication

All endpoints except social authentication require JWT authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Base URL

All API endpoints are prefixed with your configured URL path. If you include urls as:

```python
path('api/auth/', include('django_myuser.urls')),
```

Then all endpoints will be available at `/api/auth/`.

---

## JWT Authentication Endpoints

### Obtain Token Pair

**Endpoint:** `POST /token/`

**Description:** Authenticate user and receive JWT token pair.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "securepassword"
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Error Responses:**
- `400 Bad Request`: Invalid credentials or missing fields
- `401 Unauthorized`: Authentication failed

---

### Refresh Token

**Endpoint:** `POST /token/refresh/`

**Description:** Refresh access token using refresh token.

**Request Body:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Note:** With `ROTATE_REFRESH_TOKENS=True`, a new refresh token is returned and the old one is blacklisted.

---

### Verify Token

**Endpoint:** `POST /token/verify/`

**Description:** Verify if a token is valid.

**Request Body:**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200 OK):**
```json
{}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired token

---

### Logout

**Endpoint:** `POST /logout/`

**Description:** Logout user and blacklist refresh token.

**Authentication:** Required

**Request Body:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200 OK):**
```json
{
    "message": "Successfully logged out."
}
```

---

## Social Authentication Endpoints

### Google Login

**Endpoint:** `POST /social/google/`

**Description:** Authenticate using Google OAuth2.

**Request Body:**
```json
{
    "access_token": "ya29.a0AfH6SMBx..."
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "pk": 1,
        "username": "",
        "email": "user@gmail.com",
        "first_name": "John",
        "last_name": "Doe"
    }
}
```

---

### GitHub Login

**Endpoint:** `POST /social/github/`

**Description:** Authenticate using GitHub OAuth2.

**Request Body:**
```json
{
    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a"
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "pk": 1,
        "username": "johndoe",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe"
    }
}
```

---

### Facebook Login

**Endpoint:** `POST /social/facebook/`

**Description:** Authenticate using Facebook OAuth2.

**Request Body:**
```json
{
    "access_token": "EAABwz..."
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "pk": 1,
        "username": "",
        "email": "user@facebook.com",
        "first_name": "John",
        "last_name": "Doe"
    }
}
```

---

## User Profile Management

### Get/Update Profile

**Endpoint:** `GET/PUT /profile/`

**Description:** Retrieve or update user profile information.

**Authentication:** Required

**GET Response (200 OK):**
```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user": {
        "id": 1,
        "username": "",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "date_joined": "2023-01-01T00:00:00Z"
    },
    "marketing_consent": true,
    "marketing_consent_updated_at": "2023-01-01T00:00:00Z",
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
}
```

**PUT Request Body:**
```json
{
    "marketing_consent": false
}
```

**PUT Response (200 OK):**
```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user": {
        "id": 1,
        "username": "",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "date_joined": "2023-01-01T00:00:00Z"
    },
    "marketing_consent": false,
    "marketing_consent_updated_at": "2023-01-01T12:00:00Z",
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T12:00:00Z"
}
```

---

## GDPR Data Management

### Data Requests

**Endpoint:** `GET/POST /data-requests/`

**Description:** Manage GDPR data export and deletion requests.

**Authentication:** Required

**GET Response (200 OK):**
```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "request_type": "EXPORT",
            "status": "COMPLETED",
            "notes": "Data export completed successfully",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T01:00:00Z"
        },
        {
            "id": "550e8400-e29b-41d4-a716-446655440002",
            "request_type": "DELETE",
            "status": "PENDING",
            "notes": "",
            "created_at": "2023-01-02T00:00:00Z",
            "updated_at": "2023-01-02T00:00:00Z"
        }
    ]
}
```

**POST Request Body:**
```json
{
    "request_type": "EXPORT"
}
```

**POST Response (201 Created):**
```json
{
    "id": "550e8400-e29b-41d4-a716-446655440003",
    "request_type": "EXPORT",
    "status": "PENDING",
    "notes": "",
    "created_at": "2023-01-03T00:00:00Z",
    "updated_at": "2023-01-03T00:00:00Z"
}
```

**Request Types:**
- `EXPORT`: Request data export
- `DELETE`: Request account deletion

**Status Values:**
- `PENDING`: Request submitted and queued
- `COMPLETED`: Request processed successfully
- `FAILED`: Request processing failed

---

## Session Management

### List User Sessions

**Endpoint:** `GET /sessions/`

**Description:** List all active sessions for the authenticated user.

**Authentication:** Required

**Response (200 OK):**
```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "550e8400-e29b-41d4-a716-446655440004",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "last_activity": "2023-01-01T12:00:00Z",
            "created_at": "2023-01-01T00:00:00Z"
        },
        {
            "id": "550e8400-e29b-41d4-a716-446655440005",
            "ip_address": "192.168.1.101",
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X)",
            "last_activity": "2023-01-01T11:30:00Z",
            "created_at": "2023-01-01T10:00:00Z"
        }
    ]
}
```

---

### Revoke Session

**Endpoint:** `DELETE /sessions/{session_id}/`

**Description:** Revoke a specific user session.

**Authentication:** Required

**Response (204 No Content):**
No response body.

**Error Responses:**
- `404 Not Found`: Session not found or doesn't belong to user

---

## Social Account Management

### List Social Accounts

**Endpoint:** `GET /social/accounts/`

**Description:** List connected social accounts for the authenticated user.

**Authentication:** Required

**Response (200 OK):**
```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "provider": "google",
            "uid": "123456789",
            "last_login": "2023-01-01T12:00:00Z",
            "date_joined": "2023-01-01T00:00:00Z",
            "extra_data": {
                "name": "John Doe",
                "picture": "https://lh3.googleusercontent.com/..."
            }
        },
        {
            "id": 2,
            "provider": "github",
            "uid": "987654321",
            "last_login": "2023-01-01T11:00:00Z",
            "date_joined": "2023-01-01T10:00:00Z",
            "extra_data": {
                "login": "johndoe",
                "avatar_url": "https://avatars.githubusercontent.com/..."
            }
        }
    ]
}
```

---

### Social Account Connection Status

**Endpoint:** `GET /social/accounts/status/`

**Description:** Check which social providers are connected.

**Authentication:** Required

**Response (200 OK):**
```json
{
    "google": {
        "connected": true,
        "uid": "123456789"
    },
    "github": {
        "connected": true,
        "uid": "987654321"
    },
    "facebook": {
        "connected": false,
        "uid": null
    }
}
```

---

### Disconnect Social Account

**Endpoint:** `POST /social/accounts/{provider}/disconnect/`

**Description:** Disconnect a social account.

**Authentication:** Required

**Path Parameters:**
- `provider`: Social provider name (`google`, `github`, `facebook`)

**Response (200 OK):**
```json
{
    "message": "Google account disconnected successfully."
}
```

**Error Responses:**
- `400 Bad Request`: Cannot disconnect (e.g., last authentication method)
- `404 Not Found`: Social account not found

---

## Rate Limiting

The following endpoints have built-in rate limiting:

| Endpoint | Rate Limit | Scope |
|----------|------------|-------|
| `POST /token/` | 10/min | Per IP |
| `POST /social/*/` | 5/min | Per IP |
| `POST /data-requests/` | 2/day | Per User |

When rate limited, the API returns:

**Response (429 Too Many Requests):**
```json
{
    "detail": "Request was throttled. Expected available in 60 seconds."
}
```

---

## Error Responses

### Standard Error Format

All API errors follow this format:

```json
{
    "detail": "Error message",
    "code": "error_code"
}
```

### Validation Errors

For form validation errors:

```json
{
    "field_name": [
        "This field is required."
    ],
    "another_field": [
        "Invalid value."
    ]
}
```

### Common HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `204 No Content`: Request successful, no response body
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required or failed
- `403 Forbidden`: Permission denied
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

---

## Pagination

List endpoints support pagination with the following parameters:

**Query Parameters:**
- `page`: Page number (default: 1)
- `page_size`: Items per page (default: 20, max: 100)

**Response Format:**
```json
{
    "count": 100,
    "next": "http://example.com/api/endpoint/?page=3",
    "previous": "http://example.com/api/endpoint/?page=1",
    "results": [...]
}
```

---

## Webhooks

Currently, webhooks are not implemented but may be added in future versions for:
- User registration events
- Data request completions
- Security events

---

## SDK Examples

### JavaScript/TypeScript

```javascript
// Login
const response = await fetch('/api/auth/token/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'password'
    })
});

const tokens = await response.json();

// Use access token for authenticated requests
const profileResponse = await fetch('/api/auth/profile/', {
    headers: {
        'Authorization': `Bearer ${tokens.access}`
    }
});
```

### Python

```python
import requests

# Login
response = requests.post('/api/auth/token/', json={
    'email': 'user@example.com',
    'password': 'password'
})

tokens = response.json()

# Use access token for authenticated requests
headers = {'Authorization': f'Bearer {tokens["access"]}'}
profile_response = requests.get('/api/auth/profile/', headers=headers)
```

---

## Testing the API

You can test the API using tools like:

- **curl**
- **Postman**
- **HTTPie**
- **Django REST framework browsable API** (in development)

### Example with HTTPie

```bash
# Login
http POST localhost:8000/api/auth/token/ email=user@example.com password=password

# Get profile
http GET localhost:8000/api/auth/profile/ Authorization:"Bearer <access_token>"
```
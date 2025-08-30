# Gemini Project: django-myuser

This project aims to create a reusable Django package for managing users and authentication. The goal is to provide a comprehensive and configurable solution that can be easily integrated into other Django applications.

## Core Features

*   **User Management:** Build upon Django's built-in `User` model.
*   **Authentication:**
    *   JWT-based authentication using `django-rest-framework-simplejwt`.
    *   Configurable token expiry, revocation, and refresh mechanisms.
    *   Support for traditional Django sessions.
*   **Social Login:** Integration with popular social identity providers like Google, GitHub, and Facebook using the `django-allauth` library.
*   **User Data Management:**
    *   Functionality for users to request data exports.
    *   Functionality for users to request account deletion.
*   **Consents:** Management of user consents, such as for marketing communications.
*   **API Views:** Provide DRF-based views for all user-facing authentication features (login, logout, registration, token refresh, etc.).
*   **Extensibility:** The package will be designed to be highly configurable and extensible, allowing consuming applications to customize its behavior through Django settings.
*   **Separation of Concerns:** Core business logic will be separated from the views to allow for reuse in both DRF and traditional Django view contexts.

## Technical Stack

*   **Python:** 3.11
*   **Django:** 5.x (Latest LTS)
*   **Dependency Management:** Poetry
*   **Key Libraries:**
    *   `djangorestframework`
    *   `djangorestframework-simplejwt`
    *   `django-allauth`
*   **Testing:** A comprehensive test suite will be developed using `pytest-django` to ensure reliability and security. Tests will cover real-world scenarios and edge cases.

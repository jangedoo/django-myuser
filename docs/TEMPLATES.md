# Email Templates Reference

This document provides comprehensive information about all email templates included in the django-myuser package, their context variables, and how to customize them.

## Overview

The django-myuser package includes 18 professional email templates for various user authentication and data management scenarios. All templates are available in both HTML and plain text formats for maximum compatibility.

## Template Structure

```
django_myuser/templates/
├── account/
│   └── email/
│       ├── email_confirmation_message.html/txt
│       ├── email_confirmation_subject.txt
│       ├── email_confirmed.html/txt
│       ├── password_reset_key_message.html/txt
│       ├── password_reset_key_subject.txt
│       ├── password_change_alert.html/txt
│       ├── password_change_alert_subject.txt
│       ├── welcome_message.html/txt
│       ├── data_export.html/txt
│       └── account_deletion.html/txt
└── socialaccount/
    └── email/
        └── (social account templates)
```

---

## Email Confirmation Templates

### email_confirmation_message.html/txt

**Purpose:** Sent to users to verify their email address during registration.

**Context Variables:**
- `user` - User object with fields like `username`, `email`, `get_full_name()`
- `activate_url` - URL to verify the email address
- `expiration_days` - Number of days until the link expires
- `site` - Site object with domain information

**HTML Template Features:**
- Professional blue color scheme
- Responsive design
- Clear call-to-action button
- Fallback plain URL
- Security notice for unintended signups

**Plain Text Version:** Available as `email_confirmation_message.txt`

### email_confirmation_subject.txt

**Purpose:** Subject line for email confirmation emails.

**Content:** `Please confirm your email address`

**Context Variables:** None (static subject)

---

## Email Confirmed Templates

### email_confirmed.html/txt

**Purpose:** Sent after successful email verification.

**Context Variables:**
- `user` - User object
- `site` - Site object with domain information

**Features:**
- Congratulatory message
- Next steps guidance
- Green success color scheme

---

## Password Reset Templates

### password_reset_key_message.html/txt

**Purpose:** Sent when users request password reset.

**Context Variables:**
- `user` - User object
- `password_reset_url` - URL to reset password
- `site` - Site object
- `uid` - User ID token
- `token` - Password reset token

**HTML Template Features:**
- Red color scheme for security alerts
- Warning boxes for security notices
- 24-hour expiration notice
- Security guidance for unintended requests

### password_reset_key_subject.txt

**Purpose:** Subject line for password reset emails.

**Content:** `Password Reset Request`

---

## Password Change Alert Templates

### password_change_alert.html/txt

**Purpose:** Sent when user's password is successfully changed.

**Context Variables:**
- `user` - User object
- `timestamp` - When the password was changed
- `ip_address` - IP address from where change was made
- `user_agent` - Browser/device information
- `site` - Site object

**Features:**
- Security notification
- Account compromise guidance
- Contact information for suspicious activity
- Orange warning color scheme

### password_change_alert_subject.txt

**Purpose:** Subject line for password change alerts.

**Content:** `Your password has been changed`

---

## Welcome Message Templates

### welcome_message.html/txt

**Purpose:** Sent after successful account creation and email verification.

**Context Variables:**
- `user` - User object
- `site` - Site object

**Features:**
- Green celebratory color scheme
- Getting started checklist
- Support contact information
- Emoji for friendly tone

---

## GDPR Data Management Templates

### data_export.html/txt

**Purpose:** Sent when user's data export request is completed.

**Context Variables:**
- `user` - User object
- `export_url` - URL to download exported data (if applicable)
- `expiry_date` - When the download link expires
- `request_date` - When the export was requested
- `file_size` - Size of the exported data
- `site` - Site object

**Features:**
- Data privacy information
- Download instructions
- Link expiration notice
- Data security guidance

### account_deletion.html/txt

**Purpose:** Sent when user's account deletion request is completed.

**Context Variables:**
- `user` - User object (limited fields as account is being deleted)
- `deletion_date` - When the account was deleted
- `recovery_period` - Grace period for account recovery (if applicable)
- `site` - Site object

**Features:**
- Confirmation of deletion
- Data retention policy information
- Recovery instructions (if applicable)
- Final goodbye message

---

## Customizing Templates

### Method 1: Template Override

Create templates in your project with the same path structure:

```
your_project/
└── templates/
    └── account/
        └── email/
            └── email_confirmation_message.html
```

### Method 2: Custom Template Directory

Configure a custom template directory in settings:

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',
            BASE_DIR / 'custom_email_templates',  # Your custom directory
        ],
        # ... rest of configuration
    },
]
```

### Method 3: Extending Base Templates

Create a base email template and extend it:

```html
<!-- templates/email_base.html -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{% block title %}{% endblock %}</title>
    {% block styles %}
    <style>
        /* Your custom styles */
    </style>
    {% endblock %}
</head>
<body>
    <div class="container">
        {% block header %}{% endblock %}
        {% block content %}{% endblock %}
        {% block footer %}{% endblock %}
    </div>
</body>
</html>
```

```html
<!-- templates/account/email/email_confirmation_message.html -->
{% extends "email_base.html" %}

{% block title %}Confirm Your Email{% endblock %}

{% block content %}
<h2>Hello {{ user.get_full_name|default:user.username }},</h2>
<p>Please confirm your email address...</p>
{% endblock %}
```

---

## Template Context Variables Reference

### User Object Fields
- `user.username` - Username
- `user.email` - Email address
- `user.first_name` - First name
- `user.last_name` - Last name
- `user.get_full_name` - Full name (first + last)
- `user.date_joined` - Account creation date

### Site Object Fields
- `site.name` - Site name
- `site.domain` - Site domain

### Common URL Variables
- `activate_url` - Email confirmation URL
- `password_reset_url` - Password reset URL
- `login_url` - Login page URL

### Time/Date Variables
- `expiration_days` - Days until link expires
- `timestamp` - Current timestamp
- `request_date` - When request was made

---

## Email Styling Guidelines

### Default Color Scheme
- **Primary Blue:** `#007bff` (confirmations, general actions)
- **Success Green:** `#28a745` (welcome, completed actions)
- **Warning Orange:** `#ffc107` (alerts, important notices)
- **Danger Red:** `#dc3545` (password resets, security alerts)

### Typography
- **Font Family:** Arial, sans-serif
- **Line Height:** 1.6
- **Text Color:** #333
- **Background:** #f8f9fa (content areas)

### Responsive Design
All HTML templates are designed to work well on:
- Desktop email clients
- Mobile devices
- Web-based email clients
- Dark mode email clients

---

## Testing Email Templates

### Development Testing

Use Django's console email backend during development:

```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

### Template Testing

Create a management command to test templates:

```python
# management/commands/test_email_templates.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django_myuser.tasks import send_welcome_email

class Command(BaseCommand):
    def handle(self, *args, **options):
        User = get_user_model()
        user = User.objects.first()
        send_welcome_email.delay(user.id)
```

### Preview Templates

Create views to preview templates in browser:

```python
# views.py (development only)
from django.shortcuts import render
from django.contrib.auth.decorators import user_passes_test

@user_passes_test(lambda u: u.is_superuser)
def preview_email_template(request, template_name):
    context = {
        'user': request.user,
        'activate_url': 'http://example.com/activate/abc123/',
        'site': {'name': 'Your Site', 'domain': 'example.com'},
    }
    return render(request, f'account/email/{template_name}.html', context)
```

---

## Internationalization

### Multi-language Support

Templates support Django's i18n framework:

```html
{% load i18n %}
<h2>{% trans "Hello" %} {{ user.get_full_name|default:user.username }},</h2>
<p>{% trans "Thank you for signing up with our platform!" %}</p>
```

### Creating Translations

1. Mark strings for translation in templates
2. Generate message files: `django-admin makemessages -l es`
3. Translate strings in `.po` files
4. Compile translations: `django-admin compilemessages`

---

## Best Practices

### Security
- Never include sensitive data in email templates
- Use secure URLs (HTTPS) for all links
- Include security notices for password-related emails
- Implement proper token expiration

### Accessibility
- Use proper HTML structure with headers
- Include alt text for images
- Ensure good color contrast
- Provide plain text alternatives

### Deliverability
- Keep templates under 100KB
- Use web-safe fonts
- Avoid spam trigger words
- Include plain text versions
- Test across multiple email clients

### User Experience
- Clear, actionable subject lines
- Prominent call-to-action buttons
- Mobile-responsive design
- Clear expiration information
- Helpful support contact information

---

## Troubleshooting

### Template Not Loading
1. Check template path matches exactly
2. Verify `TEMPLATES` configuration
3. Ensure template directory is in Django's template search path

### Context Variables Missing
1. Verify variable names match documentation
2. Check if custom adapters modify context
3. Ensure proper template inheritance

### Styling Issues
1. Test in multiple email clients
2. Use inline CSS for better compatibility
3. Provide fallback styles for older clients

### Email Not Sending
1. Check Celery worker is running
2. Verify email backend configuration
3. Check SMTP credentials and settings
4. Review email logs for errors

---

## Advanced Customization

### Custom Context Processors

Add custom context to all email templates:

```python
# context_processors.py
def email_context(request):
    return {
        'company_name': 'Your Company',
        'support_email': 'support@yourcompany.com',
        'social_links': {
            'twitter': 'https://twitter.com/yourcompany',
            'facebook': 'https://facebook.com/yourcompany',
        }
    }
```

### Dynamic Template Selection

Choose templates based on user preferences:

```python
# adapters.py
from allauth.account.adapter import DefaultAccountAdapter

class CustomAccountAdapter(DefaultAccountAdapter):
    def render_mail(self, template_prefix, email, context):
        if context['user'].profile.email_format == 'minimal':
            template_prefix = f"{template_prefix}_minimal"
        return super().render_mail(template_prefix, email, context)
```

### Email Analytics

Track email opens and clicks:

```html
<!-- Add tracking pixel -->
<img src="https://analytics.yoursite.com/track/{{ tracking_id }}.gif" 
     width="1" height="1" alt="">

<!-- Track link clicks -->
<a href="https://analytics.yoursite.com/click/{{ link_id }}/?redirect={{ activate_url|urlencode }}">
    Verify Email
</a>
```
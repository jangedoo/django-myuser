from django.apps import AppConfig


class DjangoMyuserConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_myuser"

    def ready(self):
        import django_myuser.signals
        import django_myuser.audit_signals

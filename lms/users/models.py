# users/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLES = (
        ('admin', 'Admin'),
        ('teacher', 'Teacher'),
        ('student', 'Student'),
    )
    full_name = models.CharField(max_length=255)
    email_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLES)
    
    # Adding related_name to avoid clashes
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',  # This changes the reverse relationship name
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions_set',  # This changes the reverse relationship name
        blank=True,
    )

    def __str__(self):
        return self.username

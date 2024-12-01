from django.db import models
from django.contrib.auth.models import User  # Import the User model

class Task(models.Model):
    title = models.CharField(max_length=255)
    completed = models.BooleanField(default=False)
    user = models.ForeignKey(User, related_name='tasks', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.title

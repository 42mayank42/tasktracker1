from django.db import models
from django.conf import settings

class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='user_tasks')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    hours_spent = models.DecimalField(max_digits=4, decimal_places=2)
    tags = models.CharField(max_length=255, blank=True)
    task_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    manager_comment = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

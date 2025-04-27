from django import forms
from .models import Task

class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['user', 'title', 'description', 'hours_spent', 'tags', 'task_date', 'status', 'manager_comment']
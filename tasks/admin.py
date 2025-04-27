from django.contrib import admin
from .models import Task

class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'task_date', 'status', 'hours_spent', 'created_at', 'updated_at')
    list_filter = ('status', 'task_date', 'user')
    search_fields = ('title', 'description', 'tags')
    ordering = ('-id',)

admin.site.register(Task, TaskAdmin)
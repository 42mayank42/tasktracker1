from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'email', 'role', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff')
    search_fields = ('username', 'email')
    ordering = ('-username',)

    fieldsets = BaseUserAdmin.fieldsets + (
        (None, {'fields': ('role',)}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        (None, {'fields': ('role',)}),
    )
admin.site.register(User, UserAdmin)
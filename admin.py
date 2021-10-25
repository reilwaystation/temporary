
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin
from .forms import UserAdminCreationForm, UserAdminChangeForm
from .models import User


class BaseUserAdmin(UserAdmin):

    form = UserAdminChangeForm
    add_form = UserAdminCreationForm

    list_display = ('email', 'username', 'first_name',
                    'last_name', 'is_superuser', 'is_staff', 'is_active')
    list_filter = ('is_superuser',)
    fieldsets = ((None,
                  {'fields': [
                      'email',
                      'username',
                      'first_name',
                      'last_name',
                      'password',
                      'is_superuser',
                      'is_staff',
                      'is_active'
                  ]}),
                 )
    add_fieldsets = ((None,
                      {'fields': [
                          'email',
                          'username',
                          'first_name',
                          'last_name',
                          'password1',
                          'password2',
                          'is_superuser',
                          'is_staff',
                          'is_active'
                      ]}),
                     )
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)
    filter_horizontal = ()


admin.site.register(User, BaseUserAdmin)
admin.site.unregister(Group)

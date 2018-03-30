from django.contrib import admin

from .models import UserProfile, PhoneNumberVerification

admin.site.register(UserProfile)
admin.site.register(PhoneNumberVerification)
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import AllowAllUsersModelBackend


# Custom auth backend to allow login by email
# It extends AllowAllUsersModelBackend to allow non-active users to login
class EmailBackend(AllowAllUsersModelBackend):
    def authenticate(self, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            return None
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
        return None

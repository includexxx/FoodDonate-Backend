from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, email, full_name, phone, password=None):
        """
        Creates and saves a User with the given email and password.
        """
        # import pdb
        # pdb.set_trace()
        if not email:
            raise ValueError('Users must have an email address')
        if not full_name:
            raise ValueError('Users must have full name')
        if not phone:
            raise ValueError('Users must have phone number')

        user = self.model(
            email=self.normalize_email(email),
            full_name=full_name,
            phone=phone
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, full_name, phone, password):
        """
        Creates and saves a staff user with the given email and password.
        """
        user = self.create_user(
            email,
            full_name,
            phone,
            password=password,
        )
        user.staff = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, phone, password):
        """
        Creates and saves a superuser with the given email and password.
        """
        #pdb.set_trace()
        user = self.create_user(
            email,
            full_name,
            phone,
            password=password,
        )
        user.staff = True
        user.admin = True
        user.save(using=self._db)
        return user

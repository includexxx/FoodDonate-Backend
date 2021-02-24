from django.contrib.auth import password_validation
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_jwt.settings import api_settings


from accounts.models import User
from rest_framework import serializers


class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'phone', 'full_name', 'password', 'password2']
        # read_only_fields = ['id', 'admin', 'staff', 'active']
        write_only_fields = ['password', 'password2']

    def validate_email(self, value):
        norm_email = value.lower()
        if User.objects.filter(email=norm_email).exists():
            raise serializers.ValidationError("Not unique email")
        return norm_email

    def validate(self, data):
        if data.get('password') != data.get('password2'):
            raise serializers.ValidationError("Password do not match.")
        if data.get('full_name') == '':
            raise serializers.ValidationError("Full name is empty.")
        if data.get('phone') == '':
            raise serializers.ValidationError("Phone no is empty.")
        return data


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        fields = ['token']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password1 = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password2 = serializers.CharField(max_length=128, write_only=True, required=True)

    def validate_old_password(self, value):
        print("value", self.context)
        user = self.context['request'].user
        import pdb
        # pdb.set_trace()
        if not user.check_password(value):
            raise serializers.ValidationError('Your old password was entered incorrectly. Please enter it again.')
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError("The two password fields didn't match.")
        password_validation.validate_password(data['new_password1'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password1']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=155)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['password', 'token']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            payload = api_settings.jwt_decode_handler(token)
            if User.objects.filter(id=payload['user_id']).exists():
                user = User.objects.get(id=payload['user_id'])
                user.set_password(password)
                user.save()
                return user
            else:
                raise AuthenticationFailed('The reset link is invalid', 401)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)
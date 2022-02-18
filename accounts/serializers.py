from base64 import urlsafe_b64decode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import force_str,force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id','email','first_name','last_name','is_active']


class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model =get_user_model()
        fields = [
            'first_name',
            'last_name',
            'email',
            'password',
            'confirm_password'
            ]
        extra_kwargs = {
            "email": {"required": True},
            'first_name': {'required': True},
            'last_name':  {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields did not match."})
        return attrs
    
    def create(self):
        user = get_user_model().objects.create_user(
            email=self.validated_data['email'],
            password = self.validated_data['password'],
            first_name=self.validated_data['first_name'],
            last_name=self.validated_data['last_name'],   
        )
        user.save()
        user.refresh_from_db()
        return user


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class SetNewPasswordSerializer(serializers.ModelSerializer):
    # Passwords must be at least 8 characters, but no more than 128
    # characters. These values are the default provided by Django. We could
    # change them, but that would create extra work while introducing no real
    # benefit, so let's just stick with the defaults.
    password = serializers.RegexField(
        regex="^(?=.*\d).{8,20}$",
        max_length=128,
        min_length=8,
        write_only=True,
        required=False,
        error_messages={
            'invalid': 'Sorry, passwords must contain a letter and a number.',
            'min_length': 'Sorry, passwords must contain at least 8 characters.',
            'max_length': 'Sorry, passwords cannot contain more than 128 characters.'
        }
    )
    confirm_password = serializers.RegexField(
        regex="^(?=.*\d).{8,20}$",
        max_length=128,
        min_length=8,
        write_only=True,
        required=False,
        error_messages={
            'invalid': 'Sorry, passwords must contain a letter and a number.',
            'min_length': 'Sorry, passwords must contain at least 8 characters.',
            'max_length': 'Sorry, passwords cannot contain more than 128 characters.'
        }
    )
    token = serializers.CharField(
        min_length=1, write_only=True
    )
    uidb64 = serializers.CharField(
        min_length=1, write_only=True
    )

    class Meta:
        model = get_user_model()
        fields=['password', 'confirm_password', 'token', 'uidb64']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields did not match."})
        try:
            password=attrs.get('password')
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')

            id=force_str(urlsafe_b64decode(uidb64))
            user= get_user_model().objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The rest link is invalid', 401)

            user.reset_password(password)
            user.save()

        except Exception as e:
            print(e)
            raise AuthenticationFailed('The reset link is invalid', 401)

        return super().validate(attrs)
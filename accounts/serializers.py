# from django.contrib.auth.models import User
from accounts.models import CustomUser
from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials.')
        else:
            raise serializers.ValidationError('Must include "email" and "password".')
        data['user'] = user
        return data
    
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model

User = get_user_model()

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    email = serializers.EmailField()

    def validate(self, attrs):
        refresh_token = attrs['refresh']
        email = attrs['email']

        try:
            # Decode and validate the refresh token
            token = RefreshToken(refresh_token)
            user_id = token.payload.get('user_id')
            if user_id is None:
                raise serializers.ValidationError({'refresh': 'Invalid token: missing user_id.'})

            # Fetch the user
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise serializers.ValidationError({'refresh': 'User associated with this token no longer exists.'})

            # Verify email matches
            if user.email != email:
                raise serializers.ValidationError({'email': 'Email does not match the token owner.'})

            # Store token in the serializer instance for later use in save()
            self.token = token

        except TokenError as e:
            raise serializers.ValidationError({'refresh': f'Invalid or expired token: {str(e)}'})

        return attrs

    def save(self, **kwargs):
        try:
            self.token.blacklist()
        except TokenError as e:
            raise serializers.ValidationError({'refresh': f'Failed to blacklist token: {str(e)}'})
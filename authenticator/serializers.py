from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = User
        exclude = ['user_permissions', 'groups', 'date_joined']

    def create(self, validated_data):
        groups = validated_data.pop('groups', [])

        if 'username' not in validated_data or not validated_data["username"]:
            validated_data['username'] = validated_data.get('email', None) or validated_data.get('mobile_number', None)

        # Set a default password if none is provided
        if 'password' not in validated_data or not validated_data['password']:
            validated_data['password'] = User.objects.make_random_password()
        try:

            user = User.objects.create_user(**validated_data)
        except Exception as e:
            return "User Already Exists"

        if groups:
            user.groups.set(groups)

        return user

    def update(self, instance, validated_data):
        groups = validated_data.pop('groups', None)

        instance = super(UserCreateSerializer, self).update(instance, validated_data)

        if groups is not None:
            instance.groups.set(groups)

        return instance

    def validate_mobile_number(self, value):
        if value:
            check_qs = User.objects.filter(mobile_number=value)
            if self.instance:
                check_qs = check_qs.exclude(id=self.instance.id).exists()
            else:
                check_qs = check_qs.exists()
            if check_qs:
                raise serializers.ValidationError('This mobile number is already in use.')
            return value
        else:
            return None


class LoginOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, required=False)
    request_id = serializers.CharField(required=False)


class CustomTokenSerializer(TokenObtainPairSerializer):
    def update(self, instance, validated_data):
        return super(CustomTokenSerializer, self).update(instance, validated_data)

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['name'] = user.get_full_name()
        return token

    def validate(self, attrs):
        # data.update(custom_data)

        # attrs.update(custom_data)
        data = super(CustomTokenSerializer, self).validate(attrs)

        # and everything else you want to send in the response
        return data

    def create(self, validated_data):
        return super(CustomTokenSerializer, self).create(validated_data)

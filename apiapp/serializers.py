from rest_framework import serializers
from .models import User, Docs

# 회원가입 시리얼라이저
class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'userid', 'password', 'name', 'phone_number']    
        extra_kwargs = {'password': {'write_only': True}}

# 로그인 시리얼라이저
class UserLoginSerializer(serializers.Serializer):
    userid = serializers.CharField()
    password = serializers.CharField(write_only=True)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def create(self, validated_data):
        user = User.objects.create_user(
            email = validated_data['email'],
            password = validated_data['password'],
            name = validated_data['name'],
            phone_number = validated_data['phone_number']
        )
        return user
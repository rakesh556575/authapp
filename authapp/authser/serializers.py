from rest_framework import serializers
from .models import User


class UserSerializers(serializers.ModelSerializer):
    #name = serializers.SlugRelatedField(
    #    queryset=User.objects.all(), slug_field='name'
    #)
    class Meta:
        model=User
        fields=('id',"name","email","password")



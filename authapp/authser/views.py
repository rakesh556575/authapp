from django.shortcuts import render

# Create your views here.


from django.shortcuts import render
from rest_framework import viewsets
from .models import User
from .serializers import UserSerializers
# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.http import HttpResponse
import jwt
import datetime
import json
SECRET="rakesh"

from .logger import get_logger
logger=get_logger(__name__)

def verify(f):
    def wrapper(*args, **kw):

       # auth_token=(args[1].COOKIES.get("token")[2:-1])
       # print((auth_token))
       # if not auth_token:
        auth_token=""
        auth_header = args[1].headers.get('Authorization')
        if auth_header:
           auth_token = auth_header.split(" ")[1]
           if not auth_token:
              logger.error("No Authorization")
              return Response("No Authorization ")
        else:
            logger.error("No Authorization")
            return Response("No Authorization ")
        if auth_token:
            resp = decode_auth_token(auth_token)
            try:
                if User.objects.get(name=resp):
                   return f(*args, **kw)
                else:
                   logger.error("Not a valid user")
                   return Response("Not valid user")
            except Exception as e:
                logger.error("Not a valid user")
                return Response("Not valid user")

    return wrapper



class userview(APIView):
    @verify
    def get(self,request):
        name=request.data.get("name")
        try:
            name = User.objects.get(name=name)

            serializer = UserSerializers(name)
            return Response(serializer.data)
        except Exception as e:
            logger.error("Error {}".format(e))
            return Response("Error {}".format(e))

    #

    def delete(self,request):
        name=request.data.get("name")
        try:
            User.objects.get(name=name).delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error("Error {}".format(e))
            return Response("Error {}".format(e))

    def put(self,request):

        name=request.data.get("name")
        name_obj=User.objects.get(name=name)
        serializer = UserSerializers(name_obj,data=request.data,partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info("{} user data is scussfully modified".format(name))
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    #print(dir(jwt))
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=3000),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            SECRET

        )
    except Exception as e:
        logger.error("Error encoding auth token {}".format(e))
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET)
        return payload['sub']
    except jwt.ExpiredSignatureError:
        logger.error("Signature expired. Please log in again")
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        logger.error("Invalid token. Please log in again")
        return 'Invalid token. Please log in again.'

class Login(APIView):

      def get(self,request):

          data = {'name': request.data.get('name'), 'email': request.data.get('email'),"password":request.data.get('password')}

          try:
              if User.objects.get(name=request.data.get("name")):
                  auth_token = encode_auth_token(request.data.get("name"))
                  if auth_token:
                     responseObject = {
                             'status': 'success',
                             'message': 'Successfully logged in.',
                              'auth_token': auth_token}
                     #response=HttpResponse("sucess")
                     #response.set_cookie("token",auth_token)
                     logger.info("{} user logged in sucessfully".format(request.data.get("name")))
                     return Response(responseObject)
          except Exception as e:
              logger.error("{} user failed to login".format(request.data.get("name")))
              return Response("Error {}".format(e))

          return Response("Failure")

class Register(APIView):
     def post(self,request):

         data = {'name': request.data.get('name'), 'email': request.data.get('email'),"password":request.data.get('password')}
         try:

              if User.objects.get(name=request.data.get('name')):
                 return Response("user already exists")
         except Exception as e:
              pass


         serializer = UserSerializers(data=data)
         if serializer.is_valid():
             serializer.save()
             logger.info("{} user registered sucessfully".format(request.data.get('name')))
             return Response(serializer.data, status=status.HTTP_201_CREATED)
         logger.error("{} user failed to register".format(request.data.get('name')))
         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Modify(APIView):
    def put(self,request):

        name=request.data.get("name")
        name_obj=User.objects.get(name=name)
        serializer = UserSerializers(name_obj,data=request.data,partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info("{} user data is sucessfully modified")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        logger.error("{} user data failed to modifiy")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)









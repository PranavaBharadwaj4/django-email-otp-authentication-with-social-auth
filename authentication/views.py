from http.client import HTTPResponse
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate
from .serializers import SignUpSerializer,ChangePasswordSerializer,UserNameSerializer, ProfileSerializer
from rest_framework.decorators import api_view, permission_classes,\
    throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated,\
    IsAuthenticatedOrReadOnly
from rest_framework.views import APIView
from rest_framework.generics import UpdateAPIView, ListCreateAPIView, RetrieveUpdateDestroyAPIView
from django.utils import timezone
from .email import send_email
from .utility import generateKey,verify_otp,set_token_cookie
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from rest_framework_simplejwt.views import TokenViewBase
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from .utility import set_browser_cookie
from .models import Profile
from rest_framework import viewsets, permissions
from .authenticate import CustomAuthentication
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
import requests
import json
from django.conf import settings
from django.http import JsonResponse
import secrets

def make_token():
    """
    Creates a cryptographically-secure, URL-safe string
    """
    return secrets.token_urlsafe(32)



User = get_user_model()

@permission_classes([AllowAny,])
class ProfileViewSet(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

class UserViewSet(viewsets.ModelViewSet):
    http_method_names = ['get']
    print("hiiiiiii")
    serializer_class = SignUpSerializer
    basename = 'users'
    permission_classes = [permissions.AllowAny]
    def get_queryset(self):
        print(self.request)
        # serializer = SignUpSerializer(data=self.request.data)
        username=  self.request.query_params.get('username', None)
        if username is not None:
            print(username)
            user = User.objects.get(username=username)
            print(user)
            return User.objects.filter(username = username)
        else:
            return User.objects



# @permission_classes([AllowAny,])
# class GoogleLogin(APIView):
#     def get(self, request):
#         # Get the value of the "param1" query parameter
#         state = request.query_params.get('state', None)

#         # Get the value of the "param2" query parameter
#         code = request.query_params.get('code', None)
#         print(code, " and ",state)


#         # Return a response with the query string parameters
#         response_data = {
#             'state': state,
#             'code': code
#         }
#         return Response(response_data)

@permission_classes([AllowAny,])
class GoogleAuthCallbackView(APIView):
    def get(self, request):
        # Get the value of the "state" query parameter
        state = request.query_params.get('state', None)
        
        # Get the value of the "code" query parameter
        code = request.query_params.get('code', None)
        session_id = request.session._session_key
        print("session id: ",session_id)


        # Exchange the authorization code for a token
        if state and code and not request.session.get('access'):
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                # 'Cookie': 'sessionid=757nx80aiqsei1w3azfjnbzu4hu20kwc',
                'Cookie': f'sessionid={session_id}',
            }

            details = {
                'state': state,
                'code': code
            }

            form_body = '&'.join([f'{k}={v}' for k, v in details.items()])
            print(form_body)
            url = f'http://localhost:8000/djoser/o/google-oauth2/?{form_body}'
            print(url)
            try:
                response = requests.post(url, headers=headers)
                data = json.loads(response.content)
                
                print("data: ", data)
                if data != None:
                    # request.session['access'] = data['access']
                    user = User.objects.get(username = data['user'],is_active = True)
                    response = Response()
                    user.total_login_devices += 1
                    user.otp = None
                    user.last_login = timezone.now()
                    if user.user_secret_key is None:
                        user.user_secret_key = generateKey()['totp']
                    user.save()
                    # access_token = data['access']
                    # refresh_token = data.get('refresh', None)
                   
                    set_token_cookie(request,response,user,user.user_secret_key)
                    # set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'],data["access"])
                    # set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],data["refresh"])
                    print(user)


                    return JsonResponse({
                        'success': True,
                        'message': 'Authentication successful',
                        'data': data
                    })

                else:
                    return JsonResponse({
                        'success': False,
                        'message': 'Authentication failed',
                        'data':data
                    })


            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error: {str(e)}'
                })

        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid parameters'
            })

@permission_classes([AllowAny,])
class FacebookAuthCallbackView(APIView):
    def get(self, request):
        # Get the value of the "state" query parameter
        state = request.query_params.get('state', None)
        
        # Get the value of the "code" query parameter
        code = request.query_params.get('code', None)
        session_id = request.session._session_key
        print("session id: ",session_id)


        # Exchange the authorization code for a token
        if state and code and not request.session.get('access'):
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                # 'Cookie': 'sessionid=757nx80aiqsei1w3azfjnbzu4hu20kwc',
                'Cookie': f'sessionid={session_id}',
            }

            details = {
                'state': state,
                'code': code
            }

            form_body = '&'.join([f'{k}={v}' for k, v in details.items()])
            print(form_body)
            url = f'http://localhost:8000/djoser/o/facebook/?{form_body}'
            print(url)
            try:
                response = requests.post(url, headers=headers)
                data = json.loads(response.content)
                
                print("data: ", data)
                # if data != None:
                if True:
                    # request.session['access'] = data['access']
                    # user = User.objects.get(username = data['user'],is_active = True)
                    # response = Response()
                    # user.total_login_devices += 1
                    # user.otp = None
                    # user.last_login = timezone.now()
                    # if user.user_secret_key is None:
                    #     user.user_secret_key = generateKey()['totp']
                    # user.save()
                    # access_token = data['access']
                    # refresh_token = data.get('refresh', None)
                   
                    # set_token_cookie(request,response,user,user.user_secret_key)
                    # set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'],data["access"])
                    # set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],data["refresh"])
                    # print(user)


                    return JsonResponse({
                        'success': True,
                        'message': 'Authentication successful',
                        'data': "data"
                    })

                else:
                    return JsonResponse({
                        'success': False,
                        'message': 'Authentication failed',
                        'data':data
                    })


            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error: {str(e)}'
                })

        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid parameters'
            })

class CustomTokenRefreshView(TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = TokenRefreshSerializer
    throttle_classes = []
    def post(self, request, *args, **kwargs):
        
        refresh_token = request.get_signed_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],salt = settings.SIMPLE_JWT['AUTH_COOKIE_SALT'],default = False) or None
        
        if refresh_token is None:
            return Response({"No token" : "No refresh token found"},status=status.HTTP_400_BAD_REQUEST)
        serializer = self.get_serializer(data={"refresh" : refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            return Response({"error" : str(e.args[0])},status.HTTP_400_BAD_REQUEST)
        
        
        access_token = serializer.validated_data['access']
        refresh_token = serializer.validated_data['refresh']
                
        response = Response()
        set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'],access_token)
        set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],refresh_token)
        
        return response



@api_view(['POST'])
@permission_classes([AllowAny,])
def signup(request):
    serializer = SignUpSerializer(data=request.data)
    if serializer.is_valid():
        key = generateKey()
        user = User(username = serializer.data['username'],email = serializer.data['email'],otp = key['OTP'],activation_key = key['totp'],)
        try:
            validate_password(serializer.data['password'],user)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.data['password'])
        user.is_active = False
        user.save(update_fields=['set_password','is_active'])
        send_email('signup_otp.html',"Otp Verification",serializer.data['email'],otp = key['OTP'],username = serializer.data['username'])
        return Response({"username" :  serializer.data['username'],"email" : serializer.data['email'],"Status" : "Otp has been send!!"}, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@permission_classes([AllowAny,])
def signupVerify(request):
    otp = request.data.get('otp')
    try:
        user = User.objects.get(otp = otp,is_active = False)
        verify = verify_otp(user.activation_key,otp)
        if verify:
            response = Response()
            user.is_active = True
            user.user_secret_key = generateKey()['totp']
            user.total_login_devices += 1
            user.last_login = timezone.now()
            user.otp = None
            user.save(update_fields=['is_active','user_secret_key','total_login_devices','last_login','otp'])
            set_token_cookie(request,response,user,user.user_secret_key)      
            send_email('signup_otp_success.html',"Account successfully activated",user.email,username = user.username)
            response.data = {"Varify success" : "Your account has been successfully activated!!"}
            return response
        else:
            return Response({"Time out" : "Given otp is expired!!"}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except:
        return Response({"No User" : "Invalid otp OR No any inactive user found for given otp"}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@permission_classes([AllowAny,])
def resendOtp(request):
    email = request.data["email"]
    try:
        user = User.objects.get(email = email,is_active = False)
        key = generateKey()
        user.otp = key['OTP']
        user.activation_key = key['totp']
        user.save(update_fields=['otp','activation_key'])        
        send_email('signup_otp.html','Otp Verification',email,otp = key['OTP'],username = user.username)
        return Response({"Send OTP" : "Otp successfully send!!"},status=status.HTTP_200_OK)
    except:
        return Response({"No User" : "No Inactive account found for this given email!!"}, status=status.HTTP_400_BAD_REQUEST)

@permission_classes([AllowAny,])
class LoginView(APIView):
    
    def post(self, request, format=None):
        data = request.data
        response = Response()       
        username = data.get('username', None)
        password = data.get('password', None)
        user = authenticate(username=username,password=password)
        if user is not None:
            if user.is_active:
                if user.two_step_verification:
                    key = generateKey()
                    user.otp = key['OTP']
                    user.activation_key = key['totp']
                    user.save(update_fields=['otp','activation_key'])                    
                    send_email('two_step_authentication.html','Two step verification',user.email,otp = key['OTP'],username = user.username)
                    return Response({"send":"Two step verification OTP successfully send!!!"},status = status.HTTP_200_OK) 
                else:          
                    user.total_login_devices += 1
                    user.last_login = timezone.now()
                    user.save(update_fields=['total_login_devices','last_login'])
                    if user.user_secret_key is None:
                        user.user_secret_key = generateKey()['totp']
                        user.save(update_fields=['user_secret_key'])
                    set_token_cookie(request,response,user,user.user_secret_key) 
                    # send_email('login_success.html',"Successfully Login",user.email,username = user.username,activation_key = user.activation_key,secret_key = user.user_secret_key)
                    response.data = {"Success" : "Login successfully","data":data['username']}
                    return response
            else:
                return Response({"No active" : "This account is not active!!"},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"Invalid" : "Invalid username or password!!"},status=status.HTTP_404_NOT_FOUND)
        
@api_view(['POST'])
@permission_classes([AllowAny,])
def two_step_otp_Verify(request):
    try:
        otp = request.data.get('otp', None)
        user = User.objects.get(otp = otp,is_active = True)
        verify = verify_otp(user.activation_key,otp)
        if verify:
            response = Response()
            user.total_login_devices += 1
            user.otp = None
            user.last_login = timezone.now()
            if user.user_secret_key is None:
                user.user_secret_key = generateKey()['totp']
            user.save()
            set_token_cookie(request,response,user,user.user_secret_key)            
            send_email('login_success.html',"Successfully Login",user.email,username = user.username,activation_key = user.activation_key,secret_key = user.user_secret_key)
            response.data = {"Success" : "Login successfully"}
            return response
        else:
            return Response({"Time out" : "Given otp is expired!!"}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except:
        return Response({"No User" : "Invalid otp OR No any active user found for given otp"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny,])
def reset_password_send(request):
    data = request.data.get("email")
    if data is None:
        return Response({"Field name Error" : "Only email field acceptable!!"})
    key = generateKey()
    if '@' in data or '.' in data:
        try:
            user = User.objects.get(email = data,is_active = True)
            user.otp = key['OTP']
            user.activation_key = key['totp']
            user.save(update_fields=['otp','activation_key'])            
            send_email('reset_password_send.html',"Reset Password",user.email,username = user.username,otp = key['OTP'])
            return Response({"send" : "Password reset OTP send successfully!!"},status=status.HTTP_200_OK)         
        except:
            return Response({"No user" : "No any active account found for given email add.!!!"},status=status.HTTP_400_BAD_REQUEST)
    else:
        try:
            user = User.objects.get(username = data,is_active = True)
            user.otp = key['OTP']
            user.activation_key = key['totp']
            user.save(update_fields=['otp','activation_key'])            
            send_email('reset_password_send.html',"Reset Password",user.email,username = user.username,otp = key['OTP'])
            return Response({"send" : "Password reset OTP send successfully!!"},status=status.HTTP_200_OK)         
        except:
            return Response({"No user" : "No any active account found for given username!!!"},status=status.HTTP_400_BAD_REQUEST) 
        
@api_view(['POST'])
@permission_classes([AllowAny,])
def reset_password_verify(request):
    otp = request.data.get("otp")
    if otp is None:
        return Response({"Field name error" : "Only otp name field acceptable!!"})
    try:
        user = User.objects.get(otp = otp,is_active = True)
        verify = verify_otp(user.activation_key,otp)
        if verify:
            return Response({"Verified" : "OTP is verified!!"},status=status.HTTP_200_OK)
        else:
            return Response({"Error" : "OTP Expired!!!"},status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"Error" : "Invalid OTP"},status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny,])
def reset_password(request):
    data = request.data
    try:
        if data['password1'] != data['password2']:
            return Response({"Error" : "Both password is not same!!"},status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(otp = data["otp"],is_active = True)
        
        try:
            validate_password(data['password2'],user)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(data['password2'])
        user.otp = None
        user.user_secret_key = None
        user.total_login_devices = 0
        user.save(update_fields=['set_password','otp','user_secret_key','total_login_devices'])        
        send_email('reset_password_success.html',"Password successfully updated",user.email,username = user.username)
        return Response({"Updated" : "Password updated successfully!!"},status=status.HTTP_200_OK)
    except:
        return Response({"Wrong" : "Something went wrong.Try again!!"},status=status.HTTP_400_BAD_REQUEST) 

class ChangePasswordView(UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated, )

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        send_email('change_password_success.html',"Password successfully changed",self.request.user.email,username = self.request.user.username)
        return Response({"Changed" : "Password successfully changed!!!"},status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny,])
def set_pass_email(request,key):
    try:
        user = User.objects.get(activation_key = key,is_active = True)
        data = request.data
        if data['password1'] != data['password2']:
            return Response({"Error" : "Both password is not same!!"},status=status.HTTP_400_BAD_REQUEST)        
        
        try:
            validate_password(data['password2'],user)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(data['password2'])
        user.user_secret_key = None
        user.activation_key = None
        user.total_login_devices = 0
        user.save(update_fields=['set_password','user_secret_key','activation_key','total_login_devices'])
        send_email('change_password_success.html',"Password successfully changed",user.email,username = user.username)
        return Response({"Changed" : "Password successfully changed!!!"},status=status.HTTP_200_OK)
    except:
        return Response({"Wrong" : "Something went wrong.This link either expired or invalid!!"},status=status.HTTP_400_BAD_REQUEST)

@throttle_classes([])
class UsernameView(APIView):
    
    permission_classes = [IsAuthenticatedOrReadOnly]
    
    def get_object(self, user_name):
        try:
            return User.objects.get(username=user_name)
        except User.DoesNotExist:
            return False
    
    def get(self, request, format=None):
        if self.get_object(request.data.get('username')):
            return Response({"Exist" : "Given username already exist!!"},status=status.HTTP_200_OK)
        else:
            return Response({"Not Exist" : "No any user found!!"},status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request, format=None):
        user = self.get_object(request.user.username)
        if not user:
            return Response({"No User" : "No user found!!"},status=status.HTTP_400_BAD_REQUEST)
        serializer = UserNameSerializer(user, data=request.data,partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"Change_success" : "Username successfully changed!!","data" : serializer.data},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def post(self,request,format = None):
        user = User.objects.get(username = request.user.username)
        if user.user_secret_key != request.get_signed_cookie(settings.SIMPLE_JWT['USER_SECRET_KEY'],salt = settings.SIMPLE_JWT['AUTH_COOKIE_SALT']):
            response = Response()
            response.delete_cookie(settings.SIMPLE_JWT['USER_SECRET_KEY'])
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'])
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            response.data = {"Logout" : "Login again!!"}
            return response
        else:
            data = {"username" : user.username,'id' : user.id,"isAuthenticated" : True}
            return Response(data,status=status.HTTP_200_OK)
                
    
@api_view(['POST'])
@permission_classes([IsAuthenticated,])
def change_email_send(request):
    email = request.data.get("email")
    if email is None:
        return Response({"Field error" : "Only email name field acceptable!!"})
    try:
        User.objects.get(email = email)
        return Response({"Exist" : "Given email already exist or same as your current email address!!"},status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:        
        try:
            validate_email( email )
            user = User.objects.get(username = request.user)
            key = generateKey()
            
            user.otp = key['OTP']
            user.activation_key = key['totp']
            user.change_email = email
            user.save(update_fields=['otp','activation_key','change_email'])
            send_email('email_change_send.html',"OTP verification",email,username = user.username,otp = key['OTP'])
            return Response({"Send otp" : "Email_change otp has been successfully send in your new email eaddress!!!"},status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated,])
def change_email_verify(request):
    otp = request.data.get("otp")
    if otp is None:
        return Response({"Field name error" : "Only otp name field acceptable!!"})
    try:
        user = User.objects.get(otp = otp,username = request.user.username)
        verify = verify_otp(user.activation_key,otp)
        if verify:
            user.email = user.change_email
            user.change_email = None
            user.otp = None
            user.save(update_fields=['email','otp','change_email'])
            send_email('email_change_success.html',"Email successfully updated",user.email,username = user.username)
            return Response({"Verified" : "Email change successfully!!"},status=status.HTTP_200_OK)
        else:
            return Response({"Error" : "OTP Expired!!!"},status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"Error" : "Invalid OTP"},status=status.HTTP_400_BAD_REQUEST)

# @permission_classes([AllowAny,])
class Logout(APIView):
    
    authentication_classes = [CustomAuthentication]
    
    def put(self, request,format=None):
        try:
            user_secret_key = request.data['user_secret_key']
            user = User.objects.get(user_secret_key = user_secret_key)
            user.user_secret_key = None
            user.total_login_devices = 0
            user.save(update_fields=["user_secret_key","total_login_devices"])
            return Response({"Success" : "Successfully logout from all devices"},status=status.HTTP_200_OK)
        except:
            return Response({"No user" : "This link is expired or invalid!!!"},status=status.HTTP_400_BAD_REQUEST)
        
    def post(self,request,format=None):
        response = Response()
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'])
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        try:
            user = User.objects.get(user_secret_key = request.get_signed_cookie(settings.SIMPLE_JWT['USER_SECRET_KEY'],salt = settings.SIMPLE_JWT['AUTH_COOKIE_SALT']))
            user.total_login_devices -= 1
            user.save(update_fields=['total_login_devices'])
            response.delete_cookie(settings.SIMPLE_JWT['USER_SECRET_KEY'])
            response.data = {"Success" : "Logout successfully"}
            return response
        except:
            response.data = {"Fail" : "Something went wrong.Logout fail!!!"}
            return response
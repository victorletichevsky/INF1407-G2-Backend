from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Task
from .serializers import TaskSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout
from django.contrib.auth.models import User

class TaskView(APIView):
    '''
    View para CRUD das tasks do usuário autenticado
    '''
    
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Listar tarefas",
        operation_description="Retorna uma lista de todas as tarefas disponíveis para o usuário autenticado.",
        responses={200: TaskSerializer(many=True)}
    )
    def get(self, request):
        '''
        Parâmetros: usuário da requisição
        
        Retorna: tasks correspondentes ao usuário autenticado
        '''
        tasks = Task.objects.filter(user=request.user)
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Criar tarefa",
        operation_description="Cria uma nova tarefa associada ao usuário autenticado.",
        request_body=TaskSerializer,
        responses={201: TaskSerializer}
    )
    def post(self, request):
        '''
        Parâmetros: usuário da requisição e nova task
        
        Retorna: task criada
        '''
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Atualizar tarefa",
        operation_description="Atualiza parcialmente uma tarefa existente (marcar como concluída, por exemplo).",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'completed': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='Marcar como concluída'),
            },
        ),
        responses={200: TaskSerializer}
    )
    def patch(self, request, pk):
        '''
        Parâmetros: usuário da requisição
        
        Retorna: task modificada
        '''
        try:
            task = Task.objects.get(pk=pk, user=request.user)
        except Task.DoesNotExist:
            return Response({'detail': 'Tarefa não encontrada ou você não tem permissão para editá-la.'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Deletar tarefa",
        operation_description="Exclui uma tarefa associada ao usuário autenticado pelo ID.",
        responses={204: 'No Content'}
    )
    def delete(self, request, pk):
        '''
        Parâmetros: usuário da requisição
        
        Retorna: nada
        '''
        try:
            task = Task.objects.get(pk=pk, user=request.user)
        except Task.DoesNotExist:
            return Response({'detail': 'Tarefa não encontrada ou você não tem permissão para excluí-la.'}, 
                            status=status.HTTP_404_NOT_FOUND)
        
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CustomAuthToken(APIView):
    '''
    View para gerenciamento de tokens de autenticação e registro de novos usuários
    '''

    @swagger_auto_schema(
        operation_summary='Obter o token de autenticação ou registrar novo usuário',
        operation_description='Retorna o token em caso de sucesso na autenticação ou realiza o registro de um novo usuário se solicitado.',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['username', 'password'],
        ),
        responses={
            status.HTTP_200_OK: 'Token is generated with success.',
            status.HTTP_401_UNAUTHORIZED: 'Unauthorized request.',
            status.HTTP_201_CREATED: 'User registered successfully.',
        },
    )
    def post(self, request, *args, **kwargs):
        '''
        Parâmetros: username e senha
        
        Retorna: token do usuário já existente ou recém-criado
        '''
        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()
        if user:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                token, _ = Token.objects.get_or_create(user=user)
                login(request, user)
                return Response({'token': token.key}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            user = User.objects.create_user(username=username, password=password)
            user.save()
            token = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_summary='Obtém o username',
        operation_description="Retorna o username ou visitante se o usuário não estiver autenticado.",
        security=[{'Token': []}],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Token de autenticação no formato "token <valor do token>"',
                default='token ',
            ),
        ],
        responses={
            200: openapi.Response(
                description='Nome do usuário',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'username': openapi.Schema(type=openapi.TYPE_STRING)},
                ),
            )
        },
    )
    def get(self, request):
        '''
        Parâmetros: o token de acesso
        
        Retorna: o username ou 'visitante'
        '''
        try:
            token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
            token_obj = Token.objects.get(key=token)
            user = token_obj.user
            return Response(
                {'username': user.username},
                status=status.HTTP_200_OK
            )
        except (Token.DoesNotExist, AttributeError):
            return Response(
                {'username': 'visitante'},
                status=status.HTTP_404_NOT_FOUND
            )

    @swagger_auto_schema(
        operation_description='Realiza logout, apagando o token do usuário',
        operation_summary='Realiza logout',
        security=[{'Token': []}],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING, default='token ',
                description='Token de autenticação no formato "token <valor do token>"',
            ),
        ],
        request_body=None,
        responses={
            status.HTTP_200_OK: 'User logged out',
            status.HTTP_400_BAD_REQUEST: 'Bad request',
            status.HTTP_401_UNAUTHORIZED: 'User not authenticated',
            status.HTTP_403_FORBIDDEN: 'User not authorized to logout',
            status.HTTP_500_INTERNAL_SERVER_ERROR: 'Erro no servidor',
        },
    )
    def delete(self, request):
        '''
        Parâmetros: o token de acesso
        
        Retorna: mensagem de logout bem-sucedido ou não
        '''
        try:
            token = request.META.get('HTTP_AUTHORIZATION').split(' ')[1]
            token_obj = Token.objects.get(key=token)
        except (Token.DoesNotExist, IndexError):
            return Response({'msg': 'Token não existe.'}, status=status.HTTP_400_BAD_REQUEST)
        user = token_obj.user
        if user.is_authenticated:
            request.user = user
            logout(request)
            token = Token.objects.get(user=user)
            token.delete()
            return Response({'msg': 'Logout bem-sucedido.'},
                            status=status.HTTP_200_OK)
        else:
            return Response({'msg': 'Usuário não autenticado.'},
                            status=status.HTTP_403_FORBIDDEN)
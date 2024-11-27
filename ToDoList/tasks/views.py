from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Task
from .serializers import TaskSerializer

class TaskView(APIView):
    @swagger_auto_schema(
        operation_summary="Listar tarefas",
        operation_description="Retorna uma lista de todas as tarefas disponíveis.",
        responses={200: TaskSerializer(many=True)}
    )
    def get(self, request):
        tasks = Task.objects.all()
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Criar tarefa",
        operation_description="Cria uma nova tarefa.",
        request_body=TaskSerializer,
        responses={201: TaskSerializer}
    )
    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
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
        task = Task.objects.get(pk=pk)
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Deletar tarefa",
        operation_description="Exclui uma tarefa pelo ID.",
        responses={204: 'No Content'}
    )
    def delete(self, request, pk):
        task = Task.objects.get(pk=pk)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

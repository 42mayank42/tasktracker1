# tasks/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import TaskSerializer
from django.shortcuts import get_object_or_404
from .models import Task
from users.models import User
from django.views.generic import TemplateView
from rest_framework import status, permissions
from django.shortcuts import redirect
from users.views import EncryptedJWTAuthentication


class TaskCreateView(APIView):
    authentication_classes = [EncryptedJWTAuthentication]
    def post(self, request):
        # Ensure that a non-manager user can create a task
        if request.user.role == 'manager':
            return Response({"detail": "Managers are not allowed to create tasks."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({'message': 'Task created successfully.'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskUpdateView(APIView):
    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()  # Update the task
            return Response({'message': 'Task updated successfully.'})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class TaskListView(APIView):
    def get(self, request):
        tasks = Task.objects.all().order_by('-id')
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)
    
    
class TaskChangeStatusView(APIView):
    def post(self, request, pk, status_value):
        task = get_object_or_404(Task, pk=pk)
        if status_value not in ['approved', 'rejected']:
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)

        task.status = status_value
        task.save()
        return Response({'message': f'Task {status_value} successfully.'}, status=status.HTTP_200_OK)
    


# Template Views

class TaskListView(TemplateView):
    template_name = 'tasks/task_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['tasks'] = Task.objects.all()
        
        return context


class TaskDetailView(TemplateView):
    template_name = 'tasks/task_view.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        task_id = kwargs.get('pk')
        context['task'] = Task.objects.get(pk=task_id)
        return context


class TaskCreatepage(TemplateView):
    template_name = 'tasks/task_create.html'

    def post(self, request, *args, **kwargs):
        data = request.POST.copy()

        
        if 'status' not in data:
            data['status'] = 'pending'

        serializer = TaskSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return redirect('task_list_template') 
        else:
            context = self.get_context_data(**kwargs)
            context['errors'] = serializer.errors
            return self.render_to_response(context)


class TaskUpdateView(TemplateView):
    template_name = 'tasks/task_edit.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        task_id = kwargs.get('pk')
        context['task'] = Task.objects.get(pk=task_id)
        return context


# API Views

class TaskListAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        tasks = Task.objects.all()
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)


class TaskCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Task created successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskUpdateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Task updated successfully.'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskDetailAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        serializer = TaskSerializer(task)
        return Response(serializer.data)


class TaskChangeStatusAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk, status_value):
        task = get_object_or_404(Task, pk=pk)

        if status_value not in ['approved', 'rejected']:
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)

        task.status = status_value
        task.save()
        return Response({'message': f'Task {status_value} successfully.'}, status=status.HTTP_200_OK)

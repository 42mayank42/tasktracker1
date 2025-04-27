from django.urls import path
from . import views

urlpatterns = [
    # Task List (Template View)
    path('list/', views.TaskListView.as_view(), name='task_list_template'),

    # Task Detail (Template View)
    path('detail/<int:pk>/', views.TaskDetailView.as_view(), name='task_detail_template'),

    # Task Create (Template View)
    path('create/', views.TaskCreatepage.as_view(), name='task_create_template'),

    # Task Edit (Template View)
    path('update/<int:pk>/', views.TaskUpdateView.as_view(), name='task_edit_template'),

    # API: List All Tasks
    path('api/list/', views.TaskListAPIView.as_view(), name='task_list_api'),

    # API: Create a Task
    path('api/create/', views.TaskCreateAPIView.as_view(), name='task_create_api'),

    # API: Update a Task
    path('api/update/<int:pk>/', views.TaskUpdateAPIView.as_view(), name='task_edit_api'),

    # API: Task Detail
    path('api/detail/<int:pk>/', views.TaskDetailAPIView.as_view(), name='task_detail_api'),

    # API: Change Task Status
    path('api/change_status/<int:pk>/<str:status>/', views.TaskChangeStatusAPIView.as_view(), name='task_change_status_api'),
]

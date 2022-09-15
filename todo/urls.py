from django.contrib import admin
from django.urls import path
from todo.views import TodoListView,TodoDetailView
urlpatterns = [
    path('todo/',TodoListView.as_view()),
    path('todo/<int:todo_id>/',TodoDetailView.as_view())
]
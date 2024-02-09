from django.test import TestCase

# Create your tests here.
from rest_framework import status
from rest_framework.test import APITestCase

from django.utils import timezone
from .models import User, Moderator, Manager, ApplyLeave
from django.urls import reverse

class ModelsTestCase(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'user@example.com',
            'name': 'John Doe',
            'password': 'password123',
            'phone': '1234567890',
            'manager': 'Manager Name',
            'role': 'Employee',
            'dob': '1990-01-01',
            'address': '123 Main St, City',
            'leave_balance': 10,
        }
        self.moderator_data = {
            'email': 'moderator@example.com',
            'name': 'Jane Smith',
            'password': 'password456',
            'phone': '9876543210',
            'manager': 'Manager Name',
            'role': 'Moderator',
            'dob': '1985-05-05',
            'address': '456 Elm St, City',
        }
        self.manager_data = {
            'email': 'manager@example.com',
            'name': 'Michael Johnson',
        }
        self.apply_leave_data = {
            'leaveDesc': 'Vacation',
            'fromDate': timezone.now(),
            'toDate': timezone.now() + timezone.timedelta(days=5),
            'selectManager': 'Manager Name',
            'user': 'user@example.com',
            'verified': False,
        }

    def test_user_creation(self):
        user = User.objects.create(**self.user_data)
        self.assertEqual(user.email, self.user_data['email'])

    def test_moderator_creation(self):
        moderator = Moderator.objects.create(**self.moderator_data)
        self.assertEqual(moderator.email, self.moderator_data['email'])

    def test_manager_creation(self):
        manager = Manager.objects.create(**self.manager_data)
        self.assertEqual(manager.email, self.manager_data['email'])

    def test_apply_leave_creation(self):
        apply_leave = ApplyLeave.objects.create(**self.apply_leave_data)
        self.assertEqual(apply_leave.leaveDesc, self.apply_leave_data['leaveDesc'])

    def test_manager_string_representation(self):
        manager = Manager.objects.create(**self.manager_data)
        self.assertEqual(str(manager), self.manager_data['email'])

    def test_moderator_string_representation(self):
        moderator = Moderator.objects.create(**self.moderator_data)
        self.assertEqual(str(moderator), self.moderator_data['email'])




class UserLoginViewTestCase(APITestCase):
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'name': 'Test User',
            'password': 'testpassword',
            'phone': '1234567890',
            'manager': 'Test Manager',
            'role': 'Employee',
            'dob': '1990-01-01',
            'address': '123 Main St, City',
            'leave_balance': 10,
        }
        self.user = User.objects.create(**self.user_data)

    def test_successful_authentication(self):
        url = reverse('login')
        data = {
            'email': 'test@example.com',
            'password': 'testpassword',
            'role': 'Employee',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertEqual(response.data['message'], "Successfully authenticated")

    def test_invalid_credentials(self):
        url = reverse('login')
        data = {
            'email': 'test@example.com',
            'password': 'wrongpassword',
            'role': 'Employee',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.data['message'], "Invalid credentials.")

    def test_no_user_found(self):
        url = reverse('login')
        data = {
            'email': 'nonexistent@example.com',
            'password': 'password',
            'role': 'Employee',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.data['message'], "No user found")
from django.test import TestCase
from .models import User, Moderator, Manager, ApplyLeave
from rest_framework.test import APIClient
from rest_framework import status


class UserModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            email='test@example.com',
            name='Test User',
            password='testpassword',
            phone='1234567890',
            manager='Manager Name',
            role='Role',
            dob='1990-01-01',
            address='Test Address',
            leave_balance=10,
            applied_leave=0
        )

    def test_user_creation(self):
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertEqual(self.user.name, 'Test User')

class ModeratorModelTestCase(TestCase):
    def setUp(self):
        self.moderator = Moderator.objects.create(
            email='moderator@example.com',
            name='Test Moderator',
            password='moderatorpassword',
            phone='1234567890',
            manager='Manager Name',
            role='Role',
            dob='1990-01-01',
            address='Test Address'
        )

    def test_moderator_creation(self):
        self.assertEqual(self.moderator.email, 'moderator@example.com')
        self.assertEqual(self.moderator.name, 'Test Moderator')


class ManagerModelTestCase(TestCase):
    def setUp(self):
        self.manager = Manager.objects.create(
            email='manager@example.com',
            name='Test Manager'
        )

    def test_manager_creation(self):
        self.assertEqual(self.manager.email, 'manager@example.com')
        self.assertEqual(self.manager.name, 'Test Manager')

class ApplyLeaveModelTestCase(TestCase):
    def setUp(self):
        self.apply_leave = ApplyLeave.objects.create(
            leaveDesc='Test Leave Description',
            fromDate='2024-01-01',
            toDate='2024-01-05',
            selectManager='Manager Name',
            user='test@example.com',
            verified='Pending'
        )

    def test_apply_leave_creation(self):
        self.assertEqual(self.apply_leave.leaveDesc, 'Test Leave Description')
        self.assertEqual(self.apply_leave.fromDate, '2024-01-01')




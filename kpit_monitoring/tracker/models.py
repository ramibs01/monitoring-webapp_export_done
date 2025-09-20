from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


class User(AbstractUser):
    ROLE_CHOICES = (
        ("employee", "Employee"),
        ("manager", "Manager"),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="employee")

    # ➡️ New field
    special_user = models.BooleanField(default=False)  # 0 = normal, 1 = special

    def __str__(self):
        return f"{self.username} ({self.role})"



class Project(models.Model):
    name = models.CharField(max_length=255)
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,   # links to your User model
        on_delete=models.SET_NULL,  # if manager deleted → project.manager = NULL
        null=True,
        related_name="projects"
    )

    def __str__(self):
        return self.name


class UserProject(models.Model):
    employee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="user_projects"
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="user_projects"
    )
    dedication = models.PositiveIntegerField()  # dedication percentage (0–100)

    class Meta:
        unique_together = ('employee', 'project')  # each employee can appear only once per project

    def clean(self):
        """Ensure employee dedication does not exceed 100% across all projects."""
        total_dedication = (
            UserProject.objects.filter(employee=self.employee)
            .exclude(id=self.id)  # exclude current if updating
            .aggregate(models.Sum("dedication"))["dedication__sum"] or 0
        )
        if total_dedication + self.dedication > 100:
            raise ValidationError("Total dedication for this employee cannot exceed 100%.")

    def __str__(self):
        return f"{self.employee.username} → {self.project.name} ({self.dedication}%)"

class Month(models.Model):
    id = models.AutoField(primary_key=True)  # auto incremented id
    month = models.CharField(max_length=20, unique=True)  # e.g. "January"

    def __str__(self):
        return self.month
    
# models.py
class CalendarWeek(models.Model):
    cw = models.CharField(max_length=10, unique=True)
    month = models.ForeignKey(
        Month,
        on_delete=models.SET_NULL,
        null=True,           # <- allow NULL
        blank=True,
        related_name="calendar_weeks",
    )
class Task(models.Model):
    task_name = models.CharField(max_length=255)
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        null=True,   # allow null for common tasks
        blank=True,
        related_name="tasks"
    )
    common_task = models.BooleanField(default=False)  # applies to all projects if True

    def __str__(self):
        if self.common_task:
            return f"{self.task_name} (Common)"
        return f"{self.task_name} - {self.project.name}"

class MonitoringEntry(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    project = models.ForeignKey('Project', on_delete=models.CASCADE, null=True, blank=True)  # allow NULL for common tasks
    task = models.ForeignKey('Task', on_delete=models.CASCADE)
    month = models.ForeignKey('Month', on_delete=models.CASCADE)
    cw = models.ForeignKey('CalendarWeek', on_delete=models.CASCADE)
    hours_spent = models.DecimalField(max_digits=5, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'task', 'cw')

    def __str__(self):
        return f"{self.user.username} - {self.task.task_name} - CW{self.cw.cw}"
    
class PlannedDedication(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="planned_dedications"
    )
    project = models.ForeignKey(
        'Project',
        on_delete=models.CASCADE,
        related_name="planned_dedications"
    )
    month = models.ForeignKey(
        'Month',
        on_delete=models.CASCADE,
        related_name="planned_dedications"
    )
    planned_dedication = models.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="Planned dedication in hours or % (choose your unit)."
    )

    class Meta:
        unique_together = ('user', 'project', 'month')
        verbose_name = "Planned Dedication"
        verbose_name_plural = "Planned Dedications"

    def __str__(self):
        return f"{self.user.username} → {self.project.name} ({self.month.month}): {self.planned_dedication}"
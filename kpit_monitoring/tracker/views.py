from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import User,UserProject,Month, CalendarWeek,Task,MonitoringEntry,PlannedDedication
from django.contrib import messages
from django.db.models import Q
from .models import Project
from django.http import JsonResponse
import openpyxl
from openpyxl.styles import Font
from django.http import HttpResponse
from django.db.models import Sum
import os
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            if user.role == "manager":
                return redirect("manager_dashboard")
            else:
                return redirect("employee_dashboard")
        else:
            return render(request, "login.html", {"error": "Invalid username or password"})

    return render(request, "login.html")

@login_required
def employee_dashboard(request):
    return render(request, "employee_dashboard.html")

@login_required
def manager_dashboard(request):
    # Count number of employees
    employees_count = User.objects.filter(role="employee").count()
    projects_count = Project.objects.count()

    return render(request, "manager_dashboard.html", {
        "employees_count": employees_count,
        "projects_count": projects_count
    })

def logout_view(request):
    logout(request)
    return redirect("login")

@login_required
def manage_employees(request):
    # Only managers can access this page
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    employees = User.objects.filter(role="employee")
    employees_count = employees.count()

    return render(request, "manage_employees.html", {
        "employees": employees,
        "employees_count": employees_count
    })


@login_required
def add_employee(request):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        is_special = request.POST.get("special_user") == "on"  # checkbox value

        if username and password and email:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists")
            else:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                user.role = "employee"
                user.special_user = 1 if is_special else 0
                user.save()
                messages.success(request, f"Employee {username} added successfully")
                return redirect("manage_employees")
        else:
            messages.error(request, "Please fill all fields")

    return render(request, "add_employee.html")


@login_required
def edit_employee(request, user_id):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    try:
        employee = User.objects.get(id=user_id, role="employee")
    except User.DoesNotExist:
        messages.error(request, "Employee not found")
        return redirect("manage_employees")

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if username:
            employee.username = username
        if email:
            employee.email = email
        if password:
            employee.set_password(password)  # important for Django auth
        employee.save()
        #messages.success(request, "Employee updated successfully")
        return redirect("manage_employees")

    return render(request, "edit_employee.html", {"employee": employee})

@login_required
def delete_employee(request, user_id):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    try:
        employee = User.objects.get(id=user_id, role="employee")
        employee.delete()
        #messages.success(request, "Employee deleted successfully")
    except User.DoesNotExist:
        messages.error(request, "Employee not found")

    return redirect("manage_employees")


@login_required
def manage_projects(request):
    projects = Project.objects.all()
    return render(request, "manage_projects.html", {"projects": projects})

@login_required
def add_project(request):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    if request.method == "POST":
        name = request.POST.get("name")
        manager_id = request.POST.get("manager")  # dropdown with manager IDs

        if name and manager_id:
            manager = User.objects.filter(id=manager_id, role="manager").first()
            project = Project.objects.create(name=name, manager=manager)
            return redirect("manage_projects")
        else:
            messages.error(request, "Please fill all fields")

    managers = User.objects.filter(role="manager")
    return render(request, "add_project.html", {"managers": managers})

@login_required
def edit_project(request, project_id):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        messages.error(request, "Project not found")
        return redirect("manage_projects")

    if request.method == "POST":
        name = request.POST.get("name")
        manager_id = request.POST.get("manager")

        if name:
            project.name = name
        if manager_id:
            manager = User.objects.filter(id=manager_id, role="manager").first()
            project.manager = manager
        project.save()
        return redirect("manage_projects")

    managers = User.objects.filter(role="manager")
    return render(request, "edit_project.html", {"project": project, "managers": managers})

@login_required
def delete_project(request, project_id):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    try:
        project = Project.objects.get(id=project_id)
        project.delete()
    except Project.DoesNotExist:
        messages.error(request, "Project not found")

    return redirect("manage_projects")


@login_required
def manage_resources(request):
    if request.user.role != "manager":
        return redirect("employee_dashboard")

    # Fetch resources with employee + project in one query
    resources = UserProject.objects.select_related("employee", "project").all()

    return render(request, "manage_resources.html", {"resources": resources})

def add_assigned_resource(request):
    employees = User.objects.all()
    projects = Project.objects.all()

    if request.method == "POST":
        employee_id = request.POST.get("employee")
        project_id = request.POST.get("project")
        dedication = request.POST.get("dedication")

        if employee_id and project_id and dedication:
            try:
                employee = User.objects.get(id=employee_id)
                project = Project.objects.get(id=project_id)

                # Save new assignment
                UserProject.objects.create(
                    employee=employee,
                    project=project,
                    dedication=dedication
                )

                messages.success(request, "Resource assigned successfully!")
                return redirect("manage_resources")
            except Exception as e:
                messages.error(request, f"Error: {str(e)}")

    return render(request, "add_assigned_resource.html", {
        "employees": employees,
        "projects": projects,
    })

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import UserProject, User, Project

# List all resources
def manage_resources(request):
    resources = UserProject.objects.select_related("employee", "project").all()
    return render(request, "manage_resources.html", {"resources": resources})

# Add new resource assignment
def add_assigned_resource(request):
    employees = User.objects.all()
    projects = Project.objects.all()

    if request.method == "POST":
        employee_id = request.POST.get("employee")
        project_id = request.POST.get("project")
        dedication = request.POST.get("dedication")

        employee = get_object_or_404(User, id=employee_id)
        project = get_object_or_404(Project, id=project_id)

        UserProject.objects.create(
            employee=employee,
            project=project,
            dedication=dedication
        )
        messages.success(request, "Resource assigned successfully.")
        return redirect("manage_resources")

    return render(request, "add_assigned_resource.html", {
        "employees": employees,
        "projects": projects
    })

# Edit existing resource
def edit_assigned_resource(request, resource_id):
    resource = get_object_or_404(UserProject, id=resource_id)
    employees = User.objects.filter(role="employee")
    projects = Project.objects.all()

    if request.method == "POST":
        employee_id = request.POST.get("employee")
        project_id = request.POST.get("project")
        dedication = request.POST.get("dedication")

        resource.employee = get_object_or_404(User, id=employee_id)
        resource.project = get_object_or_404(Project, id=project_id)
        resource.dedication = dedication
        resource.save()

        messages.success(request, "Resource updated successfully.")
        return redirect("manage_resources")

    return render(request, "edit_assigned_resource.html", {
        "resource": resource,
        "employees": employees,
        "projects": projects
    })

# Delete resource
def delete_assigned_resource(request, resource_id):
    resource = get_object_or_404(UserProject, id=resource_id)
    resource.delete()
    messages.success(request, "Resource deleted successfully.")
    return redirect("manage_resources")

def manage_cw(request):
    months = Month.objects.all()
    calendar_weeks = CalendarWeek.objects.all()

    if request.method == "POST":
        month_id = request.POST.get("month_id")
        cw_ids = request.POST.getlist("cw_ids")  # multiple values

        if month_id and cw_ids:
            for cw_id in cw_ids:
                cw = get_object_or_404(CalendarWeek, id=cw_id)
                cw.month_id = month_id
                cw.save()
            return redirect("manage_cw")

    return render(request, "manage_cw.html", {"months": months, "calendar_weeks": calendar_weeks})


def manage_tasks(request):
    tasks = Task.objects.select_related("project").all()  # optimize query
    return render(request, "manage_tasks.html", {"tasks": tasks})

def add_task(request):
    projects = Project.objects.all()
    if request.method == "POST":
        task_name = request.POST.get("task_name")
        project_id = request.POST.get("project")
        common_task = request.POST.get("common_task") == "on"

        if common_task:
            Task.objects.create(task_name=task_name, common_task=True)
        else:
            project = Project.objects.get(id=project_id)
            Task.objects.create(task_name=task_name, project=project)

        return redirect("manage_tasks")

    return render(request, "add_task.html", {"projects": projects})

def edit_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    projects = Project.objects.all()
    
    if request.method == "POST":
        task_name = request.POST.get("task_name")
        project_id = request.POST.get("project")
        if project_id:
            project = Project.objects.get(id=project_id)
        else:
            project = None  # task common to all projects
        
        task.task_name = task_name
        task.project = project
        task.save()
        messages.success(request, "Task updated successfully!")
        return redirect('manage_tasks')
    
    return render(request, "edit_task.html", {"task": task, "projects": projects})

# Delete Task
def delete_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    task.delete()
    messages.success(request, "Task deleted successfully!")
    return redirect('manage_tasks')

@login_required
def fill_monitoring(request):
    months = Month.objects.all()
    cws = CalendarWeek.objects.select_related('month').all()

    # Debug: which projects does this user have?
    user_projects = UserProject.objects.filter(employee=request.user).select_related("project")
    project_ids = [up.project.id for up in user_projects]

    print("User:", request.user.username)
    print("User projects:", project_ids)

    # Fetch tasks
    tasks = Task.objects.filter(Q(project_id__in=project_ids) | Q(common_task=True)).select_related("project")

    print("Tasks count:", tasks.count())
    for t in tasks:
        print("Task:", t.task_name, "Project:", t.project)

    if request.method == 'POST':
        month_id = request.POST.get('month')
        cw_id = request.POST.get('cw')

        for task in tasks:
            hours = request.POST.get(f'hours_{task.id}')
            if hours and month_id and cw_id:
                MonitoringEntry.objects.update_or_create(
                    user=request.user,
                    task=task,
                    cw_id=int(cw_id),
                    defaults={
                        'project': task.project if task.project else None,
                        'month_id': int(month_id),
                        'hours_spent': float(hours)
                    }
                )
        return redirect('monitoring_dashboard')

    return render(request, 'fill_monitoring.html', {
        'months': months,
        'cws': cws,
        'tasks': tasks,
    })



@login_required
def monitoring_success(request):
    return render(request, 'monitoring_success.html')


@login_required


@login_required
def monitoring_dashboard(request):
    all_cws = CalendarWeek.objects.select_related("month").all().order_by("month__id", "cw")

    monitoring_entries = (
        MonitoringEntry.objects
        .filter(user=request.user)
        .select_related("month", "cw", "project", "task")
    )

    # Filter by CW if selected
    cw_id = request.GET.get("cw")
    if cw_id:
        monitoring_entries = monitoring_entries.filter(cw_id=cw_id)

    # ---- 🔽 Sort by the number after "CW" ----
    monitoring_entries = sorted(
        monitoring_entries,
        key=lambda e: int(e.cw.cw.replace("CW", "")) if e.cw and e.cw.cw else 0
    )
    # -------------------------------------------

    return render(
        request,
        "monitoring_dashboard.html",
        {
            "monitoring_entries": monitoring_entries,
            "all_cws": all_cws,
        },
    )

@login_required
@login_required
def consult_monitoring(request):
    # Only managers can access
    if request.user.role != "manager":
        return redirect("monitoring_dashboard")

    users = User.objects.all().order_by("username")
    cws = CalendarWeek.objects.select_related("month").all()
    entries = None
    selected_user = None
    selected_cw = None
    total_hours = 0  # ✅ new

    if request.method == "POST":
        user_id = request.POST.get("user")
        cw_id = request.POST.get("cw")

        if user_id and cw_id:
            selected_user = User.objects.get(id=user_id)
            selected_cw = CalendarWeek.objects.get(id=cw_id)
            entries = (
                MonitoringEntry.objects
                .filter(user=selected_user, cw=selected_cw)
                .select_related("task", "project", "month")
            )

            # ✅ Calculate total hours
            total_hours = entries.aggregate(total=Sum("hours_spent"))["total"] or 0

    return render(
        request,
        "consult_monitoring.html",
        {
            "users": users,
            "cws": cws,
            "entries": entries,
            "selected_user": selected_user,
            "selected_cw": selected_cw,
            "total_hours": total_hours,  # ✅ pass to template
        },
    )


from collections import defaultdict
@login_required
def export_monitoring_excel(request):
    months = Month.objects.all()
    month_id = request.GET.get("month")

    if month_id:
        try:
            month = Month.objects.get(id=month_id)

            # 1️⃣ Exclude entries that belong to common tasks
            entries = (
                MonitoringEntry.objects
                .filter(month=month)
                .exclude(task__common_task=True)
                .select_related("project", "user", "task")
            )

            # 2️⃣ Count number of CWs in the selected month
            num_cws = CalendarWeek.objects.filter(month=month).count()

            # 3️⃣ Total worked hours per user (excluding common tasks)
            user_totals_qs = (
                entries.values("user__id", "user__username", "user__special_user")
                .annotate(total_hours=Sum("hours_spent"))
            )
            totals_map = {
                row["user__id"]: {
                    "username": row["user__username"],
                    "total_hours": float(row["total_hours"] or 0),
                    "special_user": row["user__special_user"]
                }
                for row in user_totals_qs
            }

            # 4️⃣ Aggregate hours per project/user
            project_user_data = (
                entries.values("project__name", "user__id")
                .annotate(project_hours=Sum("hours_spent"))
                .order_by("project__name", "user__username")
            )

            # 5️⃣ Group by project
            grouped = defaultdict(list)
            for row in project_user_data:
                grouped[row["project__name"]].append(row)

            # 6️⃣ Create Excel workbook
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = f"Monitoring {month.month}"

            headers = ["Project", "KPIT Colleague", "Hours", "Month", "%"]
            ws.append(headers)
            for cell in ws[1]:
                cell.font = Font(bold=True)

            current_row = 2
            for project, rows in grouped.items():
                start_row = current_row
                for row in rows:
                    user_info = totals_map[row["user__id"]]
                    username = user_info["username"]
                    project_hours = float(row["project_hours"] or 0)
                    total_hours_user = user_info["total_hours"]
                    special_user = user_info["special_user"]

                    # ✅ Determine base hours for % calculation
                    if special_user:
                        # Super user
                        if num_cws == 4:
                            base_hours = 160
                        elif num_cws == 5:
                            base_hours = 200
                        else:
                            base_hours = total_hours_user  # fallback
                    else:
                        # Normal user
                        base_hours = total_hours_user

                    percentage = 0
                    if base_hours > 0:
                        raw_pct = (project_hours / base_hours) * 100
                        percentage = round(raw_pct / 5) * 5  # MROUND to nearest 5%

                    ws.append([project, username, project_hours, month.month, f"{percentage}%"])
                    current_row += 1

                if len(rows) > 1:
                    ws.merge_cells(
                        start_row=start_row,
                        start_column=1,
                        end_row=current_row - 1,
                        end_column=1
                    )

            # 7️⃣ Return file
            response = HttpResponse(
                content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            filename = f"Monitoring_{month.month}.xlsx"
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            wb.save(response)
            return response

        except Month.DoesNotExist:
            pass

    return render(request, "export_monitoring.html", {"months": months})




@login_required
def user_monitoring_dashboard(request):
    cw_filter = request.GET.get('cw')
    entries = MonitoringEntry.objects.filter(user=request.user).select_related('month', 'cw', 'project', 'task')
    
    if cw_filter:
        entries = entries.filter(cw_id=cw_filter)
    
    # Sort entries by CW number
    entries = sorted(
        entries,
        key=lambda e: int(e.cw.cw.replace('CW', '')) if e.cw.cw.startswith('CW') else 0
    )
    
    all_cws = CalendarWeek.objects.all()
    
    return render(request, 'user_monitoring_dashboard.html', {
        'monitoring_entries': entries,
        'all_cws': all_cws,
    })

@login_required
def user_fill_monitoring(request):
    months = Month.objects.all()
    cws = CalendarWeek.objects.select_related('month').all()

    # User projects
    user_projects = UserProject.objects.filter(employee=request.user).select_related("project")
    project_ids = [up.project.id for up in user_projects]

    # Tasks related to user projects OR common tasks
    tasks = Task.objects.filter(Q(project_id__in=project_ids) | Q(common_task=True)).select_related("project")

    if request.method == 'POST':
        month_id = request.POST.get('month')
        cw_id = request.POST.get('cw')

        for task in tasks:
            hours = request.POST.get(f'hours_{task.id}')
            if hours and month_id and cw_id:
                MonitoringEntry.objects.update_or_create(
                    user=request.user,
                    task=task,
                    cw_id=int(cw_id),
                    defaults={
                        'project': task.project if task.project else None,
                        'month_id': int(month_id),
                        'hours_spent': float(hours)
                    }
                )
        return redirect('user_monitoring_dashboard')

    return render(request, 'user_fill_monitoring.html', {
        'months': months,
        'cws': cws,
        'tasks': tasks,
    })

@login_required
def user_edit_profile(request):
    user = request.user

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')

        # Update username/email
        user.username = username
        user.email = email
        user.save()

        # Update password if provided
        new_password = request.POST.get('password')
        if new_password:
            user.set_password(new_password)
            user.save()
            # Keep user logged in after password change
            update_session_auth_hash(request, user)

        messages.success(request, "Profile updated successfully!")
        return redirect('user_edit_profile')

    return render(request, 'user_edit_profile.html', {'user': user})

@login_required
def edit_monitoring(request, entry_id):
    entry = get_object_or_404(MonitoringEntry, id=entry_id, user=request.user)

    if request.method == "POST":
        project_id = request.POST.get("project")
        task_id = request.POST.get("task")
        hours_spent = request.POST.get("hours_spent")

        entry.project_id = project_id if project_id else None
        entry.task_id = task_id
        entry.hours_spent = hours_spent
        entry.save()

        messages.success(request, "✅ Monitoring entry updated successfully.")
        return redirect("monitoring_dashboard")

    projects = Project.objects.all()
    tasks = Task.objects.all()
    return render(request, "edit_monitoring.html", {
        "entry": entry,
        "projects": projects,
        "tasks": tasks,
    })


@login_required
def delete_monitoring(request, entry_id):
    entry = get_object_or_404(MonitoringEntry, id=entry_id, user=request.user)
    entry.delete()
    messages.success(request, "🗑️ Monitoring entry deleted successfully.")
    return redirect("monitoring_dashboard")

def user_edit_monitoring(request, entry_id):
    entry = get_object_or_404(MonitoringEntry, id=entry_id, user=request.user)

    if request.method == "POST":
        project_id = request.POST.get("project")
        task_id = request.POST.get("task")
        month_id = request.POST.get("month")
        cw_id = request.POST.get("cw")
        hours_spent = request.POST.get("hours_spent")

        # Update fields
        entry.project_id = project_id if project_id else None
        entry.task_id = task_id
        entry.month_id = month_id
        entry.cw_id = cw_id
        entry.hours_spent = hours_spent
        entry.save()

        messages.success(request, "Monitoring entry updated successfully.")
        return redirect("user_monitoring_dashboard")

    context = {
        "entry": entry,
        "projects": Project.objects.all(),
        "tasks": Task.objects.all(),
        "months": Month.objects.all(),
        "cws": CalendarWeek.objects.all(),
    }
    return render(request, "user_edit_monitoring.html", context)


@login_required
def user_delete_monitoring(request, entry_id):
    entry = get_object_or_404(MonitoringEntry, id=entry_id, user=request.user)
    entry.delete()
    messages.success(request, "Monitoring entry deleted successfully.")
    return redirect("user_monitoring_dashboard")

@login_required
def manager_edit_profile(request):
    user = request.user  # manager user

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        # Update username and email
        user.username = username
        user.email = email

        # Update password only if provided
        if password:
            user.set_password(password)

        user.save()

        messages.success(request, "Profile updated successfully!")

        # If password changed, log the user in again
        if password:
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, user)

        return redirect('manager_edit_profile')

    return render(request, "manager_edit_profile.html", {"user": user})

@login_required
def consult_monitoring_cw(request):
    """
    Manager page:
    - Select a CW from a dropdown
    - Show all MonitoringEntry rows for that CW
    - Merge 'User' column
    - Add total hours per user
    """
    cws = CalendarWeek.objects.all().order_by("cw")
    selected_cw = request.GET.get("cw")

    entries_qs = MonitoringEntry.objects.none()
    rows = []

    if selected_cw:
        try:
            cw_id = int(selected_cw)
            entries_qs = (
                MonitoringEntry.objects
                .filter(cw_id=cw_id)
                .select_related("user", "task__project")
                .order_by("user__username", "task__task_name")
            )

            if entries_qs.exists():
                # Build rows with rowspan and total hours
                buffer = []
                current_user = None
                count = 0
                user_total_hours = 0

                for entry in entries_qs:
                    if current_user != entry.user.username:
                        # flush previous buffer
                        if buffer:
                            for i, e in enumerate(buffer):
                                rows.append({
                                    "entry": e,
                                    "rowspan": count if i == 0 else 0,
                                    "total_hours": user_total_hours if i == 0 else 0
                                })
                        # reset for new user
                        buffer = [entry]
                        current_user = entry.user.username
                        count = 1
                        user_total_hours = entry.hours_spent
                    else:
                        buffer.append(entry)
                        count += 1
                        user_total_hours += entry.hours_spent

                # flush last buffer
                if buffer:
                    for i, e in enumerate(buffer):
                        rows.append({
                            "entry": e,
                            "rowspan": count if i == 0 else 0,
                            "total_hours": user_total_hours if i == 0 else 0
                        })

        except (ValueError, TypeError):
            pass

    return render(
        request,
        "consult_monitoring_cw.html",
        {
            "cws": cws,
            "selected_cw": selected_cw,
            "rows": rows,
            "has_entries": entries_qs.exists(),
        },
    )


@login_required
def planned_dedication_list(request):
    dedications = PlannedDedication.objects.all().select_related("user", "project", "month")

    # Apply filters
    month_id = request.GET.get("month")
    user_id = request.GET.get("user")
    project_id = request.GET.get("project")
    dedication_val = request.GET.get("dedication")

    if month_id:
        dedications = dedications.filter(month_id=month_id)
    if user_id:
        dedications = dedications.filter(user_id=user_id)
    if project_id:
        dedications = dedications.filter(project_id=project_id)
    if dedication_val:
        dedications = dedications.filter(planned_dedication=dedication_val)

    context = {
        "dedications": dedications,
        "months": Month.objects.all(),
        "users": User.objects.all(),
        "projects": Project.objects.all(),
    }
    return render(request, "planned_dedication_list.html", context)


@login_required
def add_planned_dedication(request):
    users = User.objects.all()
    projects = Project.objects.all()
    months = Month.objects.all()

    if request.method == "POST":
        user_id = request.POST.get("user")
        project_id = request.POST.get("project")
        month_id = request.POST.get("month")
        dedication = request.POST.get("planned_dedication")

        if user_id and project_id and month_id and dedication:
            try:
                dedication_value = int(dedication)
                user = User.objects.get(id=user_id)
                project = Project.objects.get(id=project_id)
                month = Month.objects.get(id=month_id)

                PlannedDedication.objects.create(
                    user=user,
                    project=project,
                    month=month,
                    planned_dedication=dedication_value,
                )
                messages.success(request, "Planned dedication added successfully.")
                return redirect("planned_dedication_list")
            except (ValueError, User.DoesNotExist, Project.DoesNotExist, Month.DoesNotExist):
                messages.error(request, "Invalid data, please check your inputs.")
        else:
            messages.error(request, "All fields are required.")

    return render(
        request,
        "add_planned_dedication.html",
        {"users": users, "projects": projects, "months": months},
    )

from openpyxl.utils import get_column_letter
@login_required
@login_required
def export_monthly_dedication(request):
    months = Month.objects.all()

    if request.method == "POST":
        month_id = request.POST.get("month")
        month_obj = Month.objects.get(id=month_id)

        dedications = PlannedDedication.objects.filter(month_id=month_id).select_related("user", "project")

        # Group dedications by project
        grouped = defaultdict(list)
        for d in dedications:
            grouped[d.project.name].append(d)

        # Create workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Monthly Dedications"

        # Header
        headers = ["Project", "KPIT Colleague", "Month", "Planned Dedication"]
        ws.append(headers)

        # Write data rows with merging
        current_row = 2
        for project_name, rows in grouped.items():
            start_row = current_row
            for d in rows:
                ws.append([project_name, d.user.username, month_obj.month, d.planned_dedication])
                current_row += 1
            # Merge project column if more than one row
            if len(rows) > 1:
                ws.merge_cells(
                    start_row=start_row,
                    start_column=1,
                    end_row=current_row - 1,
                    end_column=1
                )

        # Adjust column widths
        for i, col in enumerate(headers, start=1):
            ws.column_dimensions[get_column_letter(i)].width = 25

        # Prepare response
        response = HttpResponse(
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        filename = f"Monthly_Dedication_{month_obj.month}.xlsx"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        wb.save(response)
        return response

    return render(request, "export_monthly_dedication.html", {"months": months})
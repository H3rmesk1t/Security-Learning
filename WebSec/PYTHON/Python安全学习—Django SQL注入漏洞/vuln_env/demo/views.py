import datetime

from django.db.models import Count
from django.http import HttpResponse

# Create your views here.
from demo.models import User


def loadexampledata(request):
    u = User(name="Admin")
    u.save()
    u = User(name="Staff1")
    u.save()
    u = User(name="Staff12")
    u.save()
    return HttpResponse("ok")


def users(request):
    field = request.GET.get('field', 'name')
    user_amount = User.objects.annotate(**{field: Count("name")})
    html = ""
    for u in user_amount:
        html += "<h3>Amoount of users: {0}</h3>".format(u)
    return HttpResponse(html)

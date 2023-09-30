# Generated by Django 4.1.7 on 2023-03-10 16:26

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('panel_app', '0017_incidentmanagement_case_update_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 3, 10, 13, 26, 43, 815191, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='CaseComment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('body', models.TextField()),
                ('pub_date', models.DateTimeField(auto_now_add=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('publication', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='panel_app.incidentmanagement')),
            ],
        ),
    ]
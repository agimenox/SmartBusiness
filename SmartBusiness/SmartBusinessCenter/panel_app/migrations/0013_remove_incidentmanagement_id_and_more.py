# Generated by Django 4.1.7 on 2023-03-09 22:07

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('panel_app', '0012_alter_incidentmanagement_registration_date'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='incidentmanagement',
            name='id',
        ),
        migrations.AddField(
            model_name='incidentmanagement',
            name='priority_case',
            field=models.CharField(default='Normal', max_length=32),
        ),
        migrations.AlterField(
            model_name='incidentmanagement',
            name='incident_number',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 3, 9, 19, 7, 52, 198433, tzinfo=datetime.timezone.utc)),
        ),
    ]

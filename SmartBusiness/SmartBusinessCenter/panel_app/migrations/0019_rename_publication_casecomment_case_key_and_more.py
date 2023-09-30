# Generated by Django 4.1.7 on 2023-03-10 16:46

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('panel_app', '0018_alter_incidentmanagement_registration_date_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='casecomment',
            old_name='publication',
            new_name='case_key',
        ),
        migrations.AlterField(
            model_name='incidentmanagement',
            name='registration_date',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2023, 3, 10, 13, 45, 55, 556122, tzinfo=datetime.timezone.utc)),
        ),
    ]

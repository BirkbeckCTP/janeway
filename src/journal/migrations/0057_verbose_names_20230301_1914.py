# Generated by Django 3.2.16 on 2023-03-01 19:14

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('journal', '0056_auto_20230126_1317'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='fixedpubcheckitems',
            options={'verbose_name_plural': 'Fixed pub check items'},
        ),
        migrations.AlterModelOptions(
            name='notifications',
            options={'verbose_name_plural': 'notifications'},
        ),
    ]

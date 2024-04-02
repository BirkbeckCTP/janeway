# Generated by Django 3.2.20 on 2024-04-02 11:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('repository', '0042_auto_20240312_0922'),
    ]

    operations = [
        migrations.AddField(
            model_name='historicalrepository',
            name='additional_version_help',
            field=models.TextField(blank=True, default='', help_text='This text allows repository managers to provide additional information to authors when they are uploading an update to their submission.', verbose_name='Additional version upload help text'),
        ),
        migrations.AddField(
            model_name='repository',
            name='additional_version_help',
            field=models.TextField(blank=True, default='', help_text='This text allows repository managers to provide additional information to authors when they are uploading an update to their submission.', verbose_name='Additional version upload help text'),
        ),
    ]

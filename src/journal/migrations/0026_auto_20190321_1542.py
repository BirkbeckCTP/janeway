# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-03-21 15:42
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('journal', '0025_remove_issue_guest_editors'),
    ]

    operations = [
        migrations.CreateModel(
            name='IssueEditor',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(default='Guest Editor', max_length=255)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('issue', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='journal.Issue')),
            ],
        ),
        migrations.AddField(
            model_name='issue',
            name='guest_editors',
            field=models.ManyToManyField(blank=True, null=True, related_name='guest_editors', through='journal.IssueEditor', to=settings.AUTH_USER_MODEL),
        ),
    ]

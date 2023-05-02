# -*- coding: utf-8 -*-
# Generated by Django 1.11.23 on 2020-01-16 12:01
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('journal', '0037_auto_20200116_1201'),
        ('submission', '0039_auto_20191115_1253'),
    ]

    operations = [
        migrations.AddField(
            model_name='article',
            name='projected_issue',
            field=models.ForeignKey(
                to='journal.Issue',
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='projected_issue',
                help_text='This field is for internal purposes only '
                          'before publication. You can use it to '
                          'track likely issue assignment before formally '
                          'assigning an issue.',
            ),
        ),
    ]

# -*- coding: utf-8 -*-
# Generated by Django 1.11.29 on 2020-05-29 14:15
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0044_auto_20200526_1010'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='frozenauthor',
            options={'ordering': ('order', 'pk')},
        ),
        migrations.AlterField(
            model_name='submissionconfiguration',
            name='subtitle',
            field=models.BooleanField(default=False),
        ),
    ]

# -*- coding: utf-8 -*-
# Generated by Django 1.11.29 on 2021-02-03 17:17
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0049_auto_20201117_1904'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='sectiontranslation',
            options={'default_permissions': (), 'managed': True, 'verbose_name': 'section Translation'},
        ),
        migrations.AlterModelManagers(
            name='section',
            managers=[
            ],
        ),
        migrations.AlterField(
            model_name='sectiontranslation',
            name='language_code',
            field=models.CharField(db_index=True, max_length=15, verbose_name='Language'),
        ),
        migrations.AlterField(
            model_name='sectiontranslation',
            name='master',
            field=models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='translations', to='submission.Section'),
        ),
    ]

# -*- coding: utf-8 -*-
# Generated by Django 1.11.29 on 2022-06-10 13:41
from __future__ import unicode_literals

from django.db import migrations
import django_bleach.models


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0069_delete_blank_keywords'),
    ]

    operations = [
        migrations.AlterField(
            model_name='article',
            name='abstract',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
        migrations.AlterField(
            model_name='article',
            name='abstract_cy',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
        migrations.AlterField(
            model_name='article',
            name='abstract_de',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
        migrations.AlterField(
            model_name='article',
            name='abstract_en',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
        migrations.AlterField(
            model_name='article',
            name='abstract_fr',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
        migrations.AlterField(
            model_name='article',
            name='abstract_nl',
            field=django_bleach.models.BleachField(blank=True, help_text='Please avoid pasting content from word processors as they can add unwanted styling to the abstract. You can retype the abstract here or copy and paste it into notepad/a plain text editor before pasting here.', null=True),
        ),
    ]

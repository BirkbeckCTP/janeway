# -*- coding: utf-8 -*-
# Generated by Django 1.11.23 on 2019-11-15 12:53
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0039_auto_20191115_1253'),
        ('metrics', '0006_auto_20190627_1412'),
    ]

    operations = [
        migrations.CreateModel(
            name='ForwardLink',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('doi', models.CharField(max_length=255)),
                ('object_type', models.CharField(choices=[('book', 'Book'), ('article', 'Article')], max_length=10)),
                ('year', models.CharField(max_length=5)),
            ],
        ),
        migrations.CreateModel(
            name='ArticleLink',
            fields=[
                ('forwardlink_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='metrics.ForwardLink')),
                ('journal_title', models.TextField()),
                ('journal_issn', models.CharField(max_length=20)),
                ('article_title', models.TextField()),
                ('volume', models.PositiveIntegerField(blank=True, null=True)),
                ('issue', models.PositiveIntegerField(blank=True, null=True)),
            ],
            bases=('metrics.forwardlink',),
        ),
        migrations.CreateModel(
            name='BookLink',
            fields=[
                ('forwardlink_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='metrics.ForwardLink')),
                ('title', models.TextField()),
                ('isbn_print', models.TextField()),
                ('isbn_electronic', models.TextField()),
                ('component_number', models.TextField()),
            ],
            bases=('metrics.forwardlink',),
        ),
        migrations.AddField(
            model_name='forwardlink',
            name='article',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='submission.Article'),
        ),
    ]

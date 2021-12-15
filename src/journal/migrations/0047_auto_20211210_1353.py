# -*- coding: utf-8 -*-
# Generated by Django 1.11.29 on 2021-12-10 18:53
from __future__ import unicode_literals

import core.file_system
from django.db import migrations, models
import django.db.models.deletion
import journal.models


class Migration(migrations.Migration):

    dependencies = [
        ('journal', '0046_auto_20210922_1436'),
    ]

    operations = [
        migrations.AlterField(
            model_name='journal',
            name='default_cover_image',
            field=models.ImageField(blank=True, help_text="The default cover image for journal issues and for the journal's listing on the press-level website", null=True, storage=core.file_system.JanewayFileSystemStorage(), upload_to=journal.models.cover_images_upload_path),
        ),
        migrations.AlterField(
            model_name='journal',
            name='default_large_image',
            field=models.ImageField(blank=True, help_text='The default background image for article openers and carousel items.', null=True, storage=core.file_system.JanewayFileSystemStorage(), upload_to=journal.models.cover_images_upload_path),
        ),
        migrations.AlterField(
            model_name='journal',
            name='disable_article_images',
            field=models.BooleanField(default=False, help_text='When checked, articles will not have header imagesor thumbnail images. Does not affect figures andtables within an article.'),
        ),
        migrations.AlterField(
            model_name='journal',
            name='favicon',
            field=models.ImageField(blank=True, help_text='The tiny round or square image appearing in browser tabs before the webpage title', null=True, storage=core.file_system.JanewayFileSystemStorage(), upload_to=journal.models.cover_images_upload_path),
        ),
        migrations.AlterField(
            model_name='journal',
            name='header_image',
            field=models.ImageField(blank=True, help_text='The logo-sized image at the top of all pages, typically used for journal logos.', null=True, storage=core.file_system.JanewayFileSystemStorage(), upload_to=journal.models.cover_images_upload_path),
        ),
        migrations.AlterField(
            model_name='journal',
            name='press_image_override',
            field=models.ForeignKey(blank=True, help_text='Replaces the press logo in the footer. Must be an SVG file.', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='press_image_override', to='core.File'),
        ),
        migrations.AlterField(
            model_name='journal',
            name='thumbnail_image',
            field=models.ForeignKey(blank=True, help_text="The default thumbnail for articles, not to be confused with 'Default cover image'.", null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='thumbnail_image', to='core.File'),
        ),
    ]

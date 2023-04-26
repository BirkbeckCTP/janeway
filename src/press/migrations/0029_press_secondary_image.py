# Generated by Django 3.2.18 on 2023-04-19 06:28

import core.file_system
import core.model_utils
from django.db import migrations, models
import press.models


class Migration(migrations.Migration):

    dependencies = [
        ('press', '0028_auto_20230308_2343'),
    ]

    operations = [
        migrations.AddField(
            model_name='press',
            name='secondary_image',
            field=core.model_utils.SVGImageField(
                blank=True,
                help_text='Optional secondary logo for footer. '
                          'Not implemented in all themes.',
                null=True,
                storage=core.file_system.JanewayFileSystemStorage(),
                upload_to=press.models.cover_images_upload_path,
            ),
        ),
    ]
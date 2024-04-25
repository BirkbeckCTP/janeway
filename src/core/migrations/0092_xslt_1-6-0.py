# -*- coding: utf-8 -*-
# Generated by Django 1.11.28 on 2020-04-28 08:11
from __future__ import unicode_literals
import os

from django.core.files.base import ContentFile
from django.db import migrations
from django.conf import settings

OLD_LABEL = "Janeway default (1.5.1)"
LATEST_LABEL = "Janeway default (1.6.0)"
FILE_NAME = "default-v1.6.0.xsl"
COMMENTS = """
Changes from v1.5.1
    - Added support for the style attribute in `<verse-line>`
    - Added support for the <email> element in all contexts
"""


def upgrade(apps, schema_editor):
    """ Installs the latest default XSLT preserving the previous one

    Only runs if the previous version XSLT was installed.
    If it was, it relabels it (the old label had no version), installs
    the new one and swaps any journals using the old default to use the
    new.
    """
    XSLFile = apps.get_model("core", "XSLFile")
    Galley = apps.get_model("core", "Galley")
    Journal = apps.get_model("journal", "Journal")
    new_default = old_default = None
    xsl_path = os.path.join(settings.BASE_DIR, "transform/xsl/default.xsl")
    try:
        old_default = XSLFile.objects.get(label=OLD_LABEL)
    except XSLFile.DoesNotExist:
        old_default = None

    if (
        not XSLFile.objects.filter(label=LATEST_LABEL).exists()
        and LATEST_LABEL == settings.DEFAULT_XSL_FILE_LABEL
    ):
        with open(xsl_path, 'rb') as f:
            xsl_file = ContentFile(f.read())
            xsl_file.name = FILE_NAME

        new_default, c = XSLFile.objects.get_or_create(
            label=LATEST_LABEL,
            defaults={
                "comments": COMMENTS,
                "file": xsl_file,
            },
        )
    if old_default and new_default:
        Journal.objects.filter(xsl=old_default).update(xsl=new_default)
        # Safe to upgrade all articles from previous version
        Galley.objects.filter(xsl_file=old_default).update(xsl_file=new_default)


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0091_merge_20240425_1555.py'),
    ]

    operations = [
        migrations.RunPython(upgrade, reverse_code=migrations.RunPython.noop)
    ]

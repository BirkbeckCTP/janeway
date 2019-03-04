# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-03-04 09:16
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0031_field_display'),
    ]

    operations = [
        migrations.AlterField(
            model_name='article',
            name='stage',
            field=models.CharField(choices=[('Unsubmitted', 'Unsubmitted'), ('Unassigned', 'Unassigned'), ('Assigned', 'Assigned to Editor'), ('Under Review', 'Peer Review'), ('Under Revision', 'Revision'), ('Rejected', 'Rejected'), ('Accepted', 'Accepted'), ('Editor Copyediting', 'Editor Copyediting'), ('Author Copyediting', 'Author Copyediting'), ('Final Copyediting', 'Final Copyediting'), ('Typesetting', 'Typesetting'), ('Proofing', 'Proofing'), ('pre_publication', 'Pre Publication'), ('Published', 'Published'), ('preprint_review', 'Preprint Review'), ('preprint_published', 'Preprint Published'), ('Back Content', 'Back Content Plugin')], default='Unsubmitted', max_length=200),
        ),
    ]

# Generated by Django 3.2.20 on 2024-01-16 15:02

from django.db import migrations, models
import django.db.models.deletion


def set_press_for_journal_editorial_teams(apps, schema_editor):
    Press = apps.get_model("press", "Press")
    EditorialGroup = apps.get_model("core", "EditorialGroup")
    EditorialGroup.objects.all().update(press=Press.objects.first())


class Migration(migrations.Migration):

    dependencies = [
        ('journal', '0059_alter_prepublicationchecklistitem_completed_by'),
        ('press', '0031_staffgroup_staffgroupmember'),
        ('core', '0082_account_name_prefix_20231204_1231'),
    ]

    operations = [
        migrations.AddField(
            model_name='editorialgroup',
            name='press',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to='press.press'
            ),
        ),
        migrations.AlterField(
            model_name='editorialgroup',
            name='journal',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to='journal.journal'
            ),
        ),
        migrations.RunPython(
            set_press_for_journal_editorial_teams,
            reverse_code=migrations.RunPython.noop
        ),
        migrations.AddField(
            model_name='editorialgroupmember',
            name='statement',
            field=models.TextField(blank=True, help_text='A statement of interest or purpose'),
        ),
    ]

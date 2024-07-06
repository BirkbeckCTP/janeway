# Generated by Django 4.2.11 on 2024-07-06 17:29

from django.db import migrations
from django.db.models import F


def increment_submission_steps(apps, schema_editor):
    """Increment the current step of all submissions by 1 in a transaction safe manner."""
    Article = apps.get_model("submission", "Article")
    Article.objects.all().update(current_step=F("current_step") + 1)


class Migration(migrations.Migration):

    dependencies = [
        ("submission", "0079_merge_20240602_1739"),
    ]

    operations = [
        migrations.RunPython(increment_submission_steps, reverse_code=migrations.RunPython.noop)
    ]

# Generated by Django 3.2.20 on 2023-11-07 17:50

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('repository', '0042_auto_20231107_1750'),
        ('submission', '0073_bleach_title_20230523_1804'),
        ('review', '0022_remove_reviewform_slug'),
        ('identifiers', '0009_deduplicate_identifiers_20220527'),
    ]

    operations = [
        migrations.AddField(
            model_name='identifier',
            name='preprint_version',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='repository.preprintversion'),
        ),
        migrations.AddField(
            model_name='identifier',
            name='review',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='review.reviewassignment'),
        ),
        migrations.AlterField(
            model_name='identifier',
            name='article',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='submission.article'),
        ),
    ]

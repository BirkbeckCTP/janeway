# Generated by Django 3.2.20 on 2024-05-28 21:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0090_alter_topics_unique_together'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='accounttopic',
            unique_together={('account', 'topic', 'topic_type')},
        ),
    ]
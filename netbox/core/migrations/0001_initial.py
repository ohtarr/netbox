# Generated by Django 4.1.5 on 2023-02-02 02:37

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import taggit.managers
import utilities.json


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('extras', '0084_staging'),
    ]

    operations = [
        migrations.CreateModel(
            name='DataSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ('description', models.CharField(blank=True, max_length=200)),
                ('comments', models.TextField(blank=True)),
                ('name', models.CharField(max_length=100, unique=True)),
                ('type', models.CharField(default='local', max_length=50)),
                ('source_url', models.CharField(max_length=200)),
                ('status', models.CharField(default='new', editable=False, max_length=50)),
                ('enabled', models.BooleanField(default=True)),
                ('ignore_rules', models.TextField(blank=True)),
                ('parameters', models.JSONField(blank=True, null=True)),
                ('last_synced', models.DateTimeField(blank=True, editable=False, null=True)),
                ('tags', taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag')),
            ],
            options={
                'ordering': ('name',),
            },
        ),
        migrations.CreateModel(
            name='DataFile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('path', models.CharField(editable=False, max_length=1000)),
                ('last_updated', models.DateTimeField(editable=False)),
                ('size', models.PositiveIntegerField(editable=False)),
                ('hash', models.CharField(editable=False, max_length=64, validators=[django.core.validators.RegexValidator(message='Length must be 64 hexadecimal characters.', regex='^[0-9a-f]{64}$')])),
                ('data', models.BinaryField()),
                ('source', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='datafiles', to='core.datasource')),
            ],
            options={
                'ordering': ('source', 'path'),
            },
        ),
        migrations.AddConstraint(
            model_name='datafile',
            constraint=models.UniqueConstraint(fields=('source', 'path'), name='core_datafile_unique_source_path'),
        ),
    ]

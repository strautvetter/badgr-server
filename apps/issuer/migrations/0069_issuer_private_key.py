# Generated by Django 3.2 on 2024-12-12 14:24

from django.db import migrations, models
import issuer.utils


class Migration(migrations.Migration):

    dependencies = [
        ('issuer', '0068_issuer_intendeduseverified'),
    ]

    operations = [
        migrations.AddField(
            model_name='issuer',
            name='private_key',
            field=models.CharField(blank=True, default=issuer.utils.generate_private_key_pem, max_length=512, null=True),
        ),
    ]

# Generated by Django 3.0.2 on 2020-02-02 09:46

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('demo_database', '0005_medicine_order'),
    ]

    operations = [
        migrations.CreateModel(
            name='OrderMedicine',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.PositiveIntegerField()),
                ('medicine', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='demo_database.Medicine')),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='demo_database.Order')),
            ],
        ),
        migrations.AddField(
            model_name='order',
            name='medicines',
            field=models.ManyToManyField(through='demo_database.OrderMedicine', to='demo_database.Medicine'),
        ),
    ]
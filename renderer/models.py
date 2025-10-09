from django.db import models

class Blip(models.Model):
    title = models.CharField()
    category = # enum
    time_relevancy = # either enum or numeric value directly representing the distance to center, so pre-processed
    importance = models.IntField()
    content = models.TextField()
    source = models.CharFied()
    start_date = models.DateTimeField(auto_now_add=True)

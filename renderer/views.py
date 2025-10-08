from django.shortcuts import render
from base_radar import render_radar
from blips import add_blips

def answer(request):
    svg = add_blips(render_radar())
    return HttpResponse(svg, content_type="image/svg+xml")

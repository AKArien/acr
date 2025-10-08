# The static elements of the radar. Should be pre-rendered/cached for efficiency

from math import pi, sin, cos
import drawsvg as draw

def draw_spliters(d, size):
    # could be replaced by much more math to accomodate for a different number of zones later on, but for now, we only have 4
    d.append(draw.Line(-size, 0, size, 0, stroke="black"))
    d.append(draw.Line(0, -size, 0, size, stroke="black"))

def render_radar():
    size = 100

    d = draw.Drawing(size, size, origin="center")
    d.append(draw.Circle(0, 0, size*(1/3), fill="none", stroke_width=0.5, stroke="black"))
    d.append(draw.Circle(0, 0, size*(2/3), fill="none", stroke_width=0.5, stroke="black"))
    d.append(draw.Circle(0, 0, size, fill="none", stroke_width=0.75, stroke="black"))

    draw_spliters(d, size)
    return d

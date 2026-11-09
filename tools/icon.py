"""Deterministic, antialiased DSM icon artwork. Standard library only."""
import struct
import zlib


def inside_polygon(x, y, points):
    inside = False
    j = len(points) - 1
    for i, (xi, yi) in enumerate(points):
        xj, yj = points[j]
        if (yi > y) != (yj > y) and x < (xj-xi)*(y-yi)/(yj-yi)+xi:
            inside = not inside
        j = i
    return inside


def shield(inset=0):
    # Broad shoulders and a curved point keep the visible footprint near DSM peers.
    pts = [(0.5,.055),(.89,.18),(.875,.48),(.85,.60),(.80,.71),(.72,.81),(.62,.89),(.5,.955),(.38,.89),(.28,.81),(.20,.71),(.15,.60),(.125,.48),(.11,.18)]
    return [(.5+(x-.5)*(1-inset), .5+(y-.5)*(1-inset)) for x,y in pts]


def rounded(x,y,left,top,right,bottom,r):
    if not (left <= x <= right and top <= y <= bottom):
        return False
    cx = max(left+r, min(right-r,x))
    cy = max(top+r, min(bottom-r,y))
    return (x-cx)**2+(y-cy)**2 <= r*r


def png(size):
    scale = 4
    outer, bevel, face = shield(), shield(.035), shield(.095)
    def pixel(x,y):
        # Subtle shadow remains inside the canvas, with no opaque background tile.
        shadow = max(0,1-((x-.5)/.37)**2-((y-.91)/.065)**2)
        col = (12,34,48,round(shadow*36))
        if inside_polygon(x,y,outer):
            col = (52,90,108,255)
        if inside_polygon(x,y,bevel):
            light = max(0,min(1,1-y*.9-x*.2))
            col = tuple(round(a+(b-a)*light) for a,b in zip((99,145,158),(229,248,249)))+(255,)
        if inside_polygon(x,y,face):
            t=max(0,min(1,y*.82+x*.25))
            col=tuple(round(a+(b-a)*t) for a,b in zip((29,193,186),(9,65,100)))+(255,)
            # Broad glass highlight and a quiet faceted edge.
            if x<.5:
                col=tuple(min(255,v+int(10*(1-y))) for v in col[:3])+(255,)
            if y < .21+(x-.13)*.26:
                col=tuple(min(255,v+18) for v in col[:3])+(255,)
        # Raised lock, drawn with a slight offset shadow.
        for dx,dy,shadow_pass in ((.007,.012,True),(0,0,False)):
            px,py=x-dx,y-dy
            arc=((px-.5)**2+(py-.415)**2)
            shackle=(py<=.45 and .095**2 <= arc <= .143**2)
            shackle=shackle or (.357<=px<=.405 and .405<=py<=.49) or (.595<=px<=.643 and .405<=py<=.49)
            body=rounded(px,py,.315,.455,.685,.715,.037)
            if shackle or body:
                if shadow_pass:col=(8,74,92,255)
                else:
                    t=max(0,min(1,(py-.28)/.45))
                    col=tuple(round(a+(b-a)*t) for a,b in zip((255,255,255),(212,237,240)))+(255,)
            if not shadow_pass and (((px-.5)**2+(py-.555)**2<.031**2) or (.484<px<.516 and .555<py<.632)):
                col=(14,103,126,255)
        return col
    rows=[]
    for iy in range(size):
        row=bytearray([0])
        for ix in range(size):
            samples=[pixel((ix+(sx+.5)/scale)/size,(iy+(sy+.5)/scale)/size) for sy in range(scale) for sx in range(scale)]
            alpha=sum(p[3] for p in samples)
            row.extend([round(sum(p[c]*p[3] for p in samples)/alpha) if alpha else 0 for c in range(3)]+[round(alpha/(scale*scale))])
        rows.append(row)
    def chunk(name,data):
        return struct.pack('!I',len(data))+name+data+struct.pack('!I',zlib.crc32(name+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',size,size,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows)))+chunk(b'IEND',b'')


if __name__ == '__main__':
    from pathlib import Path
    out=Path(__file__).resolve().parents[1]/'packaging/ui/images'
    out.mkdir(parents=True,exist_ok=True)
    for size in (16,24,32,48,64,72,128,256):
        (out/f'icon_{size}.png').write_bytes(png(size))
    print(out)

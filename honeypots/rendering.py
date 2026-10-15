"""Trusted HTML rendering of validated page components. Operator text is always escaped.

A site has one of three fixed layouts. "plain" is a single card; "store" and "portal" add a
header with the site name and a menu, and a footer. Product pictures are small drawings made
here from a fixed set of shapes and colours, so a page never loads anything from elsewhere.
"""
import html
from datetime import datetime, timezone

STYLESHEET = """
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#eef1f5;color:#1d2733}
main{max-width:720px;margin:48px auto;padding:32px;background:#fff;border:1px solid #d5dbe3;border-radius:8px}
h1{font-size:24px;margin:0 0 16px}h2{font-size:19px}h3{font-size:16px}p{line-height:1.6}
form{display:grid;gap:12px;margin:20px 0}label{display:grid;gap:6px;font-size:14px}
input{padding:9px 11px;border:1px solid #b6c0cc;border-radius:5px;font:inherit}
button,.button{display:inline-block;padding:10px 16px;border:0;border-radius:5px;background:#2f5d9b;color:#fff;font:inherit;cursor:pointer;justify-self:start;text-decoration:none}
nav{display:flex;gap:16px;flex-wrap:wrap;margin:18px 0}a{color:#2f5d9b}
section{border:1px solid #d5dbe3;border-radius:6px;padding:16px;margin:18px 0;background:#f7f9fb}
section h2{margin:0 0 10px}dl{display:grid;grid-template-columns:1fr auto;gap:8px 16px;margin:0}dd{margin:0;font-weight:600}
.ok{color:#1c7a4a}.warning{color:#9a6a00}.error{color:#b3261e}
.hero{padding:28px;margin:0 0 24px;border-radius:8px;background:#f1f4f8}.hero h1{font-size:30px;margin:0 0 10px}.hero p{margin:0 0 18px;max-width:60ch}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:20px;margin:16px 0 28px}
.product{display:block;color:inherit;text-decoration:none}.product svg{display:block;width:100%;height:auto;border-radius:6px}
.product strong{display:block;margin:10px 0 2px;font-weight:500}.product span{font-weight:700}
.product em{display:inline-block;margin-left:8px;padding:1px 7px;border-radius:10px;background:#1d2733;color:#fff;font-size:12px;font-style:normal}
.card{padding:18px;border:1px solid #d5dbe3;border-radius:8px;background:#fff}.card h3{margin:0 0 8px}.card p{margin:0;font-size:14px;color:#4a5563}
.top{display:flex;flex-wrap:wrap;align-items:center;gap:8px 32px;padding:14px 32px}.top nav{margin:0}
.brand{font-weight:700;font-size:20px;text-decoration:none;color:inherit}
footer{padding:24px 32px;font-size:13px;color:#6b7480}footer p{margin:0 0 6px;line-height:1.5}

body.store{background:#fff;color:#151515}
body.store .top{position:sticky;top:0;background:#fff;border-bottom:1px solid #e6e6e3;z-index:1}
body.store .brand{letter-spacing:.18em;text-transform:uppercase}
body.store .top a{color:#151515;text-decoration:none;font-size:14px}body.store .top nav a:hover{text-decoration:underline}
body.store main{max-width:1120px;margin:0 auto;padding:28px 32px 48px;border:0;border-radius:0;background:none}
body.store h1{font-size:28px;font-weight:600}body.store h2{font-size:20px;font-weight:600;margin:28px 0 4px}
body.store .hero{padding:56px 40px;background:#f3efe9;border-radius:0}body.store .hero h1{font-size:40px}
body.store button,body.store .button{background:#151515;border-radius:0;padding:12px 24px;letter-spacing:.04em}
body.store a{color:#151515}body.store .button{color:#fff}body.store form{max-width:400px}body.store input{border-radius:0;border-color:#c9c9c4}
body.store section{border:0;border-top:1px solid #e6e6e3;border-radius:0;background:none;padding:18px 0;margin:0}
body.store .card{border-radius:0;border-color:#e6e6e3}body.store .grid{gap:28px 20px}
body.store footer{border-top:1px solid #e6e6e3;background:#fafaf8}

body.portal{background:#f3f6f9}
body.portal .top{background:#12324f;color:#fff}body.portal .top a{color:#fff;text-decoration:none;font-size:14px;opacity:.9}
body.portal .top nav a:hover{opacity:1;text-decoration:underline}
body.portal main{max-width:980px;margin:28px auto;padding:0 24px;border:0;background:none}
body.portal .hero{background:#fff;border:1px solid #d9e0e8;border-left:4px solid #1f6fb2}
body.portal button,body.portal .button{background:#1f6fb2}body.portal a{color:#1f6fb2}body.portal main .button{color:#fff}
body.portal form{max-width:380px;padding:22px;background:#fff;border:1px solid #d9e0e8;border-radius:8px}
body.portal section{background:#fff;border-color:#d9e0e8}body.portal footer{text-align:center}
@media(max-width:640px){.top,footer{padding-left:16px;padding-right:16px}body.store main{padding:20px 16px 36px}body.store .hero{padding:32px 20px}body.store .hero h1{font-size:30px}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}}
""".strip()

LAYOUTS = ("plain", "store", "portal")
PALETTE = {"black": "#1f1f22", "white": "#fbfbf9", "grey": "#9a9da3", "beige": "#d9c7a8", "navy": "#243a5e", "blue": "#3f74b8",
           "green": "#3f7d5a", "olive": "#7b7f4a", "red": "#b53a3a", "pink": "#e3a6b4", "brown": "#7a5236"}
SHAPES = {
    "tshirt": "M42 22 22 34l8 18 10-6v52h40V46l10 6 8-18-20-12q-18 12-36 0z",
    "hoodie": "M48 22q12-10 24 0l24 18 8 52-12 2-8-38v48H36V56l-8 38-12-2 8-52zM48 76h24v14H48z",
    "jeans": "M38 16h44l6 88H66l-6-58-6 58H32z",
    "dress": "M48 16l-6 18 8 12-20 58h60L70 46l8-12-6-18q-12 12-24 0z",
    "jacket": "M46 18 24 38l-8 54 12 2 8-38v50h22V40zM74 18l22 20 8 54-12 2-8-38v50H62V40z",
    "sneakers": "M16 100V72q2-12 16-10l8 8h14q14 14 38 16q12 2 12 12v2zM16 92h88v2H16z",
    "cap": "M24 74q2-34 36-34t36 34l16 6q-28 6-88-2z",
    "bag": "M30 46h60l6 58H24zM46 46V36q14-16 28 0v10h-6V38q-8-8-16 0v8z",
}


def substitute(text: str, values: dict) -> str:
    """Replace the fixed placeholders, then escape; no expression is ever evaluated."""
    for token, value in values.items():
        text = text.replace(token, value)
    return html.escape(text)


def field_attributes(item) -> str:
    return " ".join([f"name='{html.escape(item.name)}'", f"type='{item.kind}'", "maxlength='80'", "required"])


def drawing(kind: str, color: str, name: str) -> str:
    """Product picture: a known outline in a known colour. Nothing here comes from operator text except the label."""
    fill = PALETTE.get(color, PALETTE["black"])
    return (f"<svg viewBox='0 0 120 120' role='img' aria-label='{name}'><rect width='120' height='120' fill='#f1f1ee'/>"
            f"<path d='{SHAPES.get(kind, SHAPES['tshirt'])}' fill='{fill}' fill-rule='evenodd' stroke='#000' stroke-opacity='.18'/></svg>")


def links_html(component, values) -> str:
    return "".join(f"<a href='{html.escape(item.href)}'>{substitute(item.label, values)}</a>" for item in component.items)


def component_html(component, values) -> str:
    kind = component.type
    if kind == "heading":
        return f"<h{component.level}>{substitute(component.text, values)}</h{component.level}>"
    if kind == "paragraph":
        return f"<p>{substitute(component.text, values)}</p>"
    if kind == "form":
        inputs = "".join(
            f"<label>{substitute(item.label, values)} <input {field_attributes(item)}></label>" for item in component.fields)
        target = f"action='{html.escape(component.action)}'"
        return (f"<form {target} method='post'>{inputs}"
                f"<button>{substitute(component.submit_label, values)}</button></form>")
    if kind == "links":
        return f"<nav>{links_html(component, values)}</nav>"
    if kind == "info_panel":
        return f"<section><h2>{substitute(component.title, values)}</h2><p>{substitute(component.text, values)}</p></section>"
    if kind == "hero":
        text = f"<p>{substitute(component.text, values)}</p>" if component.text else ""
        action = (f"<a class='button' href='{html.escape(component.button_href)}'>{substitute(component.button_label, values)}</a>"
                  if component.button_label else "")
        return f"<div class='hero'><h1>{substitute(component.title, values)}</h1>{text}{action}</div>"
    if kind == "products":
        title = f"<h2>{substitute(component.title, values)}</h2>" if component.title else ""
        items = "".join(
            f"<a class='product' href='{html.escape(item.href)}'>{drawing(item.kind, item.color, substitute(item.name, values))}"
            f"<strong>{substitute(item.name, values)}</strong><span>{substitute(item.price, values)}</span>"
            + (f"<em>{substitute(item.note, values)}</em>" if item.note else "") + "</a>" for item in component.items)
        return f"{title}<div class='grid'>{items}</div>"
    if kind == "cards":
        title = f"<h2>{substitute(component.title, values)}</h2>" if component.title else ""
        items = "".join(f"<div class='card'><h3>{substitute(item.title, values)}</h3><p>{substitute(item.text, values)}</p></div>"
                        for item in component.items)
        return f"{title}<div class='grid'>{items}</div>"
    rows = "".join(f"<dt>{substitute(item.label, values)}</dt><dd class='{item.state}'>{substitute(item.value, values)}</dd>"
                   for item in component.items)
    return f"<section><h2>{substitute(component.title, values)}</h2><dl>{rows}</dl></section>"


def render_page(page, values, layout: str = "plain", footer: str = "") -> bytes:
    components = list(page.components)
    layout = layout if layout in LAYOUTS else "plain"
    header = closing = ""
    if layout != "plain":
        menu = links_html(components.pop(0), values) if components and components[0].type == "links" else ""
        header = (f"<header class='top'><a class='brand' href='/'>{html.escape(values.get('{title}', ''))}</a>"
                  f"<nav>{menu}</nav></header>")
        note = f"<p>{substitute(footer, values)}</p>" if footer else ""
        closing = f"<footer>{note}<p>© {datetime.now(timezone.utc).year} {html.escape(values.get('{title}', ''))}</p></footer>"
    body = "".join(component_html(component, values) for component in components)
    return (f"<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width'><title>{substitute(page.title, values)}</title>"
            f"<link rel='stylesheet' href='/static/site.css'></head><body class='{layout}'>{header}<main>{body}</main>{closing}</body></html>").encode()

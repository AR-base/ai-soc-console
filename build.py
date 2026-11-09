"""Builds index.html: one self-contained page from src/ (no runtime dependencies besides Google Fonts)."""
import pathlib
root = pathlib.Path(__file__).parent
core = (root / 'src/core.js').read_text()
data = (root / 'src/data.js').read_text()
app = (root / 'src/app.html').read_text()
for name, js in (('core.js', core), ('data.js', data)):
    if '</script' in js.lower():
        raise SystemExit(name + ' must not contain </script')
body = app.replace('/*@CORE*/', core).replace('/*@DATA*/', data)
head = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        '<meta name="description" content="AI-powered SOC console: Wazuh alert detection handoff, redacted AI analysis verified against the log, and a command center with KPIs.">\n'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src https://api.anthropic.com; base-uri 'none'; form-action 'none'\">\n"
        '<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}'
        'body{margin:0;font:14px system-ui,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>\n</head>\n<body>\n')
(root / 'index.html').write_text(head + body + '\n</body>\n</html>\n')
print('index.html', len(head + body), 'bytes')

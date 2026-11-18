# bundle.py
import os

with open('index.html', 'r', encoding='utf-8') as f:
    html = f.read()

with open('css/style.css', 'r', encoding='utf-8') as f:
    css = f.read()

data_js = ""
if os.path.exists('js/dynamic-tools.js'):
    with open('js/dynamic-tools.js', 'r', encoding='utf-8') as f:
        data_js = f.read()
elif os.path.exists('js/tools-data.js'):
    with open('js/tools-data.js', 'r', encoding='utf-8') as f:
        data_js = f.read()

with open('js/app.js', 'r', encoding='utf-8') as f:
    app_js = f.read()

# Replace css link with inline style
html = html.replace('<link rel="stylesheet" href="css/style.css">', f'<style>\n{css}\n</style>')

# Replace script tags with inline scripts
html = html.replace('<script src="js/dynamic-tools.js"></script>', f'<script>\n{data_js}\n</script>')
html = html.replace('<script src="js/tools-data.js"></script>', f'<script>\n{data_js}\n</script>')
html = html.replace('<script src="js/app.js"></script>', f'<script>\n{app_js}\n</script>')

artifact_dir = r'C:\Users\MSI Laptop\.gemini\antigravity\brain\a41126e8-36ad-4517-9153-bc56a0fcd038'
os.makedirs(artifact_dir, exist_ok=True)
artifact_path = os.path.join(artifact_dir, 'dashboard.html')

with open(artifact_path, 'w', encoding='utf-8') as f:
    f.write(html)

print(f'Generated standalone artifact at: {artifact_path} (size: {os.path.getsize(artifact_path):,} bytes)')

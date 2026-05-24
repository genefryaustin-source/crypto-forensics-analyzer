import re
from pathlib import Path

files = list(Path(".").glob("*.py"))
total = 0

for f in files:
    lines = f.read_text(encoding="utf-8").split("\n")
    original = list(lines)
    fixed = []
    for line in lines:
        if "st.button(" in line and "width=" in line:
            line = line.replace(", use_container_width=True", ", use_container_width=True")
            line = line.replace(",width='stretch'", ", use_container_width=True")
            line = line.replace(", width='content'", "")
            line = line.replace(",width='content'", "")
        fixed.append(line)
    if fixed != original:
        f.write_text("\n".join(fixed), encoding="utf-8")
        print("Fixed: " + f.name)
        total += 1

print("Done - " + str(total) + " files fixed")

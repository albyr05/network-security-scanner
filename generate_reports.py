import json
import html

def generate_report_json(results, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, sort_keys=True, indent=4)
    return

def generate_report_html(results, filename="report.html"):
    html_content = """
    <html>
    <head>
        <title>Network Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
            h1 { color: #333; }
            .host { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .port { margin: 5px 0; color: #444; }
            .open { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Network Scan Report</h1>
    """

    for host in results:
        html_content += f"<div class='host'><h2>Host: {host['ip']}</h2>"
        if host['ports']:
            for p in host['ports']:
                filtered_banner = html.escape(p['banner'])
                html_content += f"<p class='port'><span class='open'>[+] Port {p['port']}</span> — Banner: {filtered_banner}</p>"
        else:
            html_content += "<p>No open ports found</p>"
        html_content += "</div>"

    html_content += "</body></html>"

    with open(filename, "w") as f:
        f.write(html_content)

    print(f"\n[+] Report saved as {filename}")
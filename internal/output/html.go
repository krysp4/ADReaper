package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HTMLReportData holds all findings for the report.
type HTMLReportData struct {
	Domain      string
	DCIP        string
	Timestamp   string
	Artifacts   map[string]string // Filename -> JSON Content
	Loot        []string
	UsersCount  int
	GroupsCount int
	AdcsCount   int
}

// GenerateHTMLReport creates a professional HTML dashboard in the workspace.
func GenerateHTMLReport(outDir string, data HTMLReportData) (string, error) {
	reportPath := filepath.Join(outDir, "intelligence_report_"+time.Now().Format("20060102_150405")+".html")

	// Prepare Artifacts JSON for JS injection
	artifactsJS, _ := json.Marshal(data.Artifacts)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADReaper Mission Intelligence - %[1]s</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #020617;
            --surface: #0f172a;
            --surface-secondary: #1e293b;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --success: #10b981;
            --border: rgba(255, 255, 255, 0.08);
            --glass: rgba(15, 23, 42, 0.8);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 0%% 0%%, rgba(56, 189, 248, 0.03) 0%%, transparent 50%%),
                radial-gradient(circle at 100%% 100%%, rgba(129, 140, 248, 0.03) 0%%, transparent 50%%);
        }

        .navbar {
            height: 70px;
            padding: 0 4rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .logo { font-size: 1.4rem; font-weight: 800; letter-spacing: -0.05em; display: flex; align-items: center; gap: 0.5rem; }
        .logo span { background: linear-gradient(to right, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

        .container { max-width: 1600px; margin: 0 auto; padding: 2rem 4rem; }

        .hero { margin-bottom: 3rem; animation: slideIn 0.8s cubic-bezier(0.16, 1, 0.3, 1); }
        @keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 3rem; }
        .stat-card {
            background: var(--surface);
            padding: 2rem;
            border-radius: 1.5rem;
            border: 1px solid var(--border);
            text-align: left;
            position: relative;
        }
        .stat-card .label { color: var(--text-secondary); font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
        .stat-card .value { font-size: 2.5rem; font-weight: 800; color: white; margin: 0.25rem 0; }

        .section-title { font-size: 1.5rem; font-weight: 700; margin: 2rem 0; display: flex; align-items: center; gap: 1rem; }
        .section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }

        /* Intelligence Tabs */
        .workspace-viewer {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 1rem;
            height: 800px;
            background: var(--surface);
            border-radius: 24px;
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .sidebar {
            background: rgba(255,255,255,0.02);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }

        .sidebar-header { padding: 1.5rem; font-weight: 800; font-size: 0.8rem; text-transform: uppercase; color: var(--text-secondary); border-bottom: 1px solid var(--border); }
        
        .tab-list { overflow-y: auto; flex: 1; }
        .tab-item {
            padding: 1.25rem 1.5rem;
            cursor: pointer;
            transition: 0.2s;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.9rem;
        }
        .tab-item:hover { background: rgba(56, 189, 248, 0.05); }
        .tab-item.active { background: var(--accent-glow); color: var(--accent); border-left: 3px solid var(--accent); }
        .tab-item .file-ext { font-size: 0.6rem; background: rgba(255,255,255,0.1); padding: 0.2rem 0.4rem; border-radius: 4px; }

        .viewer-content {
            padding: 2rem;
            overflow-y: auto;
            background: #0b0f19;
            font-family: 'JetBrains Mono', monospace;
        }

        /* JSON Rendering Styles */
        .json-tree { margin-left: 1.5rem; line-height: 1.6; }
        .json-key { color: #818cf8; }
        .json-string { color: #10b981; }
        .json-number { color: #f59e0b; }
        .json-bool { color: #3b82f6; }
        .json-toggle { cursor: pointer; color: var(--text-secondary); margin-left: -1rem; position: absolute; transition: 0.2s; }
        .json-toggle:hover { color: white; }

        footer { margin-top: 4rem; padding: 3rem; text-align: center; border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.8rem; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="logo">⚔️ AD<span>REAPER</span></div>
        <div style="font-size: 0.8rem; color: var(--text-secondary);">Session: <b style="color: white;">%[2]s</b></div>
    </nav>

    <div class="container">
        <div class="hero">
            <h1 style="font-size: 3rem; font-weight: 800; letter-spacing: -0.04em;">Intelligence Dashboard</h1>
            <p style="color: var(--text-secondary);">Domain Assessment: <b style="color: white;">%[3]s</b> | Active Controller: <span style="color: var(--success);">%[4]s</span></p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">LDAP Objects</div>
                <div class="value">%[5]d</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Artifacts</div>
                <div class="value">%[6]d</div>
            </div>
            <div class="stat-card">
                <div class="label">ADCS Entities</div>
                <div class="value">%[7]d</div>
            </div>
            <div class="stat-card">
                <div class="label">Loot Harvested</div>
                <div class="value">%[8]d</div>
            </div>
        </div>

        <div class="section-title">Workspace Intelligence Explorer</div>

        <div class="workspace-viewer">
            <div class="sidebar">
                <div class="sidebar-header">Artifact Files</div>
                <div class="tab-list" id="tab-list">
                    <!-- Tabs will be injected here -->
                </div>
            </div>
            <div class="viewer-content" id="viewer-content">
                <div style="height: 100%%; display: flex; flex-direction: column; justify-content: center; align-items: center; color: var(--text-secondary);">
                    <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
                    <div>Select an artifact from the sidebar to begin analysis</div>
                </div>
            </div>
        </div>

        <footer>
            ADReaper Toolkit v2.9 | Professional Red Team Assessment Report | %[2]s
        </footer>
    </div>

    <script>
        const artifacts = %[9]s;
        const tabList = document.getElementById('tab-list');
        const viewerContent = document.getElementById('viewer-content');

        function init() {
            Object.keys(artifacts).sort().forEach(filename => {
                const tab = document.createElement('div');
                tab.className = 'tab-item';
                tab.innerHTML = '<span class="file-ext">JSON</span> ' + filename;
                tab.onclick = () => loadFile(filename, tab);
                tabList.appendChild(tab);
            });
        }

        function loadFile(filename, tabElement) {
            document.querySelectorAll('.tab-item').forEach(t => t.classList.remove('active'));
            tabElement.classList.add('active');

            viewerContent.innerHTML = '';
            try {
                const data = JSON.parse(artifacts[filename]);
                const title = document.createElement('h2');
                title.style.fontFamily = 'Outfit';
                title.style.marginBottom = '1.5rem';
                title.style.color = 'var(--accent)';
                title.textContent = filename;
                viewerContent.appendChild(title);

                const tree = document.createElement('div');
                renderJSON(data, tree);
                viewerContent.appendChild(tree);
            } catch (e) {
                viewerContent.innerHTML = '<div style="color: #ef4444;">Error parsing artifact: ' + e.message + '</div>';
            }
        }

        function renderJSON(val, container, key) {
            const node = document.createElement('div');
            node.className = 'json-tree';
            node.style.position = 'relative';
            
            if (key) {
                const kSpan = document.createElement('span');
                kSpan.className = 'json-key';
                kSpan.textContent = '"' + key + '": ';
                node.appendChild(kSpan);
            }

            if (val === null) {
                node.innerHTML += '<span class="json-bool">null</span>';
            } else if (typeof val === 'object') {
                const isArr = Array.isArray(val);
                const toggle = document.createElement('span');
                toggle.className = 'json-toggle';
                toggle.textContent = '▼';
                node.insertBefore(toggle, node.firstChild);

                node.innerHTML += isArr ? '[' : '{';
                const body = document.createElement('div');
                body.style.marginLeft = '1rem';
                
                for (let k in val) {
                    renderJSON(val[k], body, k);
                }
                
                node.appendChild(body);
                node.innerHTML += isArr ? ']' : '}';

                toggle.onclick = (e) => {
                    e.stopPropagation();
                    const collapsed = body.style.display === 'none';
                    body.style.display = collapsed ? 'block' : 'none';
                    toggle.textContent = collapsed ? '▼' : '▶';
                    toggle.style.transform = collapsed ? '' : 'rotate(-90deg)';
                };
            } else if (typeof val === 'string') {
                node.innerHTML += '<span class="json-string">"' + val.replace(/"/g, '\\"') + '"</span>';
            } else if (typeof val === 'number') {
                node.innerHTML += '<span class="json-number">' + val + '</span>';
            } else if (typeof val === 'boolean') {
                node.innerHTML += '<span class="json-bool">' + val + '</span>';
            }
            
            container.appendChild(node);
        }

        init();
    </script>
</body>
</html>`,
		data.Domain, data.Timestamp, data.Domain, data.DCIP,
		data.UsersCount+data.GroupsCount, len(data.Artifacts), data.AdcsCount, len(data.Loot),
		string(artifactsJS))

	err := os.MkdirAll(outDir, 0755)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(reportPath, []byte(html), 0644)
	if err != nil {
		return "", err
	}

	return reportPath, nil
}

// DiscoverArtifacts scans the workspace for all JSON files and reads them.
func DiscoverArtifacts(wsDir string) (map[string]string, error) {
	artifacts := make(map[string]string)
	entries, err := os.ReadDir(wsDir)
	if err != nil {
		return artifacts, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			content, err := os.ReadFile(filepath.Join(wsDir, entry.Name()))
			if err == nil {
				artifacts[entry.Name()] = string(content)
			}
		}
	}
	return artifacts, nil
}

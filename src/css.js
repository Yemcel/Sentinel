export const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--text:#16181d;--muted:#5f6673;--line:#e3e6eb;--accent:#2c5cc5;
--good:#1f8a4c;--good-bg:#e4f4ea;--warn:#a86400;--warn-bg:#fdf1dc;--bad:#c4302b;--bad-bg:#fbe6e5;--info:#4b5563;--info-bg:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--text:#e7e9ee;--muted:#9aa1ad;--line:#2a2f38;--accent:#7aa2ff;
--good:#4cc77f;--good-bg:#173323;--warn:#f0b354;--warn-bg:#3a2c12;--bad:#ff6b63;--bad-bg:#3d1a19;--info:#b6bcc6;--info-bg:#232831}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
main.narrow{max-width:380px;padding-top:12vh}
h1,h2{margin:0;font-weight:650}
h2{font-size:17px}
.brand{font-size:22px;letter-spacing:.02em}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;max-width:1200px;margin:0 auto;padding:16px 16px 0}
.top-right{display:flex;align-items:center;gap:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px;overflow-x:auto}
.grid .card{margin-bottom:0;font-size:14px}
.grid .tbl td,.grid .tbl th{padding-left:4px;padding-right:4px}
.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:10px}
.muted{color:var(--muted)} .small{font-size:13px} .mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.nowrap{white-space:nowrap} .num{text-align:right;white-space:nowrap} .err{color:var(--bad)}
.tbl{width:100%;border-collapse:collapse;margin:6px 0 10px}
.tbl th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600;text-align:left;border-bottom:1px solid var(--line);padding:6px 8px}
.tbl td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}
.tbl.compact td{padding:4px 8px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:var(--muted)}
.dot-up{background:var(--good)} .dot-down{background:var(--bad)}
.status-up{color:var(--good)} .status-down{color:var(--bad);font-weight:650}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600}
.pill-good{background:var(--good-bg);color:var(--good)} .pill-warn{background:var(--warn-bg);color:var(--warn)} .pill-bad{background:var(--bad-bg);color:var(--bad)}
.sev{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:600}
.sev-high{background:var(--bad-bg);color:var(--bad)} .sev-medium{background:var(--warn-bg);color:var(--warn)}
.sev-low,.sev-info{background:var(--info-bg);color:var(--info)}
.grade{padding:0 6px;border-radius:4px}
.grade-A,.grade-B{background:var(--good-bg);color:var(--good)} .grade-C,.grade-D{background:var(--warn-bg);color:var(--warn)} .grade-E,.grade-F{background:var(--bad-bg);color:var(--bad)}
details{margin:6px 0} summary{cursor:pointer} pre{white-space:pre-wrap;margin:6px 0;font-size:13px}
.notice{background:var(--info-bg);border-radius:8px;padding:10px 12px}
.stack{display:flex;flex-direction:column;gap:10px;margin:20px 0}
input{font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--text)}
button{font:inherit;font-weight:600;padding:9px 14px;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--line);padding:5px 10px;font-size:13px}
button.link{background:none;color:var(--accent);padding:0}
button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
form.inline{display:inline;margin:0}
footer{text-align:center;padding:12px 16px 28px}
@media (max-width:600px){.grid{grid-template-columns:1fr}}
`;

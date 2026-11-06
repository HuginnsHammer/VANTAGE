(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const sampleAssets = [
    {id:"AST-001",name:"storefront.example.test",type:"Website",kind:"◉",environment:"Production",owner:"Web team",findings:2},
    {id:"AST-002",name:"payments-api.example.test",type:"API",kind:"⌘",environment:"Production",owner:"Platform team",findings:2},
    {id:"AST-003",name:"terraform/live",type:"IaC workspace",kind:"◇",environment:"Cloud",owner:"Infrastructure",findings:1},
    {id:"AST-004",name:"container-images",type:"Container registry",kind:"▦",environment:"Build",owner:"Engineering",findings:1}
  ];
  const sampleFindings = [
    {id:"VAN-1001",title:"Object storage allows public access",rule:"CS-TF-001",severity:"critical",status:"open",asset:"terraform/live",assetId:"AST-003",category:"Cloud configuration",confidence:"High",evidence:"A storage bucket access-control configuration permits public access. Review the resource policy and intended data classification.",remediation:"Remove public access unless it is explicitly required. Apply least-privilege bucket policies, enable public-access blocking and verify access from an unauthenticated context.",firstSeen:"2026-10-28"},
    {id:"VAN-1002",title:"Container runs in privileged mode",rule:"CS-CMP-001",severity:"high",status:"open",asset:"payments-api.example.test",assetId:"AST-002",category:"Container security",confidence:"High",evidence:"The Compose service declares privileged mode. This can grant the container extensive host capabilities.",remediation:"Remove privileged mode. Add only the specific Linux capabilities required by the workload and consider read-only filesystems.",firstSeen:"2026-10-29"},
    {id:"VAN-1003",title:"Wildcard host port binding",rule:"CS-CMP-004",severity:"high",status:"open",asset:"payments-api.example.test",assetId:"AST-002",category:"Network exposure",confidence:"High",evidence:"A service port is bound to all host interfaces rather than a restricted interface.",remediation:"Bind only to the required interface, restrict access with network controls and document the intended exposure.",firstSeen:"2026-10-30"},
    {id:"VAN-1004",title:"TLS certificate expires soon",rule:"VAN-TLS-004",severity:"medium",status:"open",asset:"storefront.example.test",assetId:"AST-001",category:"Transport security",confidence:"Medium",evidence:"Sample certificate metadata indicates a short remaining validity period. This is illustrative data, not a live certificate check.",remediation:"Confirm the certificate lifecycle and renewal automation. Verify the complete certificate chain after renewal.",firstSeen:"2026-10-31"},
    {id:"VAN-1005",title:"Base image uses a mutable tag",rule:"CS-DKR-002",severity:"medium",status:"open",asset:"container-images",assetId:"AST-004",category:"Build security",confidence:"High",evidence:"A Dockerfile references a mutable image tag. The referenced image may change without a source change.",remediation:"Pin the base image to an immutable digest and establish a controlled update process.",firstSeen:"2026-11-01"},
    {id:"VAN-1006",title:"Missing explicit container user",rule:"CS-DKR-003",severity:"low",status:"open",asset:"container-images",assetId:"AST-004",category:"Container security",confidence:"High",evidence:"No explicit USER instruction was observed in the sample Dockerfile.",remediation:"Create a dedicated unprivileged user and explicitly select it in the image.",firstSeen:"2026-11-02"}
  ];
  let findings = structuredClone(sampleFindings);
  let assets = structuredClone(sampleAssets);
  let selectedView = "overview";
  let selectedFinding = null;
  const severityOrder = ["critical","high","medium","low"];
  const titleCase = value => value.charAt(0).toUpperCase()+value.slice(1);
  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const count = severity => findings.filter(item => item.severity === severity && item.status === "open").length;
  const priority = () => Math.min(100, findings.filter(x=>x.status==="open").reduce((sum,x)=>sum+({critical:30,high:18,medium:9,low:4}[x.severity]||0),0));
  const visible = () => {
    const query = ($("#finding-search")?.value || "").trim().toLowerCase();
    const severity = $("#severity-filter")?.value || "all";
    const status = $("#status-filter")?.value || "all";
    return findings.filter(item => (severity==="all"||item.severity===severity) && (status==="all"||item.status===status) && (!query||[item.id,item.title,item.rule,item.asset,item.category].join(" ").toLowerCase().includes(query)));
  };
  function setView(view) {
    selectedView=view;
    ["overview","findings","assets"].forEach(name => { const el=$("#"+name+"-view"); if(el) el.hidden=name!==view; });
    $$(".side-link").forEach(button=>button.classList.toggle("active",button.dataset.view===view));
    $("#console-title").textContent=({overview:"Exposure overview",findings:"Security findings",assets:"Asset inventory"})[view];
    $("#console-subtitle").textContent=({overview:"A snapshot of your sample security posture.",findings:"Search and inspect evidence from the sample assessment.",assets:"Assets represented in this sample workspace."})[view];
    render();
  }
  function findingRow(item,compact=false) {
    return `<div class="finding-line"><span class="severity-dot ${escapeHtml(item.severity)}"></span><span class="finding-title">${escapeHtml(item.title)}<small>${escapeHtml(item.rule)} · ${escapeHtml(item.asset)}</small></span><span class="finding-severity">${escapeHtml(item.severity.toUpperCase())}</span><span class="finding-status">${escapeHtml(item.status.toUpperCase())}</span></div>`;
  }
  function renderOverview() {
    const open=findings.filter(x=>x.status==="open").length;
    $("#stat-open").textContent=String(open).padStart(2,"0");
    $("#stat-priority").textContent=String(findings.filter(x=>x.status==="open"&&["critical","high"].includes(x.severity)).length).padStart(2,"0");
    $("#stat-assets").textContent=String(assets.length).padStart(2,"0");
    $("#stat-score").innerHTML=priority()+"<span>/100</span>";
    $("#side-finding-count").textContent=open;
    $("#severity-bars").innerHTML=severityOrder.map(severity=>{const value=count(severity);const width=open?Math.round(value/open*100):0;return `<div class="severity-row"><span>${titleCase(severity)}</span><div class="severity-track"><div class="severity-fill ${severity}" style="width:${width}%"></div></div><span class="severity-count">${value}</span></div>`;}).join("");
    $("#asset-summary").innerHTML=assets.slice(0,4).map(asset=>`<div class="asset-summary-row"><span class="asset-type">${escapeHtml(asset.kind)}</span><span><b>${escapeHtml(asset.name)}</b><small>${escapeHtml(asset.type)} · ${escapeHtml(asset.environment)}</small></span><span class="asset-risk">${findings.filter(f=>f.assetId===asset.id&&f.status==="open").length} OPEN</span></div>`).join("");
    $("#overview-findings").innerHTML=findings.filter(x=>x.status==="open").slice(0,4).map(x=>findingRow(x,true)).join("") || '<div class="empty-state">No open findings in this workspace.</div>';
  }
  function renderFindings() {
    const rows=visible();
    $("#findings-table").innerHTML=rows.length?`<div class="table-wrap"><table class="findings-table"><thead><tr><th>FINDING</th><th>SEVERITY</th><th>ASSET</th><th>STATUS</th></tr></thead><tbody>${rows.map(item=>`<tr data-finding="${escapeHtml(item.id)}"><td><button class="table-finding-button" type="button" data-finding-detail="${escapeHtml(item.id)}"><span class="table-finding">${escapeHtml(item.title)}</span><small>${escapeHtml(item.rule)} · ${escapeHtml(item.id)}</small></button></td><td><span class="severity-label" style="color:${({critical:"#f07878",high:"#e7a65e",medium:"#d8c66d",low:"#83b7e7"})[item.severity]}">${escapeHtml(item.severity)}</span></td><td>${escapeHtml(item.asset)}</td><td><span class="status-label">${escapeHtml(item.status)}</span></td></tr>`).join("")}</tbody></table></div>`:'<div class="empty-state">No findings match those filters. Try changing your search.</div>';
  }
  function renderAssets() {
    $("#assets-grid").innerHTML=assets.map(asset=>{const related=findings.filter(f=>f.assetId===asset.id);return `<article class="asset-card"><div class="asset-card-top"><span class="asset-card-icon">${escapeHtml(asset.kind)}</span><span class="sample-label">${escapeHtml(asset.environment.toUpperCase())}</span></div><h4>${escapeHtml(asset.name)}</h4><p>${escapeHtml(asset.type)} · Owner: ${escapeHtml(asset.owner)}</p><div class="asset-card-foot"><span>${related.length} OBSERVATION(S)</span><span>${related.filter(x=>x.status==="open").length} OPEN</span></div></article>`;}).join("")||'<div class="empty-state">No assets in this imported report.</div>';
  }
  function render(){renderOverview();renderFindings();renderAssets();}
  function exportCsv(){
    const headers=["id","title","rule","severity","status","asset","category","confidence","evidence","remediation","firstSeen"];
    const quote=value=>'"'+String(value??"").replace(/"/g,'""')+'"';
    const csv=[headers.join(","),...findings.map(item=>headers.map(key=>quote(item[key])).join(","))].join("\r\n");
    const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
    const link=document.createElement("a");link.href=url;link.download="vantage-findings.csv";document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);
  }
  function normalizeImportedReport(report){
    if(!report||typeof report!=="object"||!Array.isArray(report.findings))throw new Error("The file must be a VANTAGE JSON report with a findings array.");
    if(report.findings.length>5000)throw new Error("This demo accepts up to 5,000 findings per import.");
    const normalized=report.findings.map((raw,index)=>{
      const severity=String(raw.severity||"").toLowerCase();
      if(!severityOrder.includes(severity))throw new Error("Finding "+(index+1)+" has an unsupported severity.");
      const asset=String(raw.asset||raw.resource||raw.asset_name||raw.file_path||"Imported asset");
      return {id:String(raw.id||raw.fingerprint||"IMPORTED-"+(index+1)),title:String(raw.title||raw.name||raw.rule_id||"Imported finding"),rule:String(raw.rule_id||raw.rule||"IMPORTED"),severity,status:"open",asset,assetId:"IMPORTED-"+asset,category:String(raw.category||"Imported"),confidence:String(raw.confidence||"Unknown"),evidence:String(raw.evidence||raw.description||"No evidence text supplied in this report."),remediation:String(raw.remediation||"Review the original scanner report for remediation guidance."),firstSeen:String(raw.first_seen_at||raw.first_seen||"")};
    });
    const assetNames=[...new Set(normalized.map(x=>x.asset))];
    return {findings:normalized,assets:assetNames.map((name,index)=>({id:"IMPORTED-"+name,name,type:"Imported asset",kind:"◇",environment:"Imported",owner:"Not specified",findings:normalized.filter(f=>f.asset===name).length}))};
  }
  async function importReport(file){
    if(!file)return;
    if(file.size>5*1024*1024){alert("Please choose a JSON report smaller than 5 MB.");return;}
    try{const parsed=JSON.parse(await file.text());const result=normalizeImportedReport(parsed);findings=result.findings;assets=result.assets;setView("findings");alert("Imported "+findings.length+" finding(s) locally. Nothing was uploaded.");}
    catch(error){alert("Could not import report: "+error.message);}
    finally{$("#report-upload").value="";}
  }
  $$(".side-link,[data-view]").forEach(button=>button.addEventListener("click",()=>setView(button.dataset.view)));
  $("#finding-search").addEventListener("input",renderFindings);
  $("#severity-filter").addEventListener("change",renderFindings);
  $("#status-filter").addEventListener("change",renderFindings);
  $("#export-report").addEventListener("click",exportCsv);
  $("#report-upload").addEventListener("change",event=>importReport(event.target.files[0]));
  $("#reset-demo").addEventListener("click",()=>{findings=structuredClone(sampleFindings);assets=structuredClone(sampleAssets);$("#finding-search").value="";$("#severity-filter").value="all";$("#status-filter").value="all";setView("overview");});
  $("#findings-table").addEventListener("click",event=>{const trigger=event.target.closest("[data-finding-detail]");if(!trigger)return;const item=findings.find(x=>x.id===trigger.dataset.findingDetail);if(!item)return;$("#dialog-title").textContent=item.title;$("#dialog-meta").textContent=item.severity.toUpperCase()+" · "+item.rule+" · "+item.asset+" · Confidence: "+item.confidence;$("#dialog-evidence").textContent=item.evidence;$("#dialog-remediation").textContent=item.remediation;$("#finding-dialog").showModal();});
  $("#menu-toggle").addEventListener("click",()=>{const nav=$("#primary-nav"),open=nav.classList.toggle("open");$("#menu-toggle").setAttribute("aria-expanded",String(open));$("#menu-toggle").setAttribute("aria-label",open?"Close navigation":"Open navigation");});
  $$("#primary-nav a").forEach(link=>link.addEventListener("click",()=>{$("#primary-nav").classList.remove("open");$("#menu-toggle").setAttribute("aria-expanded","false");}));
  $("#year").textContent=new Date().getFullYear();
  render();
})();
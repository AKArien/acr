# pip install plotly pandas requests
import random
import pandas as pd
import plotly.graph_objects as go
import requests
import json
import os

# ---------------------------
# 1) CONFIGURATION DU RADAR
# ---------------------------
QUADRANTS = ["Menaces", "Technologies", "Réglementations", "Bonnes pratiques"]
RINGS = [
    {"name": "Court terme", "radius": 1},
    {"name": "Moyen terme", "radius": 2},
    {"name": "Long terme", "radius": 3},
]
RISK_COLORS = {
    "Élevé": "#e45756",
    "Modéré": "#f1a208",
    "Faible": "#4cc3d9",
    "Inconnu": "#b0b0b0",
}
quad_to_sector = {q: i for i, q in enumerate(QUADRANTS)}

def ring_radius(ring_name: str) -> float:
    ring = next(r for r in RINGS if r["name"] == ring_name)
    return ring["radius"]

def position_item(item, jitter_angle_deg=25, jitter_radius=0.25):
    """Positionnement avec jitter plus large pour éviter chevauchement."""
    sector = quad_to_sector[item["quadrant"]]
    sector_start = sector * 90.0
    sector_mid = sector_start + 45.0
    angle = sector_mid + random.uniform(-jitter_angle_deg, jitter_angle_deg)
    r = ring_radius(item["ring"]) + random.uniform(-jitter_radius, jitter_radius)
    return angle, r

# ---------------------------
# 2) CLASSIFICATION CWE
# ---------------------------
def classify_cwe_impact(cwes: list) -> str:
    if not cwes:
        return "Inconnu"
    critical_cwes = {"CWE-79","CWE-89","CWE-119","CWE-120","CWE-787","CWE-78","CWE-306"}
    moderate_cwes = {"CWE-22","CWE-287","CWE-352","CWE-200","CWE-611","CWE-770"}
    for cwe in cwes:
        if any(cwe.startswith(cc) for cc in critical_cwes):
            return "Élevé"
        if any(cwe.startswith(mc) for mc in moderate_cwes):
            return "Modéré"
    return "Faible"

# ---------------------------
# 3) CACHE LOCAL CVSS
# ---------------------------
CVSS_CACHE_FILE = "cvss_cache.json"
if os.path.exists(CVSS_CACHE_FILE):
    with open(CVSS_CACHE_FILE,"r") as f:
        cvss_cache = json.load(f)
else:
    cvss_cache = {}

# ---------------------------
# 4) RECUPERATION CVSS VIA NVD
# ---------------------------
def get_cvss_score(cve_id: str) -> float:
    if cve_id in cvss_cache:
        return cvss_cache[cve_id]
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            vuln_data = data.get("vulnerabilities", [])
            if vuln_data:
                metrics = vuln_data[0].get("cve", {}).get("metrics", {})
                score = None
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                if score is not None:
                    cvss_cache[cve_id] = score
                    with open(CVSS_CACHE_FILE,"w") as f:
                        json.dump(cvss_cache,f)
                    return score
    except Exception as e:
        print(f"[WARN] Impossible de récupérer CVSS pour {cve_id}: {e}")
    return None

# ---------------------------
# 5) RECUPERATION VULNERABILITES CISA KEV
# ---------------------------
ITEMS=[]
CISA_KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
try:
    resp = requests.get(CISA_KEV_URL,timeout=10)
    if resp.status_code==200:
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities",[])
        print(f"[OK] {len(vulnerabilities)} vulnérabilités récupérées")
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID","CVE-XXXX")
            cwes = vuln.get("cwes",[])
            cwe_text = f" - {', '.join(cwes[:3])}" if cwes else ""
            cwe_display = ', '.join(cwes) if cwes else "N/A"
            
            risk_level = classify_cwe_impact(cwes)
            cvss_score = get_cvss_score(cve_id)
            if cvss_score is not None:
                if cvss_score>=9.0: risk_level="Élevé"
                elif cvss_score>=6.0: risk_level="Modéré"
                elif cvss_score>0: risk_level="Faible"
            
            ring = "Court terme" if risk_level=="Élevé" else "Moyen terme" if risk_level=="Modéré" else "Long terme"
            
            ITEMS.append({
                "name": f"{cve_id}: {vuln.get('vendorProject','Unknown')}{cwe_text}",
                "quadrant":"Menaces",
                "ring":ring,
                "impact": random.randint(70,95) if risk_level=="Élevé" else random.randint(30,70),
                "risk":risk_level,
                "cvss":cvss_score if cvss_score is not None else "N/A",
                "produit":vuln.get("product","N/A"),
                "notes":vuln.get("shortDescription","")[:100],
                "vendorProject":vuln.get("vendorProject","N/A"),
                "url":f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                "cwe":cwe_display,
                "requiredAction":vuln.get("requiredAction","N/A"),
                "dueDate":vuln.get("dueDate","N/A"),
                "dateAdded":vuln.get("dateAdded","N/A")
            })
except Exception as e:
    print(f"[ERREUR] Erreur CISA KEV : {e}")

# ---------------------------
# 6) DATAFRAME + POSITION
# ---------------------------
df=pd.DataFrame(ITEMS)
angles,radii=[],[]
for _,row in df.iterrows():
    a,r=position_item(row)
    angles.append(a)
    radii.append(r)
df["angle_deg"]=angles
df["radius"]=radii
df["color"]=df["risk"].map(lambda r: RISK_COLORS.get(r,RISK_COLORS["Inconnu"]))

# ---------------------------
# 7) RADAR INTERACTIF AVEC FILTRE PAR DATE
# ---------------------------
fig=go.Figure()
all_traces=[]

unique_risks=df["risk"].unique().tolist()
unique_vendors=[v for v in df["vendorProject"].unique().tolist() if v!="N/A" and v!="" ]
unique_vendors.sort()

# Créer des groupes par date d'ajout
unique_dates = sorted(df["dateAdded"].unique().tolist())
date_groups = {
    "2024": [d for d in unique_dates if "2024" in str(d)],
    "2023": [d for d in unique_dates if "2023" in str(d)],
    "2022": [d for d in unique_dates if "2022" in str(d)],
    "Autres": [d for d in unique_dates if not any(year in str(d) for year in ["2024", "2023", "2022"])]
}

for risk in unique_risks:
    for vendor in unique_vendors:
        subset=df[(df["risk"]==risk)&(df["vendorProject"]==vendor)]
        if not subset.empty:
            trace=go.Scatterpolar(
                r=subset["radius"],
                theta=subset["angle_deg"],
                mode="markers",
                text=subset["name"],
                textposition="top center",
                marker=dict(size=subset["impact"]/8+8,color=subset["color"],
                            line=dict(width=1,color="rgba(50,50,50,0.6)")),
                hovertemplate=(
                    "<b>%{text}</b><br>"
                    "Quadrant: %{customdata[0]}<br>"
                    "Anneau: %{customdata[1]}<br>"
                    "Impact: %{customdata[2]}<br>"
                    "Risque: %{customdata[3]}<br>"
                    "CVSS: %{customdata[4]}<br>"
                    "CWE: %{customdata[5]}<br>"
                    "Produit: %{customdata[6]}<br>"
                    "Vendeur/Projet: %{customdata[7]}<br>"
                    "Action requise: %{customdata[8]}<br>"
                    "Date limite: %{customdata[9]}<br>"
                    "Date ajout: %{customdata[12]}<br>"
                    "%{customdata[10]}<br>"
                    "<a href='%{customdata[11]}'>Lien CVE</a><extra></extra>"
                ),
                customdata=subset[["quadrant","ring","impact","risk","cvss","cwe","produit","vendorProject","requiredAction","dueDate","notes","url","dateAdded"]].values,
                legendgroup=risk,
                showlegend=vendor==unique_vendors[0]
            )
            fig.add_trace(trace)
            all_traces.append((risk,vendor,subset["dateAdded"].iloc[0]))

# Boutons filtre par date d'ajout
filter_buttons=[{"label":"Toutes les dates","method":"update","args":[{"visible":[True]*len(all_traces)+[True]*4}]}]

# Filtres par année
for year, dates in date_groups.items():
    if dates:  # Seulement si il y a des dates pour cette année
        year_visibility=[]
        for _, _, trace_date in all_traces:
            year_visibility.append(trace_date in dates)
        year_visibility.extend([True]*4)
        filter_buttons.append({"label":f"Ajoutées en {year}","method":"update","args":[{"visible":year_visibility}]})

# Filtre par vendeur (garder l'ancien système aussi)
filter_buttons2= [{"label":"Tous les vendeurs","method":"update","args":[{"visible":[True]*len(all_traces)+[True]*4}]}]
for vendor in unique_vendors:
    vendor_visibility=[trace_vendor==vendor for _, trace_vendor, _ in all_traces]
    vendor_visibility.extend([True]*4)
    filter_buttons2.append({"label":vendor,"method":"update","args":[{"visible":vendor_visibility}]})

# Axes
angular_ticks=[i*90+45 for i in range(len(QUADRANTS))]
fig.update_polars(
    angularaxis=dict(direction="clockwise",rotation=90,tickmode="array",
                    tickvals=angular_ticks,ticktext=QUADRANTS,ticks="outside",
                    tickfont=dict(size=12,family="Inter, Arial")),
    radialaxis=dict(tickmode="array",
                    tickvals=[r["radius"] for r in RINGS],
                    ticktext=[r["name"] for r in RINGS],
                    range=[0,max(r["radius"] for r in RINGS)+0.6],
                    angle=90,ticks="",showline=False,gridwidth=1)
)

# Layout
fig.update_layout(
    title="Acensi Radar Cyber - Filtre par Date d'Ajout",
    showlegend=True,
    legend_title_text="Niveau de risque",
    template="plotly_white",
    updatemenus=[
        {
            "buttons":filter_buttons,
            "direction":"down",
            "pad":{"r":10,"t":10},
            "showactive":True,
            "x":0.01,
            "xanchor":"left",
            "y":1.02,
            "yanchor":"top"
        },
        {
            "buttons":filter_buttons2,
            "direction":"down",
            "pad":{"r":5,"t":10},
            "showactive":True,
            "x":0.3,
            "xanchor":"left",
            "y":1.02,
            "yanchor":"top"
        }
    ]
)

# Lignes de séparation
for i in range(4):
    fig.add_trace(go.Scatterpolar(
        r=[0,max(r["radius"] for r in RINGS)+0.4],
        theta=[i*90,i*90],
        mode="lines",
        line=dict(color="rgba(0,0,0,0.15)",width=1),
        hoverinfo="skip",
        showlegend=False,
    ))

# Export
fig.write_html("radar_cyber_200plus.html",include_plotlyjs="cdn",auto_open=True)
print("[OK] Fichier généré : radar_cyber_200plus.html")
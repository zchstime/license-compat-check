import argparse, csv, json
from pathlib import Path

ALIASES={"APACHE 2":"Apache-2.0","APACHE-2.0":"Apache-2.0","MIT":"MIT","BSD-3-CLAUSE":"BSD-3-Clause","GPL3":"GPL-3.0-only","GPL-3.0":"GPL-3.0-only"}
def normalize(value): return ALIASES.get(value.strip().upper(),value.strip())
def check(path,policy):
 rules={k:{normalize(x) for x in v} for k,v in policy.items()}; rows=[]
 for dep in csv.DictReader(Path(path).read_text().splitlines()):
  license_id=normalize(dep["license"]); status="deny" if license_id in rules.get("deny",set()) else "allow" if license_id in rules.get("allow",set()) else "review"
  rows.append({"name":dep["name"],"version":dep.get("version"),"license":license_id,"status":status})
 return rows
def markdown(rows): return "# License Compatibility Report\n\n"+"\n".join(f"- **{r['status'].upper()}** {r['name']} {r['version'] or ''} — `{r['license']}`" for r in rows)+"\n"
def main(argv=None):
 p=argparse.ArgumentParser(description="Apply an explainable dependency license policy"); p.add_argument("dependencies"); p.add_argument("--policy",required=True); p.add_argument("--output")
 a=p.parse_args(argv); rows=check(a.dependencies,json.loads(Path(a.policy).read_text())); text=markdown(rows); Path(a.output).write_text(text) if a.output else print(text); return 1 if any(x["status"]=="deny" for x in rows) else 0
if __name__=="__main__": raise SystemExit(main())

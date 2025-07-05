# xml_to_json.py

import os
import json
import xml.etree.ElementTree as ET

def _parse_tags(tags_text):
    """
    Parse the OpenVAS <tags> content into a dict.
    e.g. "cvss_base_vector=...|summary=...|insight=...|solution=..."
    """
    data = {}
    for part in tags_text.split('|'):
        if '=' in part:
            key, val = part.split('=', 1)
            data[key.strip()] = val.strip()
    return data

def convert_openvas_xml_to_json(xml_path, json_path):
    """
    Convert an OpenVAS XML report into a JSON file, skipping any <result>
    entries without at least one CVE.  For each <result> we extract:

      - result_id       (the <result id="…"> attribute)
      - result_name     (the first <name> child under <result>)
      - host.ip, port
      - threat, severity
      - qod.value       (if present)
      - nvt: {
          name,
          description (from <tags> summary or <nvt><description>),
          solution.text,
          refs: {"ref":[{"type","id"},…]}
        }
      - cve             (the first CVE from refs)
      - additional_cves (any remaining CVEs from refs)
      - description     (the top‐level <description> under <result> if present,
                        otherwise the nvt_block description)

    Any existing json_path is overwritten.
    """
    # remove old output
    if os.path.exists(json_path):
        os.remove(json_path)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    output = {"report": {"results": {"result": []}}}

    for elem in root.findall(".//result"):
        # --- collect all CVEs from nvt/refs/ref[@type='cve'] ---
        cve_ids = []
        nvt = elem.find("nvt")
        if nvt is not None:
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.get("type","").lower() == "cve":
                        cid = ref.get("id","").strip()
                        if cid:
                            cve_ids.append(cid)

        # skip entries with no CVE
        if not cve_ids:
            continue

        # result metadata
        entry = {
            "result_id":   elem.get("id",""),
            "result_name": elem.findtext("name","").strip(),
            "host":        {"ip": elem.findtext("host","").strip()},
            "port":        elem.findtext("port","general").strip(),
            "threat":      elem.findtext("threat","Unknown").strip(),
            "severity":    elem.findtext("severity","0.0").strip(),
        }

        # optional qod
        qod_elem = elem.find("qod/value")
        if qod_elem is not None and qod_elem.text:
            entry["qod"] = {"value": qod_elem.text.strip()}

        # build nvt block
        nvt_block = {
            "name":        "",
            "description": "",
            "solution":    {"text": ""},
            "refs":        {"ref": []}
        }
        if nvt is not None:
            nvt_block["name"] = nvt.findtext("name","").strip()
            # parse <tags> summary and insight
            tags_text = nvt.findtext("tags","").strip()
            tags_data = _parse_tags(tags_text)
            if "summary" in tags_data:
                nvt_block["description"] = tags_data["summary"]
            else:
                # fallback to nvt/<description> if any
                nvt_block["description"] = nvt.findtext("description","").strip()
            # solution: from <solution> or tags_data
            sol_elem = nvt.find("solution")
            if sol_elem is not None and sol_elem.text:
                nvt_block["solution"]["text"] = sol_elem.text.strip()
            else:
                nvt_block["solution"]["text"] = tags_data.get("solution","").strip()
            # copy all refs
            for ref in nvt.findall(".//refs/ref"):
                r_type = ref.get("type","")
                r_id   = ref.get("id","")
                nvt_block["refs"]["ref"].append({"type": r_type, "id": r_id})

        entry["nvt"] = nvt_block

        # decide description: top-level or nvt summary
        top_desc = elem.findtext("description","").strip()
        entry["description"] = top_desc or nvt_block["description"]

        # assign primary CVE and additional_cves
        entry["cve"] = cve_ids[0]
        if len(cve_ids) > 1:
            entry["additional_cves"] = cve_ids[1:]

        # append to results
        output["report"]["results"]["result"].append(entry)

    # write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    return json_path

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Convert OpenVAS XML → JSON (skipping non-CVE entries)"
    )
    parser.add_argument("xml_file",  help="Path to the OpenVAS XML report")
    parser.add_argument("json_file", help="Where to write the output JSON")
    args = parser.parse_args()

    out = convert_openvas_xml_to_json(args.xml_file, args.json_file)
    print(f"✔ Generated JSON at: {out}")
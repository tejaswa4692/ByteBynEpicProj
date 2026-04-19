from fpdf import FPDF

def generate_pdf_bytes(repo_name, results):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font('helvetica', 'B', 20)
    pdf.cell(0, 10, f"HackHelix Vulnerability Report", new_x="LMARGIN", new_y="NEXT", align='C')
    
    pdf.set_font('helvetica', 'I', 12)
    pdf.cell(0, 10, f"Target: {repo_name} | Total Threats: {len(results)}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)
    
    for idx, r in enumerate(results, 1):
        vuln_id = r.get("vuln_id") or "Unknown"
        pkg = r.get("package_name", "")
        sev = r.get("severity", "LOW")
        risk_score = r.get("risk_score") or 0.0
        impact = r.get("risk_impact") or "Moderate Issue"
        fix = r.get("fix_suggestion") or "Upgrade to nearest patched version."
        summary = r.get("summary") or "No OSV summary provided."
        affected = f"{r.get('affected_file')}:{r.get('line_number')}" if r.get('affected_file') else "Standard node_modules nested import."

        # Header -> Package Name + Severity formatting
        pdf.set_font('helvetica', 'B', 14)
        if risk_score >= 7.0:
            pdf.set_text_color(220, 38, 38)  # Red
        elif risk_score >= 4.0:
            pdf.set_text_color(217, 119, 6)  # Orange
        else:
            pdf.set_text_color(0, 0, 0)
            
        pdf.cell(0, 8, f"{idx}. {pkg} ({vuln_id})", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('helvetica', '', 11)
        pdf.cell(0, 6, f"Severity: {sev} | Risk Factor: {risk_score} / 10", new_x="LMARGIN", new_y="NEXT")
        
        # Local Usage
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 6, f"Local Usage Found:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font('helvetica', '', 10)
        pdf.set_text_color(107, 114, 128)
        pdf.multi_cell(0, 6, str(affected), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        
        # Error / Summary
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(0, 6, f"Vulnerability Error (Context & Specifics):", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font('helvetica', '', 10)
        pdf.multi_cell(0, 6, f"[{impact}] {summary}", new_x="LMARGIN", new_y="NEXT")
        
        # Actionable Fix Generated
        pdf.set_font('helvetica', 'B', 10)
        pdf.set_text_color(5, 150, 105) # Green
        pdf.cell(0, 6, f"Recommended Actionable Fix:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font('helvetica', 'I', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 6, fix, new_x="LMARGIN", new_y="NEXT")
        
        pdf.ln(5)
        
    return pdf.output()

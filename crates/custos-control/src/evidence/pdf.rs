//! Renders an [`EvidenceReport`] as a PDF, in English, German, or Romanian.
//! Not a compliance certification — see the report's own disclaimer
//! section and `docs/decisions/0009-evidence-export.md`.

use super::{EvidenceError, EvidenceReport, Lang};
use genpdf::elements::{Break, FrameCellDecorator, Paragraph, StyledElement, TableLayout};
use genpdf::style::Style;
use genpdf::{Alignment, Document, Element as _, fonts};

const REGULAR: &[u8] = include_bytes!("../../assets/fonts/PTSans-Regular.ttf");
const BOLD: &[u8] = include_bytes!("../../assets/fonts/PTSans-Bold.ttf");
const ITALIC: &[u8] = include_bytes!("../../assets/fonts/PTSans-Italic.ttf");
const BOLD_ITALIC: &[u8] = include_bytes!("../../assets/fonts/PTSans-BoldItalic.ttf");

fn embedded_font_family() -> Result<fonts::FontFamily<fonts::FontData>, EvidenceError> {
    let load = |bytes: &[u8]| {
        fonts::FontData::new(bytes.to_vec(), None).map_err(|e| EvidenceError::Pdf(e.to_string()))
    };
    Ok(fonts::FontFamily {
        regular: load(REGULAR)?,
        bold: load(BOLD)?,
        italic: load(ITALIC)?,
        bold_italic: load(BOLD_ITALIC)?,
    })
}

/// Every fixed piece of report text, in one language. Content pulled from
/// the database (agent names, tool names, comments, ...) is never
/// translated — only these labels are.
struct Labels {
    title: &'static str,
    generated: &'static str,
    range: &'static str,
    agents_heading: &'static str,
    agents_name: &'static str,
    agents_status: &'static str,
    agents_expiry: &'static str,
    agents_none: &'static str,
    policies_heading: &'static str,
    policies_version: &'static str,
    policies_message: &'static str,
    policies_none: &'static str,
    decisions_heading: &'static str,
    decisions_allowed: &'static str,
    decisions_blocked: &'static str,
    decisions_held: &'static str,
    approvals_heading: &'static str,
    approvals_agent: &'static str,
    approvals_tool: &'static str,
    approvals_status: &'static str,
    approvals_approver: &'static str,
    approvals_comment: &'static str,
    approvals_none: &'static str,
    gateways_heading: &'static str,
    gateways_name: &'static str,
    gateways_chain: &'static str,
    gateways_none: &'static str,
    compliance_heading: &'static str,
    compliance_disclaimer: &'static str,
    compliance_points: [(&'static str, &'static str); 5],
}

fn labels(lang: Lang) -> Labels {
    match lang {
        Lang::En => Labels {
            title: "Custos Evidence Report",
            generated: "Generated",
            range: "Reporting period",
            agents_heading: "Agent inventory",
            agents_name: "Name",
            agents_status: "Status",
            agents_expiry: "Expiry",
            agents_none: "No agents on record.",
            policies_heading: "Policy versions (published)",
            policies_version: "Version",
            policies_message: "Message",
            policies_none: "No published policy versions.",
            decisions_heading: "Decision statistics",
            decisions_allowed: "Allowed",
            decisions_blocked: "Blocked",
            decisions_held: "Held for approval",
            approvals_heading: "Approvals resolved in this period",
            approvals_agent: "Agent",
            approvals_tool: "Tool",
            approvals_status: "Status",
            approvals_approver: "Approver",
            approvals_comment: "Comment",
            approvals_none: "No approvals were resolved in this period.",
            gateways_heading: "Gateway chain integrity",
            gateways_name: "Gateway",
            gateways_chain: "Chain status",
            gateways_none: "No gateways enrolled.",
            compliance_heading: "Regulatory context (informational only)",
            compliance_disclaimer: "This section maps the sections above to specific provisions of the EU AI Act, NIS2, and GDPR for convenience. It is an aid to your own compliance assessment, not a compliance certification, legal advice, or a guarantee of conformity. Consult qualified legal counsel for a compliance determination.",
            compliance_points: [
                (
                    "Decision statistics and audit trail",
                    "Support EU AI Act record-keeping for high-risk AI systems (Art. 12, automatic logging) and human oversight (Art. 14) by showing every tool call attempted, the applicable policy, and the outcome.",
                ),
                (
                    "Approval records",
                    "Support EU AI Act human oversight (Art. 14) and NIS2 access-control/incident-handling documentation (Art. 21(2)(a), (e)) by evidencing that human review took place where policy required it.",
                ),
                (
                    "Policy inventory and version history",
                    "Support NIS2 access-control policy documentation (Art. 21(2)(a)) by showing what rules governed agent behaviour during the period and when they changed.",
                ),
                (
                    "Gateway chain-integrity results",
                    "Support the tamper-evidence expectation behind NIS2 logging requirements and GDPR's integrity and confidentiality principle (Art. 5(1)(f)) by showing whether the underlying audit trail is intact.",
                ),
                (
                    "Findings, not raw arguments",
                    "Only what was found in tool call arguments (kind, count, location) appears above, never the raw values, unless the gateway's own audit mode is set to 'full' - supporting GDPR data minimisation (Art. 5(1)(c)).",
                ),
            ],
        },
        Lang::De => Labels {
            title: "Custos Nachweisbericht",
            generated: "Erstellt am",
            range: "Berichtszeitraum",
            agents_heading: "Agentenübersicht",
            agents_name: "Name",
            agents_status: "Status",
            agents_expiry: "Ablauf",
            agents_none: "Keine Agenten erfasst.",
            policies_heading: "Richtlinienversionen (veröffentlicht)",
            policies_version: "Version",
            policies_message: "Nachricht",
            policies_none: "Keine veröffentlichten Richtlinienversionen.",
            decisions_heading: "Entscheidungsstatistik",
            decisions_allowed: "Erlaubt",
            decisions_blocked: "Blockiert",
            decisions_held: "Zur Freigabe zurückgestellt",
            approvals_heading: "In diesem Zeitraum entschiedene Freigaben",
            approvals_agent: "Agent",
            approvals_tool: "Tool",
            approvals_status: "Status",
            approvals_approver: "Freigeber",
            approvals_comment: "Kommentar",
            approvals_none: "In diesem Zeitraum wurden keine Freigaben entschieden.",
            gateways_heading: "Integrität der Gateway-Kette",
            gateways_name: "Gateway",
            gateways_chain: "Kettenstatus",
            gateways_none: "Keine Gateways registriert.",
            compliance_heading: "Regulatorischer Kontext (nur informativ)",
            compliance_disclaimer: "Dieser Abschnitt ordnet die obigen Abschnitte zur Orientierung bestimmten Vorgaben der EU-KI-Verordnung, von NIS2 und der DSGVO zu. Er dient als Hilfestellung für Ihre eigene Compliance-Bewertung, ist aber keine Compliance-Zertifizierung, keine Rechtsberatung und keine Konformitätsgarantie. Für eine verbindliche Beurteilung ziehen Sie qualifizierten juristischen Rat hinzu.",
            compliance_points: [
                (
                    "Entscheidungsstatistik und Audit-Trail",
                    "Unterstützen die Aufzeichnungspflichten der EU-KI-Verordnung für Hochrisiko-KI-Systeme (Art. 12, automatische Protokollierung) und die menschliche Aufsicht (Art. 14), indem jeder Toolaufruf, die anwendbare Richtlinie und das Ergebnis dokumentiert werden.",
                ),
                (
                    "Freigabeaufzeichnungen",
                    "Unterstützen die menschliche Aufsicht nach der EU-KI-Verordnung (Art. 14) sowie die NIS2-Dokumentation zu Zugriffskontrolle/Vorfallbehandlung (Art. 21(2)(a), (e)), indem sie belegen, dass eine menschliche Prüfung stattgefunden hat, wo die Richtlinie dies verlangte.",
                ),
                (
                    "Richtlinienbestand und Versionshistorie",
                    "Unterstützen die NIS2-Dokumentation von Zugriffskontrollrichtlinien (Art. 21(2)(a)), indem sie zeigen, welche Regeln das Agentenverhalten im Zeitraum bestimmten und wann sie sich geändert haben.",
                ),
                (
                    "Ergebnisse der Ketten-Integrität pro Gateway",
                    "Unterstützen die Manipulationssicherheit, die sowohl den NIS2-Protokollierungsanforderungen als auch dem Grundsatz der Integrität und Vertraulichkeit der DSGVO (Art. 5(1)(f)) zugrunde liegt, indem sie zeigen, ob der zugrunde liegende Audit-Trail intakt ist.",
                ),
                (
                    "Befunde statt Rohdaten",
                    "Es erscheinen oben nur Befunde zu Toolargumenten (Art, Anzahl, Fundstelle), niemals die Rohwerte selbst, außer der Audit-Modus des Gateways ist auf 'full' gesetzt - dies unterstützt die Datenminimierung nach der DSGVO (Art. 5(1)(c)).",
                ),
            ],
        },
        Lang::Ro => Labels {
            title: "Raport de dovezi Custos",
            generated: "Generat la",
            range: "Perioada raportată",
            agents_heading: "Inventar agenți",
            agents_name: "Nume",
            agents_status: "Stare",
            agents_expiry: "Expirare",
            agents_none: "Niciun agent înregistrat.",
            policies_heading: "Versiuni de politici (publicate)",
            policies_version: "Versiune",
            policies_message: "Mesaj",
            policies_none: "Nicio versiune de politică publicată.",
            decisions_heading: "Statistici decizii",
            decisions_allowed: "Permise",
            decisions_blocked: "Blocate",
            decisions_held: "Reținute pentru aprobare",
            approvals_heading: "Aprobări soluționate în această perioadă",
            approvals_agent: "Agent",
            approvals_tool: "Instrument",
            approvals_status: "Stare",
            approvals_approver: "Aprobator",
            approvals_comment: "Comentariu",
            approvals_none: "Nicio aprobare nu a fost soluționată în această perioadă.",
            gateways_heading: "Integritatea lanțului gateway-urilor",
            gateways_name: "Gateway",
            gateways_chain: "Stare lanț",
            gateways_none: "Niciun gateway înregistrat.",
            compliance_heading: "Context de reglementare (doar informativ)",
            compliance_disclaimer: "Această secțiune corelează secțiunile de mai sus, pentru comoditate, cu prevederi specifice ale Regulamentului UE privind IA, NIS2 și RGPD. Este un ajutor pentru propria dumneavoastră evaluare de conformitate, nu o certificare de conformitate, consultanță juridică sau o garanție de conformitate. Consultați un consilier juridic calificat pentru o determinare a conformității.",
            compliance_points: [
                (
                    "Statistici decizii și jurnal de audit",
                    "Susțin obligațiile de păstrare a evidențelor din Regulamentul UE privind IA pentru sistemele de IA cu risc ridicat (Art. 12, jurnalizare automată) și supravegherea umană (Art. 14), arătând fiecare apel de instrument încercat, politica aplicabilă și rezultatul.",
                ),
                (
                    "Evidențele aprobărilor",
                    "Susțin supravegherea umană din Regulamentul UE privind IA (Art. 14) și documentația NIS2 privind controlul accesului/gestionarea incidentelor (Art. 21(2)(a), (e)), dovedind că a avut loc o revizuire umană acolo unde politica o cerea.",
                ),
                (
                    "Inventarul politicilor și istoricul versiunilor",
                    "Susțin documentația NIS2 privind politicile de control al accesului (Art. 21(2)(a)), arătând ce reguli au guvernat comportamentul agenților în perioada respectivă și când s-au schimbat.",
                ),
                (
                    "Rezultatele integrității lanțului per gateway",
                    "Susțin garanția de inviolabilitate care stă la baza atât a cerințelor de jurnalizare NIS2, cât și a principiului integrității și confidențialității din RGPD (Art. 5(1)(f)), arătând dacă jurnalul de audit de bază este intact.",
                ),
                (
                    "Constatări, nu argumente brute",
                    "Mai sus apar doar constatările privind argumentele apelurilor de instrumente (tip, număr, locație), niciodată valorile brute, cu excepția cazului în care modul de audit al gateway-ului este setat la 'full' - susținând minimizarea datelor conform RGPD (Art. 5(1)(c)).",
                ),
            ],
        },
    }
}

pub fn render_pdf(report: &EvidenceReport, lang: Lang) -> Result<Vec<u8>, EvidenceError> {
    let l = labels(lang);
    let font_family = embedded_font_family()?;

    let mut doc = Document::new(font_family);
    doc.set_title(l.title);
    doc.set_minimal_conformance();
    doc.set_line_spacing(1.25);
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    doc.push(
        Paragraph::new(l.title)
            .aligned(Alignment::Center)
            .styled(Style::new().bold().with_font_size(18)),
    );
    doc.push(Break::new(1));
    let from = report
        .from
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| EvidenceError::Pdf(e.to_string()))?;
    let to = report
        .to
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| EvidenceError::Pdf(e.to_string()))?;
    let generated = report
        .generated_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| EvidenceError::Pdf(e.to_string()))?;
    doc.push(Paragraph::new(format!("{}: {from} – {to}", l.range)));
    doc.push(Paragraph::new(format!("{}: {generated}", l.generated)));
    doc.push(Break::new(1.5));

    // --- agent inventory ---------------------------------------------
    doc.push(heading(l.agents_heading));
    if report.agents.is_empty() {
        doc.push(Paragraph::new(l.agents_none));
    } else {
        let mut table = TableLayout::new(vec![3, 2, 2]);
        table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        push_row(
            &mut table,
            &[l.agents_name, l.agents_status, l.agents_expiry],
            true,
        );
        for agent in &report.agents {
            let expiry = match agent.expiry_date {
                Some(dt) => dt
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "-".to_string()),
                None => "-".to_string(),
            };
            push_row(
                &mut table,
                &[&agent.name, agent.status.as_str(), &expiry],
                false,
            );
        }
        doc.push(table);
    }
    doc.push(Break::new(1.5));

    // --- policy versions -----------------------------------------------
    doc.push(heading(l.policies_heading));
    if report.published_policy_versions.is_empty() {
        doc.push(Paragraph::new(l.policies_none));
    } else {
        let mut table = TableLayout::new(vec![1, 3]);
        table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        push_row(&mut table, &[l.policies_version, l.policies_message], true);
        for version in &report.published_policy_versions {
            push_row(
                &mut table,
                &[
                    &format!("v{}", version.version),
                    version.message.as_deref().unwrap_or("-"),
                ],
                false,
            );
        }
        doc.push(table);
    }
    doc.push(Break::new(1.5));

    // --- decision statistics --------------------------------------------
    doc.push(heading(l.decisions_heading));
    let mut table = TableLayout::new(vec![1, 1]);
    table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
    push_row(
        &mut table,
        &[l.decisions_allowed, &report.decisions.allow.to_string()],
        false,
    );
    push_row(
        &mut table,
        &[l.decisions_blocked, &report.decisions.block.to_string()],
        false,
    );
    push_row(
        &mut table,
        &[l.decisions_held, &report.decisions.hold.to_string()],
        false,
    );
    doc.push(table);
    doc.push(Break::new(1.5));

    // --- approvals ------------------------------------------------------
    doc.push(heading(l.approvals_heading));
    if report.resolved_approvals.is_empty() {
        doc.push(Paragraph::new(l.approvals_none));
    } else {
        let mut table = TableLayout::new(vec![2, 2, 2, 3, 3]);
        table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        push_row(
            &mut table,
            &[
                l.approvals_agent,
                l.approvals_tool,
                l.approvals_status,
                l.approvals_approver,
                l.approvals_comment,
            ],
            true,
        );
        for approval in &report.resolved_approvals {
            push_row(
                &mut table,
                &[
                    &approval.agent,
                    &approval.tool,
                    &approval.status,
                    approval.approver_email.as_deref().unwrap_or("-"),
                    approval.comment.as_deref().unwrap_or("-"),
                ],
                false,
            );
        }
        doc.push(table);
    }
    doc.push(Break::new(1.5));

    // --- gateway chain integrity -----------------------------------------
    doc.push(heading(l.gateways_heading));
    if report.gateways.is_empty() {
        doc.push(Paragraph::new(l.gateways_none));
    } else {
        let mut table = TableLayout::new(vec![2, 2]);
        table.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        push_row(&mut table, &[l.gateways_name, l.gateways_chain], true);
        for gateway in &report.gateways {
            push_row(&mut table, &[&gateway.name, &gateway.chain_status], false);
        }
        doc.push(table);
    }
    doc.push(Break::new(1.5));

    // --- regulatory context ----------------------------------------------
    doc.push(heading(l.compliance_heading));
    doc.push(Paragraph::new(l.compliance_disclaimer).styled(Style::new().italic()));
    doc.push(Break::new(0.5));
    for (title, body) in l.compliance_points {
        doc.push(Paragraph::new(title).styled(Style::new().bold()));
        doc.push(Paragraph::new(body));
        doc.push(Break::new(0.5));
    }

    let mut bytes = Vec::new();
    doc.render(&mut bytes)
        .map_err(|e| EvidenceError::Pdf(e.to_string()))?;
    Ok(bytes)
}

fn heading(text: &str) -> StyledElement<Paragraph> {
    Paragraph::new(text).styled(Style::new().bold().with_font_size(14))
}

fn push_row(table: &mut TableLayout, cells: &[&str], bold: bool) {
    let mut row = table.row();
    for cell in cells {
        let style = if bold {
            Style::new().bold()
        } else {
            Style::new()
        };
        row = row.element(Paragraph::new(cell.to_string()).styled(style).padded(1));
    }
    // A malformed row (wrong cell count for the table's column widths)
    // would be a programming error, not bad input - every call site above
    // passes exactly as many cells as the table has columns.
    if row.push().is_err() {
        tracing::error!("evidence PDF table row had the wrong number of cells");
    }
}

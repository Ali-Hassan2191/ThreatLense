# %%writefile app.py
"""
app.py
------
ThreatLens - Lightweight Threat Intelligence Analyzer (Streamlit UI).

This file is only responsible for:
- Streamlit UI / user interaction
- Calling helpers and the SOURCES registry from sources.py
- Building the Gemini prompt and calling Gemini
- Displaying the verdict, AI insight, and technical source results

It never contains source-specific logic (that lives in sources.py) and it
never hard-codes calls to individual sources - it always loops over
SOURCES so new sources "just work" without touching this file.
"""

import json
import os

import streamlit as st
import google.generativeai as genai

from sources import SOURCES, normalize_target, validate_target

# ---------------------------------------------------------------------------
# Streamlit configuration
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

VERDICT_STYLE = {
    "SAFE": ("🟢", st.success),
    "SUSPICIOUS": ("🟠", st.warning),
    "MALICIOUS": ("🔴", st.error),
    "UNKNOWN": ("⚪", st.info),
}

KNOWLEDGE_LEVEL_GUIDANCE = {
    "Beginner": (
        "Use simple, plain language. Explain what the target is, whether it "
        "appears safe or suspicious, why, any important warning signs, and "
        "what the user should do next. Avoid advanced cybersecurity jargon "
        "unless you briefly explain it."
    ),
    "Intermediate": (
        "Provide more technical detail: detection counts, reputation, "
        "domain/registration information, important indicators, possible "
        "risks, and a recommended action. Common cybersecurity terminology "
        "is fine, but briefly explain unusual terms."
    ),
    "Expert": (
        "Provide a concise, technical analysis focused on detection ratios, "
        "reputation signals, IOC characteristics, registration information, "
        "discrepancies between sources, and confidence/limitations. Skip "
        "beginner-level explanations."
    ),
}


# ---------------------------------------------------------------------------
# Gemini helpers (kept in app.py per project design)
# ---------------------------------------------------------------------------

def _get_gemini_model():
    """
    Reads the Gemini key with the same priority as sources.py's _get_secret:
    sidebar Settings (session_state) -> secrets.toml -> environment variable.
    """
    api_key = st.session_state.get("GEMINI_API_KEY")
    if not api_key:
        try:
            api_key = st.secrets.get("GEMINI_API_KEY")
        except Exception:
            pass
    api_key = api_key or os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return None
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-3.8-flash")


def build_prompt(target, target_type, knowledge_level, results):
    """
    Build a knowledge-level-aware prompt from the full, source-agnostic
    results dictionary produced by the SOURCES registry. Any future source
    automatically shows up here because we pass the whole `results` object
    rather than naming individual sources.
    """
    guidance = KNOWLEDGE_LEVEL_GUIDANCE.get(knowledge_level, KNOWLEDGE_LEVEL_GUIDANCE["Beginner"])

    return f"""You are a friendly cybersecurity analyst explaining findings to a real person, not writing a technical report.

Target: {target}
Target Type: {target_type}
User Knowledge Level: {knowledge_level}

Threat Intelligence Results (JSON, one entry per source):
{json.dumps(results, indent=2, default=str)}

Writing style rules (apply these no matter the knowledge level):
- Write in plain, everyday sentences. Avoid long, dense, jargon-packed sentences.
- Never assume the reader already knows security terms. If you must use a
  technical term (e.g. "reputation score", "detection engines", "WHOIS"),
  explain it in a few simple words right where you use it.
- Prefer short sentences over one long sentence stuffed with many facts.
- Write like you are explaining it out loud to a friend, not writing a
  security audit document.
- {guidance}

Rules about facts:
- Base your analysis ONLY on the data provided above. Do not invent facts.
- If a piece of information is unavailable or a source failed/was unsupported,
  say "Insufficient data" for that point rather than guessing.
- Choose a verdict of exactly one of: SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN.
  Use UNKNOWN if the evidence is insufficient or conflicting. Do not default
  to SAFE just because nothing malicious was found - that only means no
  malicious indicator was detected by these particular sources.

Also decide a simple, direct answer to the question every user actually
wants answered: "Can I safely use/visit/access this target right now?"
Put that answer in "can_access" as exactly one of: "Yes", "No", "With caution".
Then give one short, plain-language sentence in "can_access_reason" explaining
why, in everyday words (e.g. "Yes, this domain has a long history and almost
all scanners consider it safe." or "No, several scanners flagged this as
malicious, so avoid entering personal information here.").

Respond with ONLY a strict JSON object (no markdown, no extra text) in
exactly this shape:
{{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
  "confidence": "Low" | "Medium" | "High",
  "summary": "short overall summary in plain language",
  "key_findings": ["finding 1 in plain language", "finding 2 in plain language"],
  "recommendation": "what the user should do next, in plain language",
  "can_access": "Yes" | "No" | "With caution",
  "can_access_reason": "one short plain-language sentence"
}}
"""


def call_gemini(model, prompt):
    """Call Gemini and parse its JSON response. Returns (result_dict, error)."""
    try:
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        # Strip accidental markdown code fences, just in case.
        if text.startswith("```"):
            text = text.strip("`")
            text = text.replace("json\n", "", 1) if text.startswith("json\n") else text

        parsed = json.loads(text)

        required_keys = {"verdict", "confidence", "summary", "key_findings", "recommendation"}
        if not required_keys.issubset(parsed.keys()):
            return None, "Gemini response was missing expected fields."
        if parsed["verdict"] not in VERDICT_STYLE:
            parsed["verdict"] = "UNKNOWN"
        # can_access / can_access_reason are a newer addition to the schema;
        # fall back gracefully instead of failing if an older-style response
        # ever comes back without them.
        parsed.setdefault("can_access", "With caution")
        parsed.setdefault("can_access_reason", "Not enough information was provided to give a direct answer.")

        return parsed, None
    except json.JSONDecodeError:
        return None, "Gemini returned a response that could not be parsed as JSON."
    except Exception as exc:
        return None, f"AI analysis is currently unavailable ({exc})."


# ---------------------------------------------------------------------------
# Sidebar - Settings (enter API keys from the frontend, no secrets.toml needed)
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Settings")
    st.caption("Paste your API keys here. They stay only in this browser session "
               "and are never written to disk.")

    vt_input = st.text_input(
        "VirusTotal API Key",
        value=st.session_state.get("VIRUSTOTAL_API_KEY", ""),
        type="password",
        placeholder="Paste your VirusTotal API key",
    )
    gemini_input = st.text_input(
        "Gemini API Key",
        value=st.session_state.get("GEMINI_API_KEY", ""),
        type="password",
        placeholder="Paste your Gemini API key",
    )

    if st.button("Save Keys", use_container_width=True):
        st.session_state["VIRUSTOTAL_API_KEY"] = vt_input.strip()
        st.session_state["GEMINI_API_KEY"] = gemini_input.strip()
        st.success("Keys saved for this session.")
        st.caption(f"VirusTotal key length: {len(vt_input.strip())} characters "
                   f"(should be 64 for a standard VT key)")

    st.divider()
    vt_ready = bool(st.session_state.get("VIRUSTOTAL_API_KEY"))
    gemini_ready = bool(st.session_state.get("GEMINI_API_KEY"))
    st.write("VirusTotal:", "✅ Set" if vt_ready else "❌ Not set")
    st.write("Gemini:", "✅ Set" if gemini_ready else "❌ Not set")

    st.divider()
    st.caption(
        "Don't have keys yet?\n\n"
        "- VirusTotal: virustotal.com → profile icon → API Key\n"
        "- Gemini: aistudio.google.com/apikey"
    )

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

st.title("🛡️ ThreatLens")
st.caption("Lightweight Threat Intelligence Analyzer")

st.subheader("Target Type")
target_type = st.radio(
    "Target Type",
    options=["IP Address", "Domain", "URL"],
    horizontal=True,
    label_visibility="collapsed",
)

placeholder_map = {
    "IP Address": "8.8.8.8",
    "Domain": "example.com",
    "URL": "https://example.com/login",
}

st.subheader("Target")
raw_target = st.text_input(
    "Enter IP, domain, or URL",
    placeholder=placeholder_map[target_type],
    label_visibility="collapsed",
)

st.subheader("How much security knowledge do you have?")
knowledge_level = st.selectbox(
    "Knowledge Level",
    options=["Beginner", "Intermediate", "Expert"],
    label_visibility="collapsed",
)

analyze_clicked = st.button("Analyze Target", type="primary", use_container_width=True)

st.divider()

# ---------------------------------------------------------------------------
# Analyze flow
# ---------------------------------------------------------------------------

if analyze_clicked:
    is_valid, validation_error = validate_target(raw_target.strip(), target_type)

    if not is_valid:
        st.error(validation_error)
    else:
        target = normalize_target(raw_target, target_type)

        # 1. Dynamically collect results from every registered source.
        #    No source is called by name here - new sources in sources.py
        #    show up automatically.
        results = {}
        with st.spinner("Collecting threat intelligence..."):
            for source_name, source_function in SOURCES.items():
                try:
                    results[source_name] = source_function(target, target_type)
                except Exception as exc:
                    # Absolute last line of defense - a misbehaving source
                    # should never take down the whole app.
                    results[source_name] = {
                        "source": source_name,
                        "status": "error",
                        "data": {},
                        "error": f"{source_name} could not be reached. "
                                 f"The analysis will continue with the available sources.",
                    }

        # 2. Ask Gemini to interpret the combined results.
        ai_result, ai_error = None, None
        with st.spinner("Generating AI security insight..."):
            model = _get_gemini_model()
            if model is None:
                ai_error = "Gemini API key is not configured. AI analysis is unavailable."
            else:
                prompt = build_prompt(target, target_type, knowledge_level, results)
                ai_result, ai_error = call_gemini(model, prompt)

        # 3. Verdict
        st.subheader("Verdict")
        if ai_result:
            icon, verdict_fn = VERDICT_STYLE.get(ai_result["verdict"], VERDICT_STYLE["UNKNOWN"])
            verdict_fn(f"{icon} **{ai_result['verdict']}** (Confidence: {ai_result['confidence']})")
        else:
            st.info("⚪ Verdict unavailable - AI analysis could not be completed.")
            if ai_error:
                st.caption(ai_error)

        st.caption(
            "Note: this verdict reflects the limitations of the sources queried. "
            "A lack of detections does not guarantee a target is safe."
        )

        # 4. AI Security Insight card
        st.subheader("AI Security Insight")
        if ai_result:
            with st.container(border=True):
                st.markdown(f"**Summary**\n\n{ai_result['summary']}")
                st.markdown(f"**Confidence:** {ai_result['confidence']}")
                st.markdown("**Key Findings**")
                for finding in ai_result.get("key_findings", []):
                    st.markdown(f"- {finding}")
                st.markdown(f"**Recommendation**\n\n{ai_result['recommendation']}")

                st.divider()
                access_icon = {"Yes": "✅", "No": "🚫", "With caution": "⚠️"}.get(
                    ai_result.get("can_access"), "⚠️"
                )
                st.markdown(f"### {access_icon} Can I use/access this?")
                st.markdown(f"**{ai_result.get('can_access', 'With caution')}** — "
                            f"{ai_result.get('can_access_reason', '')}")
        else:
            st.warning("AI analysis is currently unavailable. Source results are still shown below.")

        # 5. Technical source results - rendered dynamically so any future
        #    source in SOURCES automatically appears here with zero changes
        #    to this file.
        st.subheader("Source Results")
        for source_name, result in results.items():
            status = result.get("status")
            status_label = {
                "success": "✓ Completed",
                "error": "✗ Failed",
                "unsupported": "– Not applicable",
            }.get(status, status)

            with st.expander(f"{source_name} — {status_label}"):
                if status == "error":
                    st.write(result.get("error") or "This source could not be reached.")
                elif status == "unsupported":
                    st.write(result.get("error") or "This source does not apply to this target type.")
                else:
                    data = result.get("data") or {}
                    if not data:
                        st.write("No data returned.")
                    else:
                        for key, value in data.items():
                            label = key.replace("_", " ").title()
                            st.write(f"**{label}:** {value}")

# КОНТУР

Моніторинг повітряних загроз України.

## Setup Instructions

1. Fork this repo
2. Enable GitHub Pages (Settings → Pages → Deploy from branch `gh-pages`)
3. Add secrets in Settings → Secrets → Actions
4. Upload your threat icons to `/icons/` folder
5. Enable GitHub Actions
6. First run: trigger manually via Actions → "Parse Alerts" → Run workflow
7. App will be live at `https://yourusername.github.io/kontur/`

## GitHub Secrets Required
- `TG_API_ID`          ← from [my.telegram.org](https://my.telegram.org)
- `TG_API_HASH`        ← from [my.telegram.org](https://my.telegram.org)
- `TG_SESSION_STRING`  ← generate via script
- `GEMINI_API_KEY`     ← from [Google AI Studio](https://aistudio.google.com/)

"""PEN-AGENT operator portal — internal package.

server.py is the thin HTTP layer (routing, SSE, auth wiring, main). Everything
else lives here as cohesive modules:

  config      paths + constants
  auth        token / session-cookie helpers
  pages       template loading + page registry
  state       state.db readers (read-only)
  scope       objective & scope (file-based)
  objectives  objective tracker read + operator toggle
  team        teammate roster/health + per-teammate token usage (from transcripts)
  findings    confirmed findings (engagement/findings/*.json)
  activity    live activity feed (state_events)
  msf         Metasploit RPC read-side + file-based logs
  shelllogs   shell-server read-side (non-MSF sessions)
"""

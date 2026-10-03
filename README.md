# TaskHub — Web (Medium)

> "Every ticket, right where it belongs." — the TaskHub team

TaskHub is a tiny internal IT ticketing tool. Staff log in, file tickets,
and can see "what the team's working on." There's a flag hidden
somewhere only admins should be able to reach.

## Running it

```
docker build -t taskhub .
docker run -p 5000:5000 taskhub
```

Then visit http://localhost:5000

## Notes for players

- Staff login: `judy` / `judy123` (or `mike` / `mike2024`).
- If you find something that *looks* like a flag early on... read it
  carefully before you celebrate.
- Viewing page source is allowed and encouraged. 🙂

## Category / Difficulty

- Category: Web — Broken Access Control
- Difficulty: Medium
- Skills tested: IDOR, missing function-level access control, vertical
  privilege escalation, not trusting the first flag-shaped string you see

Good luck!
# taskhub-ctf

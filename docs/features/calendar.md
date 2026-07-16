# Calendar

Month, week, and day views over the same MOTE substrate as everything else — events are just
`kind = calendar` MOTEs (spec §8.4) synced via JMAP alongside mail, chat, and contacts. There is no
separate central calendar service to trust or to lose.

<p align="center">
  <img src="../img/calendar-dark.png#gh-dark-mode-only" width="860" alt="Calendar — month view, dark theme">
  <img src="../img/calendar-light.png#gh-light-mode-only" width="860" alt="Calendar — month view, light theme">
</p>

## What you get

- **Month, week, and day views**, plus an always-visible **agenda** rail (the "today / this week"
  pattern familiar from any modern calendar app).
- **Recurring events**, all-day events, and per-event reminders (at start, 10/30 min, 1 hour, or
  1 day before).
- **Meetings and invitees** — add attendees straight from [Contacts](contacts.md); an event with
  invitees is a **meeting**, and the client marks it as such.
- **Peer-to-peer invitations and RSVP.** Inviting someone sends a signed MOTE, not a server
  request — the same iTIP-style invite/accept/decline/tentative flow existing calendar tools use,
  carried over the mesh instead of a shared server. Free/busy is answered the same way: a message,
  not a query against a central calendar database.

<p align="center">
  <img src="../img/calendar-mobile.png" width="300" alt="Calendar — mobile, single-pane view">
</p>

## How it interoperates

- **Native** — JSCalendar (RFC 8984) objects synced via JMAP, end-to-end encrypted at rest and in
  transit like every other MOTE kind.
- **Compatibility** — a CalDAV (RFC 4791) server projects the same event store as iCalendar for
  Apple Calendar, Thunderbird, and other CalDAV clients, so switching to Envoir doesn't mean
  switching calendar apps on day one. See [`crates/dmtap-mail`](../../crates/dmtap-mail) for the
  protocol-server implementation and [features/mail.md](mail.md#client-protocols) for the
  client-protocol picture shared with mail.

## What's real vs. simulated today

Event **construction** (a real signed MOTE, exactly like a mail or chat message) and the full UI —
month/week/day rendering, recurrence, reminders, the invite/RSVP flow — are real code in the web
client. As with every other module, **delivery** of that MOTE across the mesh is the same
clearly-labeled in-browser simulation described in [`client/README.md`](../../client/README.md);
the seed events you see on first load are demo data (`seed.js`), not a real calendar. See
[roadmap.md](../roadmap.md) for the project-wide real-vs-simulated line.

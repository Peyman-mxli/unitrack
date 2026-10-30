/* Shared live entry/exit event timeline for student, teacher and staff.
 * Polling is read-only. Only authorized operator QR submissions write visits.
 * Do not rotate or regenerate the QR displayed by the current page.
 */
(() => {
  "use strict";
  const start = () => {
    const history = document.querySelector("[data-live-campus-history]");
    if (!history || !window.fetch) return;

    const spanish = document.documentElement.lang.toLowerCase().startsWith("es");
    const insideLabel = spanish ? "Dentro del campus" : "Inside campus";
    const outsideLabel = spanish ? "Fuera del campus" : "Outside campus";
    const entryLabel = spanish ? "Entrada" : "Check-in";
    const exitLabel = spanish ? "Salida" : "Check-out";
    const filteredByDate = new URLSearchParams(window.location.search).has("date")
      && Boolean(new URLSearchParams(window.location.search).get("date"));
    const tbody = history.querySelector("[data-access-event-rows]");
    const tableWrap = history.querySelector("[data-access-table-wrap]");
    const empty = history.querySelector("[data-access-empty]");
    const summaryValues = [...document.querySelectorAll(".summary-card .summary-mini-value")];
    let lastSnapshot = "";
    let pending = false;

    const setStatus = (inside) => {
      for (const badge of [
        document.querySelector(".summary-status-wrap .status-badge"),
        document.querySelector("[data-live-campus-status] .status-badge")
      ]) {
        if (!badge) continue;
        badge.classList.toggle("status-green", inside);
        badge.classList.toggle("status-red", !inside);
        badge.textContent = inside ? insideLabel : outsideLabel;
      }
    };

    const appendCell = (row, value) => {
      const cell = document.createElement("td");
      cell.textContent = value == null || value === "" ? "--" : String(value);
      row.appendChild(cell);
      return cell;
    };
    const appendTag = (row, value, isIn) => {
      const cell = document.createElement("td");
      const tag = document.createElement("span");
      tag.className = `access-events-tag ${isIn ? "in" : "out"}`;
      tag.textContent = value;
      cell.appendChild(tag);
      row.appendChild(cell);
    };

    const update = (payload) => {
      const status = payload.status || {};
      const pairs = Array.isArray(payload.records) ? payload.records : [];
      const latest = pairs[0] || {};
      setStatus(status.status === "checked_in");

      [latest.date, latest.check_in, latest.check_out, latest.hours].forEach((value, index) => {
        if (summaryValues[index]) summaryValues[index].textContent = value || "--";
      });
      for (const [key, value] of Object.entries({
        "last-in": status.last_check_in,
        "last-out": status.last_check_out,
        "hours": status.hours_today
      })) {
        const node = document.querySelector(`[data-live-${key}]`);
        if (node) node.textContent = value || "--";
      }

      // A filtered date belongs to a fixed historical query. Keep it visible,
      // even while live status and the personal summary continue updating.
      if (filteredByDate) return;

      const events = Array.isArray(payload.events) ? payload.events : [];
      const counts = payload.event_counts || {};
      const countIn = history.querySelector("[data-access-count-in]");
      const countOut = history.querySelector("[data-access-count-out]");
      const countTotal = history.querySelector("[data-access-count-total]");
      const countPill = history.querySelector("[data-access-total-label]");
      const inCount = Number(counts.check_ins) || 0;
      const outCount = Number(counts.check_outs) || 0;
      const total = Number(counts.total) || (inCount + outCount);

      if (countIn) countIn.textContent = String(inCount);
      if (countOut) countOut.textContent = String(outCount);
      if (countTotal) countTotal.textContent = String(total);
      if (countPill) countPill.textContent = spanish
        ? `${total} movimiento${total === 1 ? "" : "s"}`
        : `${total} event${total === 1 ? "" : "s"}`;

      if (tableWrap) tableWrap.hidden = events.length === 0;
      if (empty) empty.hidden = events.length > 0;
      if (!tbody) return;

      const snapshot = JSON.stringify(events.map(event => [
        event.access_log_id, event.action, event.date, event.time, event.duration
      ]));
      if (lastSnapshot === snapshot) return;
      lastSnapshot = snapshot;
      const fragment = document.createDocumentFragment();
      events.forEach((event, index) => {
        const row = document.createElement("tr");
        appendCell(row, index + 1);
        appendCell(row, event.name || payload.name || payload.username);
        appendCell(row, event.user_id_code || payload.user_id_code || payload.username);
        appendCell(row, event.date);
        appendCell(row, event.time);
        appendTag(row, event.action === "check_in" ? entryLabel : exitLabel, event.action === "check_in");
        appendCell(row, event.duration);
        appendTag(row, event.status === "checked_in" ? insideLabel : outsideLabel, event.status === "checked_in");
        fragment.appendChild(row);
      });
      tbody.replaceChildren(fragment);
    };

    const poll = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const response = await fetch("/api/access-control/live", {
          credentials: "same-origin", cache: "no-store"
        });
        if (response.ok) update(await response.json());
      } catch (_) {
        // Keep the last successful snapshot during a temporary network error.
      } finally {
        pending = false;
      }
    };
    poll();
    window.setInterval(poll, 12000);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) poll();
    });
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();

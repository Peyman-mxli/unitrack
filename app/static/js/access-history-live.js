/* Live personal campus status/history; never refreshes or replaces the QR.
 * Read-only polling: entry and exit are written only by authorized QR scans.
 */
(() => {
  "use strict";
  const start = () => {
    const history = document.querySelector("[data-live-campus-history]");
    if (!history || !window.fetch) return;
    const spanish = document.documentElement.lang.toLowerCase().startsWith("es");
    const insideLabel = spanish ? "Dentro del campus" : "Inside campus";
    const outsideLabel = spanish ? "Fuera del campus" : "Outside campus";
    let lastSnapshot = "";
    let pending = false;
    let templateRow = history.querySelector("tbody tr")?.cloneNode(true) || null;
    const summaryValues = [...document.querySelectorAll(".summary-card .summary-mini-value")];
    const setStatus = (inside) => {
      const badges = [
        document.querySelector(".summary-status-wrap .status-badge"),
        document.querySelector("[data-live-campus-status] .status-badge")
      ];
      for (const badge of badges) {
        if (!badge) continue;
        badge.classList.toggle("status-green", inside);
        badge.classList.toggle("status-red", !inside);
        badge.textContent = inside ? insideLabel : outsideLabel;
      }
    };

    const update = (payload) => {
      const rows = Array.isArray(payload.records) ? payload.records : [];
      const status = payload.status || {};
      const latest = rows[0] || {};
      setStatus(status.status === "checked_in");
      const values = [latest.date, latest.check_in, latest.check_out, latest.hours];
      summaryValues.slice(0, 4).forEach((node, index) => {
        node.textContent = values[index] || "--";
      });
      const secondary = {
        "last-in": status.last_check_in,
        "last-out": status.last_check_out,
        "hours": status.hours_today,
      };
      Object.entries(secondary).forEach(([key, value]) => {
        const node = document.querySelector(`[data-live-${key}]`);
        if (node) node.textContent = value || "--";
      });

      const count = history.querySelector(".history-count");
      if (count) count.textContent = spanish
        ? `${rows.length} registro${rows.length === 1 ? "" : "s"}`
        : `${rows.length} record${rows.length === 1 ? "" : "s"}`;

      // Leave the user's active date-filtered historical view alone.
      if (new URLSearchParams(window.location.search).has("date")) return;

      let tbody = history.querySelector("tbody");
      if (!tbody && rows.length) {
        const oldEmpty = history.querySelector(".history-empty");
        if (oldEmpty) oldEmpty.remove();
        const wrapper = document.createElement("div");
        wrapper.className = "history-table-wrap";
        const table = document.createElement("table");
        table.className = "history-table";
        const head = document.createElement("thead");
        const headRow = document.createElement("tr");
        const labels = spanish
          ? ["#", "Usuario", "ID / Usuario", "Fecha", "Entrada", "Salida", "Horas", "Estado"]
          : ["#", "User", "ID / Username", "Date", "Check-In", "Check-Out", "Hours", "Status"];
        for (const label of labels) {
          const th = document.createElement("th");
          th.textContent = label;
          headRow.appendChild(th);
        }
        head.appendChild(headRow);
        table.appendChild(head);
        tbody = document.createElement("tbody");
        table.appendChild(tbody);
        wrapper.appendChild(table);
        history.appendChild(wrapper);
      }
      if (!tbody) return;

      const snapshot = JSON.stringify(rows.map(row => [
        row.date, row.check_in, row.check_out, row.hours, row.status
      ]));
      if (snapshot === lastSnapshot) return;
      lastSnapshot = snapshot;
      const output = document.createDocumentFragment();
      rows.forEach((record, index) => {
        const row = templateRow ? templateRow.cloneNode(true) : document.createElement("tr");
        if (!row.cells.length) {
          for (let n = 0; n < 8; n++) row.appendChild(document.createElement("td"));
        }
        if (!templateRow) {
          row.cells[1].textContent = payload.name || payload.username || "—";
          row.cells[2].textContent = `${payload.user_id_code || "—"} / ${payload.username || "—"}`;
        }
        const fields = [
          [0, String(index + 1)],
          [3, record.date || "--"],
          [4, record.check_in || "--"],
          [5, record.check_out || "--"],
          [6, record.hours || "--"],
        ];
        for (const [col, value] of fields) row.cells[col].textContent = value;
        const statusCell = row.cells[7];
        statusCell.replaceChildren();
        const badge = document.createElement("span");
        const checkedIn = record.status === "checked_in";
        badge.className = `history-status ${checkedIn ? "history-status-inside" : "history-status-outside"}`;
        badge.textContent = checkedIn ? insideLabel : outsideLabel;
        statusCell.appendChild(badge);
        output.appendChild(row);
      });
      tbody.replaceChildren(output);
    };

    const poll = async () => {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const response = await fetch("/api/access-control/live", {
          credentials: "same-origin", cache: "no-store"
        });
        if (!response.ok) return;
        update(await response.json());
      } catch (_) {
        // Keep existing history on screen during a temporary network error.
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
